#!/usr/bin/env python3
"""
Universeller LDAP-Sync mit Web-Oberflaeche.

Installation:  pip install flask ldap3
Start (Web):   python ldap_sync_ui.py                -> http://127.0.0.1:5000
Headless/Cron: python ldap_sync_ui.py --run <job-id> [--dry-run]

Umgebungsvariablen:
  UI_HOST (127.0.0.1)  UI_PORT (5000)  UI_USER / UI_PASS (Basic-Auth, empfohlen)
  SYNC_DATA (jobs.json) = Datei mit den Job-Definitionen (enthaelt Passwoerter!)

Mapping-Syntax (eine Zeile pro Zielattribut):
  ziel=quelle                 Attribut kopieren
  ziel=quelle1|quelle2        erstes vorhandenes Attribut verwenden
  ziel=mail:local             lokaler Teil einer Mailadresse (vor dem @)
  ziel='festerwert'           Konstante
"""
import argparse
import hmac
import json
import os
import ssl
import sys
import threading
import time
import uuid

from flask import Flask, Response, jsonify, request
from ldap3 import LEVEL, MODIFY_REPLACE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

DATA = os.getenv("SYNC_DATA", "jobs.json")
MASK = "********"
app = Flask(__name__)
runs, busy, io_lock = {}, set(), threading.Lock()


# ---------------------------------------------------------------- Jobs
def load():
    try:
        with open(DATA, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(jobs):
    with io_lock:
        with open(DATA, "w", encoding="utf-8") as f:
            json.dump(jobs, f, indent=1, ensure_ascii=False)
        os.chmod(DATA, 0o600)


# ---------------------------------------------------------------- LDAP
def connect(c, p):
    use_ssl = bool(c.get(p + "ssl"))
    tls = Tls(validate=ssl.CERT_REQUIRED if c.get("verify_tls") else ssl.CERT_NONE) if use_ssl else None
    port = int(c.get(p + "port") or (636 if use_ssl else 389))
    srv = Server(c[p + "host"], port=port, use_ssl=use_ssl, tls=tls, get_info=NONE)
    return Connection(srv, user=c.get(p + "user") or None, password=c.get(p + "pw") or None,
                      auto_bind=True, raise_exceptions=True)


def vals(v):
    if v is None:
        return []
    v = v if isinstance(v, (list, tuple)) else [v]
    return [x.decode("utf-8", "ignore") if isinstance(x, bytes) else str(x)
            for x in v if str(x).strip()]


def parse_map(text):
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            d, s = line.split("=", 1)
            out.append((d.strip(), [x.strip() for x in s.split("|")]))
    return out


def map_entry(attrs, mapping):
    low = {k.lower(): v for k, v in attrs.items()}
    out = {}
    for dst, srcs in mapping:
        for s in srcs:
            if len(s) > 1 and s[0] == s[-1] == "'":
                v = [s[1:-1]]
            else:
                loc = s.endswith(":local")
                v = vals(low.get((s[:-6] if loc else s).lower()))
                if loc:
                    v = [x.split("@")[0] for x in v if "@" in x]
            if v:
                out[dst] = v
                break
    return out


def entries(conn):
    return [e for e in (conn.response or []) if e.get("type") == "searchResEntry"]


def read_src(conn, base, flt, attrs, scope):
    try:
        gen = conn.extend.standard.paged_search(base, flt, scope, attributes=attrs,
                                                paged_size=500, generator=True)
        for e in gen:
            if e.get("type") == "searchResEntry":
                yield e["dn"], e["attributes"]
    except LDAPException:  # Server ohne Paged Results -> einfache Suche
        conn.search(base, flt, scope, attributes=attrs)
        for e in entries(conn):
            yield e["dn"], e["attributes"]


# ---------------------------------------------------------------- Sync
def run_job(job, dry, rid):
    r = runs[rid]
    log = lambda m: r["log"].append(time.strftime("%H:%M:%S ") + m)
    st = dict(added=0, modified=0, unchanged=0, skipped=0, deleted=0, errors=0)
    r["stats"] = st
    try:
        src, dst = connect(job, "src_"), connect(job, "dst_")
        mapping = parse_map(job.get("mapping"))
        key = job["key_attr"].strip()
        ocs = [x.strip() for x in job.get("object_classes", "").split(",") if x.strip()]
        mk, mv = job.get("marker_attr", "").strip(), job.get("marker_value", "").strip()
        managed = sorted({d for d, _ in mapping} | ({mk} if mk else set()), key=str.lower)
        needed = sorted({s[:-6] if s.endswith(":local") else s
                         for _, ss in mapping for s in ss if s[:1] != "'"}) or ["*"]
        scope = LEVEL if job.get("src_scope", "sub").strip() == "one" else SUBTREE
        base = job["dst_base"].strip()
        log(f"Start{' (Dry-Run)' if dry else ''}: {job['src_base']} [{job['src_filter']}] -> {base}")
        seen = set()

        for sdn, sattrs in read_src(src, job["src_base"], job["src_filter"], needed, scope):
            new = map_entry(sattrs, mapping)
            if mk:
                new[mk] = [mv]
            kv = (new.get(key) or [None])[0]
            if not kv:
                log(f"SKIP   {sdn} (Schluesselattribut '{key}' leer)")
                st["skipped"] += 1
                continue
            try:
                dn = f"{key}={escape_rdn(kv)},{base}"
                dst.search(base, f"({key}={escape_filter_chars(kv)})", SUBTREE, attributes=managed)
                hits = entries(dst)
                if not hits:
                    log(f"ADD    {dn}")
                    if not dry:
                        dst.add(dn, ocs, new)
                    st["added"] += 1
                    seen.add(dn.lower())
                    continue
                dn = hits[0]["dn"]
                seen.add(dn.lower())
                cur = {k.lower(): vals(v) for k, v in hits[0]["attributes"].items()}
                ch = {}
                for n, v in new.items():
                    if n.lower() != key.lower() and sorted(cur.get(n.lower(), [])) != sorted(v):
                        ch[n] = [(MODIFY_REPLACE, v)]
                if job.get("remove_missing"):
                    for n in managed:
                        if n not in new and cur.get(n.lower()):
                            ch[n] = [(MODIFY_REPLACE, [])]
                if not ch:
                    st["unchanged"] += 1
                    continue
                log(f"MODIFY {dn} ({', '.join(sorted(ch))})")
                if not dry:
                    dst.modify(dn, ch)
                st["modified"] += 1
            except LDAPException as exc:
                log(f"FEHLER {sdn}: {exc}")
                st["errors"] += 1

        if job.get("delete_orphans") and mk:
            if st["errors"] or not (st["added"] + st["modified"] + st["unchanged"]):
                log("Loeschen verwaister Eintraege uebersprungen (Fehler oder leere Quelle)")
            else:
                dst.search(base, f"({mk}={escape_filter_chars(mv)})", SUBTREE, attributes=["1.1"])
                for e in entries(dst):
                    if e["dn"].lower() not in seen:
                        log(f"DELETE {e['dn']}")
                        if not dry:
                            dst.delete(e["dn"])
                        st["deleted"] += 1
        src.unbind()
        dst.unbind()
        log(f"Fertig: {st}")
        r["status"] = "error" if st["errors"] else "done"
    except Exception as exc:  # Verbindungs-/Konfigurationsfehler
        log(f"ABBRUCH: {exc}")
        r["status"] = "error"


def start(jid, job, dry):
    if jid in busy:
        return None
    rid = uuid.uuid4().hex[:8]
    runs[rid] = {"job": job.get("name", jid), "log": [], "status": "running", "stats": {}}
    while len(runs) > 50:
        runs.pop(next(iter(runs)))
    busy.add(jid)

    def worker():
        try:
            run_job(job, dry, rid)
        finally:
            busy.discard(jid)
    threading.Thread(target=worker, daemon=True).start()
    return rid


def scheduler():
    last = {}
    while True:
        time.sleep(30)
        for jid, j in load().items():
            m = int(j.get("interval") or 0)
            t = last.setdefault(jid, time.time())
            if m > 0 and time.time() - t >= m * 60 and jid not in busy:
                last[jid] = time.time()
                start(jid, j, False)


def test(job):
    out = []
    for p, label in (("src_", "Quelle"), ("dst_", "Ziel")):
        try:
            c = connect(job, p)
            flt = job["src_filter"] if p == "src_" else "(objectClass=*)"
            base = job[p + "base"]
            c.search(base, flt, SUBTREE if p == "src_" else LEVEL, attributes=["1.1"])
            out.append(f"{label} OK: {len(entries(c))} Treffer unter {base}")
            c.unbind()
        except Exception as exc:
            out.append(f"{label} FEHLER: {exc}")
    return out


# ---------------------------------------------------------------- Web/API
@app.before_request
def auth():
    u, p = os.getenv("UI_USER"), os.getenv("UI_PASS")
    if u and p:
        a = request.authorization
        if not (a and hmac.compare_digest(a.username, u) and hmac.compare_digest(a.password or "", p)):
            return Response("Login erforderlich", 401, {"WWW-Authenticate": 'Basic realm="ldap-sync"'})


@app.get("/api/jobs")
def jobs_get():
    jobs = load()
    for j in jobs.values():
        for k in ("src_pw", "dst_pw"):
            if j.get(k):
                j[k] = MASK
    return jsonify(jobs)


@app.post("/api/jobs")
def jobs_save():
    j, jobs = request.get_json(), load()
    jid = j.pop("id", None) or uuid.uuid4().hex[:8]
    old = jobs.get(jid, {})
    for k in ("src_pw", "dst_pw"):
        if j.get(k) == MASK:
            j[k] = old.get(k, "")
    jobs[jid] = j
    save(jobs)
    return jsonify(id=jid)


@app.delete("/api/jobs/<jid>")
def jobs_del(jid):
    jobs = load()
    jobs.pop(jid, None)
    save(jobs)
    return jsonify(ok=True)


@app.post("/api/jobs/<jid>/run")
def jobs_run(jid):
    job = load().get(jid)
    if not job:
        return jsonify(error="unbekannt"), 404
    rid = start(jid, job, request.args.get("dry") == "1")
    return jsonify(run=rid) if rid else (jsonify(error="Job laeuft bereits"), 409)


@app.post("/api/jobs/<jid>/test")
def jobs_test(jid):
    job = load().get(jid)
    return jsonify(log=test(job)) if job else (jsonify(error="unbekannt"), 404)


@app.get("/api/runs/<rid>")
def runs_get(rid):
    return jsonify(runs.get(rid, {"log": ["unbekannter Lauf"], "status": "error"}))


@app.get("/")
def index():
    return Response(HTML, mimetype="text/html")


HTML = r"""<!doctype html><html lang="de"><meta charset="utf-8"><title>LDAP Sync</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:light dark;--b:#8884;--a:#2f6fed}
body{font:14px system-ui,sans-serif;margin:0;display:flex;height:100vh}
aside{width:220px;border-right:1px solid var(--b);padding:12px;overflow:auto}
main{flex:1;padding:16px;overflow:auto;max-width:1200px}
ul{list-style:none;padding:0;margin:8px 0}li{padding:6px 8px;border-radius:6px;cursor:pointer}
li.on{background:var(--a);color:#fff}li:hover:not(.on){background:var(--b)}
label{display:block;margin:6px 0;font-size:12px}label.c{display:flex;gap:6px;align-items:center;font-size:13px}
input[type=text],input[type=password],textarea{width:100%;box-sizing:border-box;padding:6px;font:inherit;
 border:1px solid var(--b);border-radius:6px;background:transparent;color:inherit}
textarea{font-family:ui-monospace,monospace}
h3{margin:18px 0 4px;border-bottom:1px solid var(--b);padding-bottom:4px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:28px}.sec{min-width:0}
@media(max-width:900px){.cols{grid-template-columns:1fr}}
button{padding:7px 12px;border:1px solid var(--b);border-radius:6px;background:transparent;color:inherit;cursor:pointer;font:inherit}
button.p{background:var(--a);color:#fff;border-color:var(--a)}
#bar{position:sticky;bottom:0;padding:10px 0;display:flex;gap:6px;flex-wrap:wrap;background:Canvas}
pre{background:#8881;padding:10px;border-radius:6px;white-space:pre-wrap;max-height:300px;overflow:auto}
</style>
<aside><b>LDAP Sync</b><ul id="list"></ul><button onclick="newJob()">+ Neuer Job</button></aside>
<main><div id="f"></div>
<div id="bar"><button class="p" onclick="doSave()">Speichern</button><button onclick="doTest()">Verbindung testen</button>
<button onclick="doRun(1)">Dry-Run</button><button onclick="doRun(0)">Sync starten</button>
<button onclick="doDel()" style="margin-left:auto">Loeschen</button></div>
<h3>Protokoll</h3><pre id="log">-</pre></main>
<script>
const F=[["h","Allgemein"],["name","Name"],["interval","Automatisch alle N Minuten (0 = nur manuell)"],["verify_tls","TLS-Zertifikat pruefen","b"],
["h","Quelle"],["src_host","Host"],["src_port","Port (leer = 389/636)"],["src_ssl","LDAPS","b"],["src_user","Bind-DN"],["src_pw","Passwort","p"],
["src_base","Search-Base"],["src_filter","Suchfilter (einzige Selektion)"],["src_scope","Scope: sub oder one"],
["h","Ziel"],["dst_host","Host"],["dst_port","Port (leer = 389/636)"],["dst_ssl","LDAPS","b"],["dst_user","Bind-DN"],["dst_pw","Passwort","p"],
["dst_base","Ziel-Base (Eintraege landen direkt darunter)"],
["h","Abbildung"],["key_attr","Schluesselattribut (wird RDN, z.B. uid)"],["object_classes","objectClasses (Komma-getrennt)"],
["mapping","Attribut-Mapping: ziel=quelle1|quelle2 , ziel=mail:local , ziel='wert'","t"],
["h","Abgleich"],["remove_missing","Attribute entfernen, die in der Quelle fehlen","b"],
["marker_attr","Marker-Attribut (zur Erkennung synchronisierter Eintraege)"],["marker_value","Marker-Wert"],
["delete_orphans","Verwaiste Eintraege im Ziel loeschen (nur mit Marker)","b"]];
const DEF={interval:"0",verify_tls:true,src_scope:"sub",src_filter:"(objectClass=person)",key_attr:"uid",
object_classes:"top,person,organizationalPerson,inetOrgPerson",marker_attr:"employeeType",marker_value:"ldap-sync",
remove_missing:true,mapping:"uid=uid|mail:local\ncn=cn\nsn=sn\ngivenName=givenName\ndisplayName=displayName|cn\nmail=mail\ntelephoneNumber=telephoneNumber"};
let jobs={},cur=null,timer=null;const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
async function api(u,m="GET",b){const r=await fetch(u,{method:m,headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined});return r.json()}
async function load(){jobs=await api("/api/jobs");list()}
function list(){$("#list").innerHTML=Object.entries(jobs).map(([id,j])=>`<li class="${id==cur?"on":""}" onclick="sel('${id}')">${esc(j.name||id)}</li>`).join("")}
function sel(id){cur=id;form(jobs[id]);list()}
function newJob(){cur=null;form(DEF);list()}
function fld([k,l,t],j){return t=="b"?`<label class=c><input type=checkbox data-k="${k}" ${j[k]?"checked":""}> ${l}</label>`:
t=="t"?`<label>${l}<textarea data-k="${k}" rows=8>${esc(j[k])}</textarea></label>`:
`<label>${l}<input data-k="${k}" type="${t=="p"?"password":"text"}" value="${esc(j[k])}"></label>`}
function form(j){const secs=[];F.forEach(f=>f[0]=="h"?secs.push({h:f[1],f:[]}):secs[secs.length-1].f.push(f));
const box=x=>`<div class=sec><h3>${x.h}</h3>${x.f.map(f=>fld(f,j)).join("")}</div>`;let o="";
for(let i=0;i<secs.length;i++){const x=secs[i],n=secs[i+1];
if(x.h=="Quelle"&&n&&n.h=="Ziel"){o+=`<div class=cols>${box(x)}${box(n)}</div>`;i++}else o+=box(x)}
$("#f").innerHTML=o}
function read(){const j={};document.querySelectorAll("[data-k]").forEach(e=>j[e.dataset.k]=e.type=="checkbox"?e.checked:e.value);if(cur)j.id=cur;return j}
async function doSave(){const r=await api("/api/jobs","POST",read());cur=r.id;await load();sel(cur);return cur}
async function doDel(){if(cur&&confirm("Job loeschen?")){await api("/api/jobs/"+cur,"DELETE");cur=null;await load();$("#f").innerHTML=""}}
async function doTest(){await doSave();$("#log").textContent="Teste...";const r=await api(`/api/jobs/${cur}/test`,"POST");$("#log").textContent=r.log.join("\n")}
async function doRun(dry){await doSave();const r=await api(`/api/jobs/${cur}/run?dry=${dry}`,"POST");
if(!r.run){$("#log").textContent=r.error;return}clearInterval(timer);
const tick=async()=>{const s=await api("/api/runs/"+r.run);$("#log").textContent=s.log.join("\n")||"...";if(s.status!="running")clearInterval(timer)};
tick();timer=setInterval(tick,1000)}
load().then(()=>{const k=Object.keys(jobs);k.length?sel(k[0]):newJob()});
</script></html>"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", metavar="JOB_ID", help="Job headless ausfuehren (z.B. per Cron)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.run:
        job = load().get(a.run)
        if not job:
            sys.exit(f"Job '{a.run}' nicht gefunden in {DATA}")
        rid = start(a.run, job, a.dry_run)
        while runs[rid]["status"] == "running":
            time.sleep(0.5)
        print("\n".join(runs[rid]["log"]))
        sys.exit(0 if runs[rid]["status"] == "done" else 1)
    threading.Thread(target=scheduler, daemon=True).start()
    app.run(host=os.getenv("UI_HOST", "127.0.0.1"), port=int(os.getenv("UI_PORT", "5000")))
