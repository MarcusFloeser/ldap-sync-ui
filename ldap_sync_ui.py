#!/usr/bin/env python3
"""
LDAP Sync UI - universeller LDAP-Sync mit Web-Oberflaeche, Login und Zeitplan.

Installation:  pip install -r requirements.txt
Start (Web):   python ldap_sync_ui.py                 -> http://127.0.0.1:5000
Headless:      python ldap_sync_ui.py --run <job-id> [--dry-run]
Benutzer:      python ldap_sync_ui.py --add-user <name>   (legt an / setzt Passwort)

Umgebungsvariablen:
  UI_HOST (127.0.0.1)   UI_PORT (5000)
  SYNC_DATA   (jobs.json)  Pfad der Job-Datei; users.json und .secret_key
                           liegen im selben Ordner
  UI_USER / UI_PASS        optional: legt beim ersten Start den ersten Benutzer an
                           (sonst Einrichtung ueber /setup im Browser)
  SECRET_KEY               optional: Schluessel fuer Session-Cookies
                           (sonst wird .secret_key im Datenordner erzeugt)
  COOKIE_SECURE=1          Session-Cookie nur ueber HTTPS senden (hinter HTTPS-Proxy)
  BEHIND_PROXY=1           X-Forwarded-* eines vorgeschalteten Reverse-Proxys beachten
  SESSION_HOURS (8)        Gueltigkeit der Anmeldung
  TZ                       Zeitzone fuer Cron-Zeitplaene (z.B. Europe/Zurich)

Mapping-Syntax (eine Zeile pro Zielattribut):
  ziel=quelle                 Attribut kopieren
  ziel=quelle1|quelle2        erstes vorhandenes Attribut verwenden
  ziel=mail:local             lokaler Teil einer Mailadresse (vor dem @)
  ziel='festerwert'           Konstante
"""
import argparse
import getpass
import hmac
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta

from croniter import croniter
from flask import (Flask, jsonify, redirect, render_template, request,
                   session, url_for)
from ldap3 import LEVEL, MODIFY_REPLACE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.abspath(os.getenv("SYNC_DATA", "jobs.json"))
DATA_DIR = os.path.dirname(DATA)
USERS = os.path.join(DATA_DIR, "users.json")
KEYFILE = os.path.join(DATA_DIR, ".secret_key")
MASK = "********"
USER_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
MIN_PW = 8
PW_METHOD = "pbkdf2:sha256"

runs, busy, last_run = {}, {}, {}   # busy: job-id -> run-id
io_lock = threading.Lock()
FAILS = {}                          # Login-Fehlversuche je IP


def env_flag(name):
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------- Dateien
def write_file(path, text):
    """Atomar schreiben (Rechte 0600); Fallback fuer einzeln gemountete Dateien."""
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, 0o600)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load():
    return read_json(DATA)


def save(jobs):
    with io_lock:
        write_file(DATA, json.dumps(jobs, indent=1, ensure_ascii=False))


def load_users():
    return read_json(USERS)


def save_users(users):
    write_file(USERS, json.dumps(users, indent=1, ensure_ascii=False))


def add_user(name, pw):
    with io_lock:
        users = load_users()
        users[name] = {"hash": generate_password_hash(pw, method=PW_METHOD)}
        save_users(users)


def load_secret_key():
    key = os.getenv("SECRET_KEY", "").strip()
    if key:
        return key
    try:
        with open(KEYFILE, encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    except OSError:
        pass
    key = secrets.token_hex(32)
    try:
        write_file(KEYFILE, key)
    except OSError:
        print("WARNUNG: .secret_key nicht schreibbar - Anmeldungen gelten nur bis zum "
              "Neustart (SECRET_KEY setzen oder Datenordner schreibbar machen).",
              file=sys.stderr)
    return key


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


def validate(job, full=True):
    """Liste von Problemen (leer = ok)."""
    need = [("src_host", "Quelle: Host"), ("src_base", "Quelle: Search-Base"),
            ("src_filter", "Suchfilter"), ("dst_host", "Ziel: Host"),
            ("dst_base", "Ziel-Base")]
    if full:
        need += [("key_attr", "Schluesselattribut"), ("object_classes", "objectClasses"),
                 ("mapping", "Attribut-Mapping")]
    problems = [f"{label} fehlt" for k, label in need if not str(job.get(k) or "").strip()]
    key = str(job.get("key_attr") or "").strip().lower()
    targets = {d.lower() for d, _ in parse_map(job.get("mapping"))}
    if full and key and targets and key not in targets:
        problems.append(f"Das Schluesselattribut '{key}' muss im Mapping als Ziel vorkommen")
    expr = str(job.get("cron") or "").strip()
    if expr and not croniter.is_valid(expr):
        problems.append(f"Ungueltiger Cron-Ausdruck: {expr}")
    return problems


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


def start(jid, job, dry, trigger="manuell"):
    if jid in busy:
        return None
    rid = uuid.uuid4().hex[:8]
    runs[rid] = {"job": job.get("name", jid), "log": [], "status": "running",
                 "stats": {}, "dry": dry, "trigger": trigger}
    while len(runs) > 50:
        runs.pop(next(iter(runs)))
    busy[jid] = rid

    def worker():
        try:
            run_job(job, dry, rid)
        except Exception:  # sollte nie passieren, run_job faengt alles ab
            runs.get(rid, {})["status"] = "error"
        finally:
            r = runs.get(rid, {})
            last_run[jid] = {"status": r.get("status", "error"), "stats": r.get("stats", {}),
                             "time": time.strftime("%d.%m.%Y %H:%M"), "dry": dry,
                             "trigger": trigger, "run": rid}
            busy.pop(jid, None)
    threading.Thread(target=worker, daemon=True).start()
    return rid


def next_run(job):
    expr = str(job.get("cron") or "").strip()
    if not expr or not croniter.is_valid(expr):
        return None
    nxt = croniter(expr, datetime.now().astimezone()).get_next(datetime)
    return nxt.strftime("%d.%m.%Y %H:%M")


def scheduler():
    """Startet Jobs nach Cron-Ausdruck (Vorrang) oder festem Intervall."""
    last_tick = time.time()
    last_start = {}
    while True:
        time.sleep(15)
        now = time.time()
        for jid, j in load().items():
            if jid in busy:
                continue
            expr = str(j.get("cron") or "").strip()
            try:
                if expr:
                    if not croniter.is_valid(expr):
                        continue
                    base = datetime.fromtimestamp(last_tick).astimezone()
                    due = croniter(expr, base).get_next(datetime).timestamp() <= now
                    if due and not validate(j):
                        start(jid, j, False, "Zeitplan")
                else:
                    mins = int(j.get("interval") or 0)
                    t = last_start.setdefault(jid, now)
                    if mins > 0 and now - t >= mins * 60 and not validate(j):
                        last_start[jid] = now
                        start(jid, j, False, "Intervall")
            except (ValueError, TypeError):
                continue
        last_tick = now


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


# ---------------------------------------------------------------- Flask
app = Flask(__name__, static_folder=os.path.join(HERE, "static"),
            template_folder=os.path.join(HERE, "templates"))
app.config.update(
    SESSION_COOKIE_NAME="ldapsync_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_flag("COOKIE_SECURE"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.getenv("SESSION_HOURS", "8") or 8)),
    MAX_CONTENT_LENGTH=1024 * 1024,
)
if env_flag("BEHIND_PROXY"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
DUMMY_HASH = generate_password_hash(secrets.token_hex(8), method=PW_METHOD)


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def asset(name):
    try:
        v = int(os.path.getmtime(os.path.join(app.static_folder, name)))
    except OSError:
        v = 0
    return url_for("static", filename=name, v=v)


@app.context_processor
def inject():
    return {"csrf_token": csrf_token, "asset": asset}


def token_ok(sent):
    expected = session.get("csrf")
    return bool(expected) and hmac.compare_digest(str(sent or ""), expected)


def login_locked(ip):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 600]
    return len(FAILS[ip]) >= 5


def do_login(name):
    session.clear()
    session["user"] = name
    session.permanent = True
    csrf_token()


@app.before_request
def guard():
    ep = request.endpoint
    if ep in (None, "static"):
        return None
    users = load_users()
    if not users:
        return None if ep == "setup" else redirect(url_for("setup"))
    if ep in ("login", "setup"):
        return None
    if session.get("user") not in users:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify(error="Nicht angemeldet"), 401
        return redirect(url_for("login"))
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not token_ok(request.headers.get("X-CSRF-Token")):
            return jsonify(error="Sicherheitspruefung fehlgeschlagen - Seite neu laden"), 403
    return None


@app.after_request
def secure_headers(resp):
    h = resp.headers
    h.setdefault("Content-Security-Policy",
                 "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "same-origin")
    if request.endpoint != "static":
        h["Cache-Control"] = "no-store"
    return resp


# ---- Seiten
@app.route("/login", methods=["GET", "POST"])
def login():
    if not load_users():
        return redirect(url_for("setup"))
    if session.get("user") in load_users():
        return redirect(url_for("index"))
    ip = request.remote_addr or "?"
    error, status = None, 200
    posted = request.form.get("username", "").strip() if request.method == "POST" else ""
    if request.method == "POST":
        if not token_ok(request.form.get("csrf")):
            error = "Die Sitzung ist abgelaufen. Bitte erneut versuchen."
        elif login_locked(ip):
            error, status = "Zu viele Fehlversuche. Bitte in 10 Minuten erneut versuchen.", 429
        else:
            name = request.form.get("username", "").strip()
            user = load_users().get(name)
            good = check_password_hash(user["hash"] if user else DUMMY_HASH,
                                       request.form.get("password", ""))
            if good and user:
                FAILS.pop(ip, None)
                do_login(name)
                return redirect(url_for("index"))
            FAILS.setdefault(ip, []).append(time.time())
            error = "Benutzername oder Passwort falsch."
    return render_template("login.html", mode="login", error=error, username=posted), status


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if load_users():
        return redirect(url_for("login"))
    error = None
    posted = request.form.get("username", "").strip() if request.method == "POST" else ""
    if request.method == "POST":
        name = posted
        pw, pw2 = request.form.get("password", ""), request.form.get("password2", "")
        if not token_ok(request.form.get("csrf")):
            error = "Die Sitzung ist abgelaufen. Bitte erneut versuchen."
        elif not USER_RE.match(name):
            error = "Benutzername: 1-64 Zeichen (Buchstaben, Ziffern, . _ @ -)."
        elif len(pw) < MIN_PW:
            error = f"Das Passwort muss mindestens {MIN_PW} Zeichen lang sein."
        elif pw != pw2:
            error = "Die Passwoerter stimmen nicht ueberein."
        else:
            add_user(name, pw)
            do_login(name)
            return redirect(url_for("index"))
    return render_template("login.html", mode="setup", error=error, username=posted)


@app.get("/")
def index():
    return render_template("app.html", user=session["user"])


# ---- Konto
@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.post("/api/password")
def password_change():
    d = request.get_json(silent=True) or {}
    user = load_users().get(session["user"])
    if not user or not check_password_hash(user["hash"], str(d.get("current", ""))):
        return jsonify(error="Das aktuelle Passwort ist falsch."), 400
    new = str(d.get("new", ""))
    if len(new) < MIN_PW:
        return jsonify(error=f"Das neue Passwort muss mindestens {MIN_PW} Zeichen lang sein."), 400
    add_user(session["user"], new)
    return jsonify(ok=True)


@app.get("/api/users")
def users_list():
    return jsonify(users=sorted(load_users()), me=session["user"])


@app.post("/api/users")
def users_add():
    d = request.get_json(silent=True) or {}
    name, pw = str(d.get("name", "")).strip(), str(d.get("password", ""))
    if not USER_RE.match(name):
        return jsonify(error="Benutzername: 1-64 Zeichen (Buchstaben, Ziffern, . _ @ -)."), 400
    if len(pw) < MIN_PW:
        return jsonify(error=f"Das Passwort muss mindestens {MIN_PW} Zeichen lang sein."), 400
    if name in load_users():
        return jsonify(error="Dieser Benutzer existiert bereits."), 409
    add_user(name, pw)
    return jsonify(ok=True)


@app.delete("/api/users/<name>")
def users_del(name):
    with io_lock:
        users = load_users()
        if name == session["user"]:
            return jsonify(error="Der eigene Benutzer kann nicht geloescht werden."), 400
        if name not in users:
            return jsonify(error="Unbekannter Benutzer."), 404
        users.pop(name)
        save_users(users)
    return jsonify(ok=True)


# ---- Jobs
@app.get("/api/jobs")
def jobs_get():
    jobs = load()
    for jid, j in jobs.items():
        for k in ("src_pw", "dst_pw"):
            if j.get(k):
                j[k] = MASK
        j["_last"] = last_run.get(jid)
        j["_running"] = busy.get(jid)
        j["_next"] = next_run(j)
    return jsonify(jobs)


@app.post("/api/jobs")
def jobs_save():
    j = request.get_json(silent=True)
    if not isinstance(j, dict):
        return jsonify(error="Ungueltige Daten"), 400
    jobs = load()
    jid = str(j.pop("id", "") or uuid.uuid4().hex[:8])
    old = jobs.get(jid, {})
    j = {k: v for k, v in j.items() if not k.startswith("_")}
    for k in ("src_pw", "dst_pw"):
        if j.get(k) == MASK:
            j[k] = old.get(k, "")
    jobs[jid] = j
    save(jobs)
    return jsonify(id=jid, warnings=validate(j))


@app.delete("/api/jobs/<jid>")
def jobs_del(jid):
    jobs = load()
    jobs.pop(jid, None)
    save(jobs)
    last_run.pop(jid, None)
    return jsonify(ok=True)


@app.post("/api/jobs/<jid>/run")
def jobs_run(jid):
    job = load().get(jid)
    if not job:
        return jsonify(error="Unbekannter Job"), 404
    problems = validate(job)
    if problems:
        return jsonify(error="; ".join(problems)), 400
    rid = start(jid, job, request.args.get("dry") == "1")
    return jsonify(run=rid) if rid else (jsonify(error="Der Job laeuft bereits"), 409)


@app.post("/api/jobs/<jid>/test")
def jobs_test(jid):
    job = load().get(jid)
    if not job:
        return jsonify(error="Unbekannter Job"), 404
    problems = validate(job, full=False)
    if problems:
        return jsonify(error="; ".join(problems)), 400
    return jsonify(log=test(job))


@app.get("/api/runs/<rid>")
def runs_get(rid):
    r = runs.get(rid)
    if not r:
        return jsonify(error="Unbekannter Lauf"), 404
    frm = max(0, request.args.get("from", 0, type=int))
    return jsonify(status=r["status"], stats=r.get("stats", {}), job=r["job"],
                   dry=r.get("dry", False), trigger=r.get("trigger", ""),
                   log=r["log"][frm:], total=len(r["log"]))


# ---------------------------------------------------------------- Start
def bootstrap_users():
    if load_users():
        return
    name, pw = os.getenv("UI_USER", "").strip(), os.getenv("UI_PASS", "")
    if name and pw:
        if USER_RE.match(name) and len(pw) >= MIN_PW:
            add_user(name, pw)
            print(f"Benutzer '{name}' aus UI_USER/UI_PASS angelegt.")
            return
        print(f"WARNUNG: UI_USER/UI_PASS ungueltig (Passwort mindestens {MIN_PW} Zeichen).",
              file=sys.stderr)
    print("HINWEIS: Noch kein Benutzer vorhanden. Der erste Aufruf im Browser oeffnet "
          "die Einrichtung (/setup) - rufe die Seite zuerst selbst auf.", file=sys.stderr)


app.secret_key = load_secret_key()


def main():
    ap = argparse.ArgumentParser(description="LDAP Sync UI")
    ap.add_argument("--run", metavar="JOB_ID", help="Job headless ausfuehren (z.B. per Cron)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--add-user", metavar="NAME", help="Benutzer anlegen bzw. Passwort setzen")
    a = ap.parse_args()

    if a.add_user:
        name = a.add_user.strip()
        if not USER_RE.match(name):
            sys.exit("Ungueltiger Benutzername (1-64 Zeichen: Buchstaben, Ziffern, . _ @ -)")
        pw = getpass.getpass("Passwort: ")
        if len(pw) < MIN_PW:
            sys.exit(f"Das Passwort muss mindestens {MIN_PW} Zeichen lang sein.")
        if pw != getpass.getpass("Passwort wiederholen: "):
            sys.exit("Die Passwoerter stimmen nicht ueberein.")
        add_user(name, pw)
        print(f"Benutzer '{name}' gespeichert ({USERS}).")
        return

    if a.run:
        job = load().get(a.run)
        if not job:
            sys.exit(f"Job '{a.run}' nicht gefunden in {DATA}")
        problems = validate(job)
        if problems:
            sys.exit("Job unvollstaendig: " + "; ".join(problems))
        rid = start(a.run, job, a.dry_run, "Kommandozeile")
        while runs[rid]["status"] == "running":
            time.sleep(0.5)
        print("\n".join(runs[rid]["log"]))
        sys.exit(0 if runs[rid]["status"] == "done" else 1)

    bootstrap_users()
    threading.Thread(target=scheduler, daemon=True).start()
    app.run(host=os.getenv("UI_HOST", "127.0.0.1"), port=int(os.getenv("UI_PORT", "5000")),
            threaded=True)


if __name__ == "__main__":
    main()
