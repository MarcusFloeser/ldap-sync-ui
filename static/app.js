"use strict";

const $ = (s, r = document) => r.querySelector(s);
const CSRF = $('meta[name="csrf-token"]').content;

/* ---------------------------------------------------------------- Felder */
const FIELDS = {
  general: [
    { k: "name", l: "Name", ph: "z. B. Domino → OpenLDAP" },
    { k: "cron", l: "Zeitplan (Cron-Ausdruck)", ph: "*/30 * * * *", mono: true,
      hint: "Minute Stunde Tag Monat Wochentag, z. B. 15 2 * * 1-5. Leer = kein Cron." },
    { k: "interval", l: "oder: alle N Minuten", ph: "0",
      hint: "Nur wirksam ohne Cron-Ausdruck. 0 = nur manuell." },
    { k: "verify_tls", l: "TLS-Zertifikat prüfen", t: "bool" },
  ],
  src: [
    { k: "src_host", l: "Host", ph: "ldap.example.com" },
    { k: "src_port", l: "Port", ph: "389 / 636", hint: "Leer = Standardport" },
    { k: "src_ssl", l: "LDAPS (SSL)", t: "bool" },
    { k: "src_user", l: "Bind-DN", mono: true },
    { k: "src_pw", l: "Passwort", t: "password" },
    { k: "src_base", l: "Search-Base", mono: true },
    { k: "src_filter", l: "Suchfilter", mono: true, hint: "Einzige Selektion der Quelle." },
    { k: "src_scope", l: "Scope", t: "select",
      opts: [["sub", "Gesamter Teilbaum (sub)"], ["one", "Nur eine Ebene (one)"]] },
  ],
  dst: [
    { k: "dst_host", l: "Host", ph: "ldap.example.com" },
    { k: "dst_port", l: "Port", ph: "389 / 636", hint: "Leer = Standardport" },
    { k: "dst_ssl", l: "LDAPS (SSL)", t: "bool" },
    { k: "dst_user", l: "Bind-DN", mono: true },
    { k: "dst_pw", l: "Passwort", t: "password" },
    { k: "dst_base", l: "Ziel-Base", mono: true, hint: "Einträge landen direkt darunter. Muss existieren." },
  ],
  map: [
    { k: "key_attr", l: "Schlüsselattribut (wird RDN)", ph: "uid", mono: true },
    { k: "object_classes", l: "objectClasses (Komma-getrennt)", mono: true },
  ],
  mapping: { k: "mapping", l: "Attribut-Mapping", t: "textarea", rows: 9 },
  sync: [
    { k: "remove_missing", l: "Attribute entfernen, die in der Quelle fehlen", t: "bool" },
    { k: "delete_orphans", l: "Verwaiste Einträge im Ziel löschen (nur mit Marker)", t: "bool" },
    { k: "marker_attr", l: "Marker-Attribut", mono: true, hint: "Kennzeichnet synchronisierte Einträge." },
    { k: "marker_value", l: "Marker-Wert", mono: true },
  ],
};

const DEF = {
  name: "", cron: "", interval: "0", verify_tls: true,
  src_scope: "sub", src_filter: "(objectClass=person)",
  key_attr: "uid", object_classes: "top,person,organizationalPerson,inetOrgPerson",
  marker_attr: "employeeType", marker_value: "ldap-sync", remove_missing: true,
  mapping: "uid=uid|mail:local\ncn=cn\nsn=sn\ngivenName=givenName\ndisplayName=displayName|cn\nmail=mail\ntelephoneNumber=telephoneNumber",
};

const CHIPS = [
  ["added", "Neu", "ok"], ["modified", "Geändert", "info"], ["unchanged", "Unverändert", ""],
  ["skipped", "Übersprungen", "warn"], ["deleted", "Gelöscht", "err"], ["errors", "Fehler", "err"],
];

/* ---------------------------------------------------------------- Helfer */
function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c);
  return e;
}

function toast(msg, kind = "") {
  const t = el("div", { class: "toast " + kind, text: msg });
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "err" ? 7000 : 3500);
}

async function api(url, method = "GET", body) {
  const r = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("Nicht angemeldet"); }
  let data = {};
  try { data = await r.json(); } catch (_) { /* leere Antwort */ }
  if (!r.ok) {
    const e = new Error(data.error || "Fehler (HTTP " + r.status + ")");
    e.status = r.status;
    throw e;
  }
  return data;
}

/* ---------------------------------------------------------------- Zustand */
let jobs = {};
let cur = null;        // Job-ID oder null (neuer Job)
let dirty = false;
let pollTimer = null;
let polling = false;   // true, solange ein Lauf beobachtet wird
let logState = { rid: null, n: 0 };

/* ---------------------------------------------------------------- Formular */
function field(f, job) {
  const v = job[f.k];
  if (f.t === "bool") {
    const input = el("input", { type: "checkbox", "data-k": f.k });
    input.checked = !!v;
    return el("label", { class: "check" }, input, el("span", { text: f.l }));
  }
  let input;
  if (f.t === "select") {
    input = el("select", { "data-k": f.k }, f.opts.map(([val, txt]) => el("option", { value: val, text: txt })));
    input.value = v ?? f.opts[0][0];
  } else if (f.t === "textarea") {
    input = el("textarea", { "data-k": f.k, rows: f.rows || 8, spellcheck: "false", class: "mono" });
    input.value = v ?? "";
  } else {
    input = el("input", {
      "data-k": f.k, type: f.t === "password" ? "password" : "text", placeholder: f.ph || "",
      autocomplete: f.t === "password" ? "new-password" : "off", spellcheck: "false",
      class: f.mono ? "mono" : "",
    });
    input.value = v ?? "";
  }
  return el("label", { class: "field" },
    el("span", { class: "lbl", text: f.l }), input,
    f.hint ? el("span", { class: "hint", text: f.hint }) : null);
}

function card(title, sub, body, bodyClass = "") {
  return el("section", { class: "card" },
    el("div", { class: "card-head" },
      el("h3", { text: title }), sub ? el("p", { class: "muted", text: sub }) : null),
    el("div", { class: "card-body " + bodyClass }, body));
}

function mappingHelp() {
  const li = (code, text) => el("li", {}, el("code", { text: code }), " – " + text);
  return el("ul", { class: "help" },
    li("cn=cn", "Attribut kopieren"),
    li("uid=uid|mail:local", "erstes vorhandenes verwenden; mail:local = Teil vor dem @"),
    li("o='Firma'", "Konstante"),
    li("# …", "Kommentarzeile"));
}

function renderForm(job) {
  const f = (list) => list.map((x) => field(x, job));
  $("#form").replaceChildren(
    card("Allgemein", null, f(FIELDS.general), "auto"),
    el("div", { class: "two" },
      card("Quelle", "Hier werden die Einträge gelesen.", f(FIELDS.src)),
      card("Ziel", "Hierhin werden die Einträge geschrieben.", f(FIELDS.dst))),
    card("Abbildung", "Zuordnung der Attribute von Quelle nach Ziel.",
      [el("div", { class: "card-body auto" }, f(FIELDS.map)), field(FIELDS.mapping, job), mappingHelp()]),
    card("Abgleich", null, f(FIELDS.sync), "auto"));
  $("#form [data-k=name]").addEventListener("input", (e) => {
    $("#title").textContent = e.target.value || "Neuer Job";
  });
}

function readForm() {
  const j = {};
  document.querySelectorAll("#form [data-k]").forEach((e) => {
    j[e.dataset.k] = e.type === "checkbox" ? e.checked : e.value;
  });
  if (cur) j.id = cur;
  return j;
}

function setDirty(v) {
  dirty = v;
  $("#btn-save").classList.toggle("dirty", v);
  $("#btn-save").textContent = v ? "Speichern •" : "Speichern";
}

/* ---------------------------------------------------------------- Liste */
function statusOf(j) {
  if (j._running) return ["running", "Läuft"];
  if (j._last) return [j._last.status, j._last.status === "done" ? "Letzter Lauf erfolgreich" : "Letzter Lauf mit Fehlern"];
  return ["idle", "Noch nicht gelaufen"];
}

function renderList() {
  const ul = $("#jobs");
  const items = Object.entries(jobs).map(([id, j]) => {
    const [st, title] = statusOf(j);
    const sched = j.cron ? "Cron" : (+j.interval > 0 ? j.interval + " min" : "");
    const li = el("li", { class: "job" + (id === cur ? " on" : ""), tabindex: "0", role: "button" },
      el("span", { class: "dot " + st, title }),
      el("span", { class: "jname", text: j.name || id }),
      sched ? el("span", { class: "tag", text: sched }) : null);
    li.addEventListener("click", () => select(id));
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(id); }
    });
    return li;
  });
  if (!items.length) items.push(el("li", { class: "muted pad", text: "Noch keine Jobs." }));
  ul.replaceChildren(...items);
}

function renderLastInfo() {
  const j = jobs[cur];
  const parts = [];
  if (j && j._last) {
    const l = j._last;
    parts.push(`Letzter Lauf: ${l.time}${l.dry ? " (Dry-Run)" : ""}, ${l.status === "done" ? "erfolgreich" : "mit Fehlern"}`
      + (l.trigger ? ` · ${l.trigger}` : ""));
  }
  if (j && j._next) parts.push("Nächster Lauf: " + j._next);
  $("#lastinfo").textContent = parts.join(" · ");
}

async function reload() {
  jobs = await api("/api/jobs");
  renderList();
}

function showEditor(show) {
  $("#editor").hidden = !show;
  $("#empty").hidden = show;
}

function resetResult() {
  clearTimeout(pollTimer);
  polling = false;
  logState = { rid: null, n: 0 };
  $("#result").hidden = true;
  $("#log").replaceChildren();
  $("#chips").replaceChildren();
}

function select(id) {
  if (dirty && !confirm("Ungespeicherte Änderungen verwerfen?")) return;
  cur = id;
  setDirty(false);
  resetResult();
  showEditor(true);
  const j = jobs[id];
  $("#title").textContent = j.name || id;
  renderForm(j);
  renderList();
  renderLastInfo();
  setBusy(false);
  if (j._running) poll(j._running);
}

function newJob() {
  if (dirty && !confirm("Ungespeicherte Änderungen verwerfen?")) return;
  cur = null;
  setDirty(false);
  resetResult();
  showEditor(true);
  $("#title").textContent = "Neuer Job";
  $("#lastinfo").textContent = "";
  renderForm(DEF);
  renderList();
  setBusy(false);
  $("#btn-del").disabled = true;
}

/* ---------------------------------------------------------------- Aktionen */
function setBusy(b) {
  ["btn-save", "btn-test", "btn-dry", "btn-run"].forEach((id) => { $("#" + id).disabled = b; });
  $("#btn-del").disabled = b || !cur;
}

async function save(quiet = false) {
  const r = await api("/api/jobs", "POST", readForm());
  cur = r.id;
  await reload();
  setDirty(false);
  $("#title").textContent = jobs[cur].name || cur;
  renderForm(jobs[cur]);
  renderLastInfo();
  $("#btn-del").disabled = false;
  if (!quiet) toast("Gespeichert", "ok");
  return r;
}

async function guarded(fn) {
  try { await fn(); } catch (e) { if (e.message !== "Nicht angemeldet") toast(e.message, "err"); }
}

function logLine(text, cls) {
  const m = text.match(/^\d\d:\d\d:\d\d (ADD|MODIFY|DELETE|SKIP|FEHLER|ABBRUCH)/);
  return el("div", { class: "ln" + (cls ? " " + cls : m ? " " + m[1] : ""), text });
}

function showStats(stats) {
  $("#chips").replaceChildren(...CHIPS
    .filter(([k]) => stats && k in stats)
    .map(([k, label, cls]) => el("span", { class: "chip " + (stats[k] ? cls : "") },
      label, el("b", { text: String(stats[k]) }))));
}

function setStatus(status, text) {
  const b = $("#result-status");
  b.className = "badge " + status;
  b.textContent = text;
}

async function doTest() {
  await save(true);
  resetResult();
  $("#result").hidden = false;
  $("#result-title").textContent = "Verbindungstest";
  setStatus("running", "Teste …");
  const r = await api(`/api/jobs/${cur}/test`, "POST");
  $("#log").replaceChildren(...r.log.map((t) => logLine(t, t.includes("FEHLER") ? "FEHLER" : "ADD")));
  const bad = r.log.some((t) => t.includes("FEHLER"));
  setStatus(bad ? "error" : "done", bad ? "Fehler" : "In Ordnung");
}

async function doRun(dry) {
  if (!dry && !confirm("Den Sync jetzt gegen das Ziel ausführen? Es werden Einträge angelegt, geändert und ggf. gelöscht.")) return;
  await save(true);
  resetResult();
  const r = await api(`/api/jobs/${cur}/run?dry=${dry ? 1 : 0}`, "POST");
  poll(r.run);
}

function poll(rid) {
  clearTimeout(pollTimer);
  polling = true;
  setBusy(true);
  $("#result").hidden = false;
  if (logState.rid !== rid) {
    logState = { rid, n: 0 };
    $("#log").replaceChildren();
  }
  const tick = async () => {
    try {
      const s = await api(`/api/runs/${rid}?from=${logState.n}`);
      $("#result-title").textContent = (s.dry ? "Dry-Run" : "Sync") + (s.trigger ? ` (${s.trigger})` : "");
      const box = $("#log");
      const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
      s.log.forEach((t) => box.append(logLine(t)));
      logState.n = s.total;
      if (stick) box.scrollTop = box.scrollHeight;
      showStats(s.stats);
      if (s.status === "running") {
        setStatus("running", "Läuft …");
        pollTimer = setTimeout(tick, 1000);
      } else {
        setStatus(s.status, s.status === "done" ? "Abgeschlossen" : "Mit Fehlern beendet");
        polling = false;
        setBusy(false);
        await reload();
        renderLastInfo();
        toast(s.status === "done" ? "Lauf abgeschlossen" : "Lauf mit Fehlern beendet", s.status === "done" ? "ok" : "err");
      }
    } catch (e) {
      polling = false;
      setBusy(false);
      if (e.message !== "Nicht angemeldet") toast(e.message, "err");
    }
  };
  tick();
}

async function doDelete() {
  if (!cur || !confirm("Diesen Job wirklich löschen?")) return;
  await api("/api/jobs/" + cur, "DELETE");
  cur = null;
  setDirty(false);
  resetResult();
  await reload();
  showEditor(false);
  toast("Job gelöscht");
}

/* ---------------------------------------------------------------- Konto / Benutzer */
function showErr(id, msg) {
  const p = $(id);
  p.textContent = msg || "";
  p.hidden = !msg;
}

async function renderUsers() {
  const r = await api("/api/users");
  $("#userlist").replaceChildren(...r.users.map((u) => {
    const me = u === r.me;
    const del = el("button", { class: "btn small danger", type: "button", text: "Löschen" });
    del.disabled = me;
    del.title = me ? "Der eigene Benutzer kann nicht gelöscht werden" : "";
    del.addEventListener("click", () => guarded(async () => {
      if (!confirm(`Benutzer „${u}“ löschen?`)) return;
      await api("/api/users/" + encodeURIComponent(u), "DELETE");
      await renderUsers();
    }));
    return el("li", {}, el("span", { class: "uname", text: u + (me ? " (du)" : "") }), del);
  }));
}

function initDialogs() {
  document.querySelectorAll("dialog [data-close]").forEach((b) =>
    b.addEventListener("click", () => b.closest("dialog").close()));

  $("#btn-pw").addEventListener("click", () => {
    $("#f-pw").reset();
    showErr("#pw-err");
    $("#dlg-pw").showModal();
  });
  $("#f-pw").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    if (f.get("new") !== f.get("new2")) return showErr("#pw-err", "Die neuen Passwörter stimmen nicht überein.");
    try {
      await api("/api/password", "POST", { current: f.get("current"), new: f.get("new") });
      $("#dlg-pw").close();
      toast("Passwort geändert", "ok");
    } catch (err) { showErr("#pw-err", err.message); }
  });

  $("#btn-users").addEventListener("click", () => guarded(async () => {
    $("#f-user").reset();
    showErr("#user-err");
    await renderUsers();
    $("#dlg-users").showModal();
  }));
  $("#f-user").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api("/api/users", "POST", { name: f.get("name"), password: f.get("password") });
      e.target.reset();
      showErr("#user-err");
      await renderUsers();
      toast("Benutzer hinzugefügt", "ok");
    } catch (err) { showErr("#user-err", err.message); }
  });

  $("#btn-logout").addEventListener("click", async () => {
    try { await api("/api/logout", "POST"); } catch (_) { /* egal */ }
    location.href = "/login";
  });
}

/* ---------------------------------------------------------------- Start */
function init() {
  $("#btn-new").addEventListener("click", newJob);
  $("#btn-new2").addEventListener("click", newJob);
  $("#btn-save").addEventListener("click", () => guarded(save));
  $("#btn-test").addEventListener("click", () => guarded(doTest));
  $("#btn-dry").addEventListener("click", () => guarded(() => doRun(true)));
  $("#btn-run").addEventListener("click", () => guarded(() => doRun(false)));
  $("#btn-del").addEventListener("click", () => guarded(doDelete));
  $("#form").addEventListener("input", () => setDirty(true));
  $("#form").addEventListener("change", () => setDirty(true));
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s" && !$("#editor").hidden) {
      e.preventDefault();
      guarded(save);
    }
  });
  window.addEventListener("beforeunload", (e) => { if (dirty) { e.preventDefault(); e.returnValue = ""; } });
  initDialogs();

  guarded(async () => {
    await reload();
    const ids = Object.keys(jobs);
    if (ids.length) select(ids[0]); else showEditor(false);
  });
  // Status der Jobs gelegentlich auffrischen (z. B. nach Cron-Läufen)
  setInterval(() => {
    if (dirty || polling) return;
    reload().then(() => {
      renderLastInfo();
      const j = jobs[cur];
      if (j && j._running) poll(j._running);
    }).catch(() => {});
  }, 20000);
}

init();
