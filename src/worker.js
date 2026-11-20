// Wichteln – Cloudflare Worker (API) mit D1-Datenbank.
// Die statischen Dateien (public/) liefert Cloudflare direkt aus; alles unter /api/ landet hier.

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, data TEXT NOT NULL, admin_hash TEXT NOT NULL, created_at INTEGER)",
  "CREATE TABLE IF NOT EXISTS participants(id TEXT PRIMARY KEY, pid TEXT NOT NULL, name TEXT NOT NULL, managed_by TEXT, pub TEXT, priv TEXT, pin_hash TEXT, created_at INTEGER)",
  "CREATE INDEX IF NOT EXISTS ix_part_pid ON participants(pid)",
  "CREATE TABLE IF NOT EXISTS wishes(id TEXT PRIMARY KEY, pid TEXT NOT NULL, owner TEXT NOT NULL, n INTEGER, text TEXT, link TEXT, res TEXT, created_at INTEGER)",
  "CREATE INDEX IF NOT EXISTS ix_wish_pid ON wishes(pid)",
  "CREATE TABLE IF NOT EXISTS assign(pid TEXT NOT NULL, uid TEXT NOT NULL, sealed TEXT, PRIMARY KEY(pid, uid))",
  "CREATE TABLE IF NOT EXISTS meta(pid TEXT PRIMARY KEY, reveal TEXT, result TEXT)",
  "CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, pid TEXT NOT NULL, who TEXT NOT NULL, created_at INTEGER)",
  "CREATE TABLE IF NOT EXISTS attempts(k TEXT PRIMARY KEY, n INTEGER, since INTEGER)",
];
let ready = null;
const init = env => (ready ||= env.DB.batch(SCHEMA.map(s => env.DB.prepare(s))).catch(e => { ready = null; throw e; }));

const MAX_TRIES = 5, LOCK_MS = 10 * 60 * 1000, SESSION_MS = 90 * 24 * 3600 * 1000;

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const fail = (status, msg) => { throw new HttpError(status, msg); };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});

const rid = (n = 10) => {
  const a = "abcdefghijkmnopqrstuvwxyz23456789";
  return [...crypto.getRandomValues(new Uint8Array(n))].map(x => a[x % a.length]).join("");
};
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function sha(s) { return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))); }
async function hashPin(pin) { const salt = rid(16); return salt + "$" + await sha(salt + ":" + pin); }
async function checkPin(pin, stored) {
  if (!stored) return false;
  const [salt, h] = stored.split("$");
  return (await sha(salt + ":" + pin)) === h;
}

const str = (v, max, name, required = true) => {
  const s = typeof v === "string" ? v.trim() : "";
  if (required && !s) fail(400, `${name} fehlt.`);
  if (s.length > max) fail(400, `${name} ist zu lang.`);
  return s;
};
const pinOk = p => typeof p === "string" && /^\d{4}$/.test(p);
const famKey = s => s.trim().toLowerCase().replace(/\s+/g, " ");
const sealedOk = s => s && typeof s === "object" && ["k", "iv", "ct"].every(k => typeof s[k] === "string" && s[k].length < 20000);
const privOk = p => p && typeof p === "object" && ["salt", "iv", "ct"].every(k => typeof p[k] === "string" && p[k].length < 8000);

function cleanWishes(list) {
  if (!Array.isArray(list)) return [];
  if (list.length > 20) fail(400, "Höchstens 20 Wünsche.");
  return list.map(w => ({
    id: typeof w.id === "string" && /^[a-z0-9]{6,20}$/.test(w.id) ? w.id : null,
    text: str(w.text, 200, "Wunsch"),
    link: str(w.link || "", 500, "Link", false),
  }));
}

// ---------- Datenbank-Hilfen ----------
async function getProject(env, pid) {
  const r = await env.DB.prepare("SELECT id, data, admin_hash FROM projects WHERE id = ?").bind(pid).first();
  if (!r) fail(404, "Dieses Wichtelprojekt gibt es nicht.");
  return { id: r.id, adminHash: r.admin_hash, ...JSON.parse(r.data) };
}
const saveProject = (env, p) => {
  const { id, adminHash, ...data } = p;
  return env.DB.prepare("UPDATE projects SET data = ? WHERE id = ?").bind(JSON.stringify(data), id).run();
};
const publicProject = p => {
  const { adminHash, admin, ...rest } = p;
  return { ...rest, admin: admin ? { pub: admin.pub } : null };
};
const parts = (env, pid) => env.DB.prepare("SELECT id, name, managed_by, pub, priv, pin_hash, created_at FROM participants WHERE pid = ? ORDER BY created_at").bind(pid).all().then(r => r.results);

async function session(env, req, pid) {
  const t = req.headers.get("x-session");
  if (!t) return null;
  const r = await env.DB.prepare("SELECT pid, who, created_at FROM sessions WHERE token = ?").bind(t).first();
  if (!r || r.pid !== pid || Date.now() - r.created_at > SESSION_MS) return null;
  return r.who;
}
async function requireAdmin(env, req, pid) {
  const t = req.headers.get("x-admin");
  const r = t && await env.DB.prepare("SELECT pid, who, created_at FROM sessions WHERE token = ?").bind(t).first();
  if (!r || r.pid !== pid || r.who !== "admin" || Date.now() - r.created_at > SESSION_MS) fail(401, "Bitte Admin erneut entsperren.");
}
async function requireUser(env, req, pid) {
  const who = await session(env, req, pid);
  if (!who) fail(401, "Bitte erneut mit PIN anmelden.");
  return who;
}
async function newSession(env, pid, who) {
  const token = rid(32);
  await env.DB.prepare("INSERT INTO sessions(token, pid, who, created_at) VALUES(?,?,?,?)").bind(token, pid, who, Date.now()).run();
  return token;
}
async function guardTries(env, k) {
  const r = await env.DB.prepare("SELECT n, since FROM attempts WHERE k = ?").bind(k).first();
  if (r && r.n >= MAX_TRIES && Date.now() - r.since < LOCK_MS) fail(429, "Zu viele falsche Versuche. Bitte warte 10 Minuten.");
}
async function failTry(env, k) {
  const r = await env.DB.prepare("SELECT n, since FROM attempts WHERE k = ?").bind(k).first();
  const fresh = !r || Date.now() - r.since >= LOCK_MS;
  await env.DB.prepare("INSERT OR REPLACE INTO attempts(k, n, since) VALUES(?,?,?)").bind(k, fresh ? 1 : r.n + 1, fresh ? Date.now() : r.since).run();
}
const okTry = (env, k) => env.DB.prepare("DELETE FROM attempts WHERE k = ?").bind(k).run();

// Darf die Sitzung "who" für die Person "owner" handeln? (selbst oder von ihr eingetragen)
async function mayActFor(env, pid, who, owner) {
  if (who === owner) return true;
  const r = await env.DB.prepare("SELECT managed_by FROM participants WHERE id = ? AND pid = ?").bind(owner, pid).first();
  return !!r && r.managed_by === who;
}

async function writeWishes(env, pid, owner, list) {
  const existing = (await env.DB.prepare("SELECT id FROM wishes WHERE pid = ? AND owner = ?").bind(pid, owner).all()).results.map(r => r.id);
  const keep = new Set(list.filter(w => w.id && existing.includes(w.id)).map(w => w.id));
  const st = [];
  for (const id of existing) if (!keep.has(id)) st.push(env.DB.prepare("DELETE FROM wishes WHERE id = ?").bind(id));
  list.forEach((w, i) => {
    if (w.id && keep.has(w.id)) st.push(env.DB.prepare("UPDATE wishes SET text = ?, link = ?, n = ? WHERE id = ?").bind(w.text, w.link, i + 1, w.id));
    else st.push(env.DB.prepare("INSERT INTO wishes(id, pid, owner, n, text, link, res, created_at) VALUES(?,?,?,?,?,?,NULL,?)").bind(rid(), pid, owner, i + 1, w.text, w.link, Date.now()));
  });
  if (st.length) await env.DB.batch(st);
}

// ---------- Routen ----------
async function handle(req, env, url) {
  await init(env);
  const m = req.method;
  const seg = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  let body = {};
  if (m !== "GET" && m !== "DELETE") {
    const txt = await req.text();
    if (txt.length > 300000) fail(413, "Zu viele Daten.");
    try { body = txt ? JSON.parse(txt) : {}; } catch { fail(400, "Ungültige Anfrage."); }
  }

  // GET /api/projects
  if (seg[0] === "projects" && seg.length === 1 && m === "GET") {
    const rows = (await env.DB.prepare("SELECT p.id, p.data, (SELECT COUNT(*) FROM participants x WHERE x.pid = p.id) AS cnt FROM projects p").all()).results;
    return json({ projects: rows.map(r => ({ ...publicProject({ id: r.id, ...JSON.parse(r.data) }), count: r.cnt })) });
  }
  // POST /api/projects – neues Wichtelprojekt
  if (seg[0] === "projects" && seg.length === 1 && m === "POST") {
    const family = str(body.family, 40, "Familienname");
    const year = Number(body.year);
    if (!Number.isInteger(year) || year < 2000 || year > 2200) fail(400, "Ungültiges Jahr.");
    if (!pinOk(body.adminPin)) fail(400, "Die PIN muss aus 4 Ziffern bestehen.");
    if (!body.admin || typeof body.admin.pub !== "string" || !privOk(body.admin.priv)) fail(400, "Ungültige Anfrage.");
    const all = (await env.DB.prepare("SELECT data FROM projects").all()).results.map(r => JSON.parse(r.data));
    if (all.some(p => p.familyKey === famKey(family) && p.year === year)) fail(409, `Für Familie ${family} gibt es ${year} schon ein Wichteln.`);
    const id = rid();
    const data = {
      family, familyKey: famKey(family), year, deadline: str(body.deadline || "", 10, "Datum", false),
      budgetMin: Math.max(0, Number(body.budgetMin) || 0), budgetMax: Math.max(0, Number(body.budgetMax) || 0),
      rules: str(body.rules || "", 1000, "Spielregeln", false), phase: "open", gifts: 0,
      admin: { pub: body.admin.pub, priv: body.admin.priv }, createdAt: Date.now(),
    };
    await env.DB.prepare("INSERT INTO projects(id, data, admin_hash, created_at) VALUES(?,?,?,?)").bind(id, JSON.stringify(data), await hashPin(body.adminPin), Date.now()).run();
    return json({ id, adminToken: await newSession(env, id, "admin") });
  }

  if (seg[0] !== "p" || !seg[1]) fail(404, "Nicht gefunden.");
  const pid = seg[1], act = seg[2] || "", arg = seg[3];
  const p = await getProject(env, pid);

  // GET /api/p/:pid – alles Öffentliche
  if (!act && m === "GET") {
    const ps = await parts(env, pid);
    const ws = (await env.DB.prepare("SELECT id, owner, n, text, link, res FROM wishes WHERE pid = ?").bind(pid).all()).results;
    const meta = await env.DB.prepare("SELECT result FROM meta WHERE pid = ?").bind(pid).first();
    return json({
      project: publicProject(p),
      participants: ps.map(x => ({ id: x.id, name: x.name, managedBy: x.managed_by, pub: x.pub, createdAt: x.created_at })),
      wishes: ws,
      result: meta && meta.result ? JSON.parse(meta.result) : null,
    });
  }
  // PATCH /api/p/:pid – Einstellungen / Phase / Anzahl Geschenke (Admin)
  if (!act && m === "PATCH") {
    await requireAdmin(env, req, pid);
    if ("family" in body) { p.family = str(body.family, 40, "Familienname"); p.familyKey = famKey(p.family); }
    if ("deadline" in body) p.deadline = str(body.deadline || "", 10, "Datum", false);
    if ("budgetMin" in body) p.budgetMin = Math.max(0, Number(body.budgetMin) || 0);
    if ("budgetMax" in body) p.budgetMax = Math.max(0, Number(body.budgetMax) || 0);
    if ("rules" in body) p.rules = str(body.rules || "", 1000, "Spielregeln", false);
    if ("phase" in body) {
      const ok = { open: ["closed"], closed: ["open"], revealed: ["archived"] };
      if (!(ok[p.phase] || []).includes(body.phase)) fail(409, "Dieser Schritt ist gerade nicht möglich.");
      if (body.phase === "closed") {
        const n = (await env.DB.prepare("SELECT COUNT(*) AS c FROM participants WHERE pid = ?").bind(pid).first()).c;
        if (n < 2) fail(409, "Es braucht mindestens 2 Teilnehmer.");
      }
      p.phase = body.phase;
    }
    if ("gifts" in body) {
      const n = (await env.DB.prepare("SELECT COUNT(*) AS c FROM participants WHERE pid = ?").bind(pid).first()).c;
      const g = Number(body.gifts);
      if (p.phase !== "closed") fail(409, "Die Anzahl kann nur bei geschlossener Anmeldung festgelegt werden.");
      if (!Number.isInteger(g) || g < 1 || g > n - 1) fail(400, "Ungültige Anzahl Geschenke.");
      p.gifts = g;
    }
    await saveProject(env, p);
    return json({ ok: true });
  }
  // DELETE /api/p/:pid – leeres Projekt löschen (Admin)
  if (!act && m === "DELETE") {
    await requireAdmin(env, req, pid);
    const n = (await env.DB.prepare("SELECT COUNT(*) AS c FROM participants WHERE pid = ?").bind(pid).first()).c;
    if (n > 0 || p.phase !== "open") fail(409, "Nur leere Projekte können gelöscht werden.");
    await env.DB.batch([env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(pid), env.DB.prepare("DELETE FROM sessions WHERE pid = ?").bind(pid)]);
    return json({ ok: true });
  }
  // POST /api/p/:pid/admin-login
  if (act === "admin-login" && m === "POST") {
    const k = "admin:" + pid;
    await guardTries(env, k);
    if (!pinOk(body.pin) || !await checkPin(body.pin, p.adminHash)) { await failTry(env, k); fail(401, "Die Admin-PIN ist falsch."); }
    await okTry(env, k);
    return json({ token: await newSession(env, pid, "admin"), priv: p.admin.priv });
  }
  // POST /api/p/:pid/join – mitmachen (selbst oder eine verwaltete Person)
  if (act === "join" && m === "POST") {
    if (p.phase !== "open") fail(409, "Die Anmeldung ist geschlossen.");
    const name = str(body.name, 30, "Name");
    if (typeof body.pub !== "string" || body.pub.length > 2000 || !privOk(body.priv)) fail(400, "Ungültige Anfrage.");
    const wishes = cleanWishes(body.wishes);
    const ps = await parts(env, pid);
    if (ps.length >= 60) fail(409, "Zu viele Teilnehmer.");
    if (ps.some(x => x.name.toLowerCase() === name.toLowerCase())) fail(409, "Diesen Namen gibt es schon. Ergänze z. B. den Anfangsbuchstaben des Nachnamens.");
    let managedBy = null, pinHash = null;
    if (body.managedBy) {
      const who = await requireUser(env, req, pid);
      const mgr = ps.find(x => x.id === who);
      if (who !== body.managedBy || !mgr || mgr.managed_by) fail(403, "Nicht erlaubt.");
      managedBy = who;
    } else {
      if (!pinOk(body.pin)) fail(400, "Die PIN muss aus 4 Ziffern bestehen.");
      pinHash = await hashPin(body.pin);
    }
    const id = rid();
    await env.DB.prepare("INSERT INTO participants(id, pid, name, managed_by, pub, priv, pin_hash, created_at) VALUES(?,?,?,?,?,?,?,?)")
      .bind(id, pid, name, managedBy, body.pub, JSON.stringify(body.priv), pinHash, Date.now()).run();
    await writeWishes(env, pid, id, wishes);
    return json({ id, token: managedBy ? null : await newSession(env, pid, id) });
  }
  // POST /api/p/:pid/login
  if (act === "login" && m === "POST") {
    const ps = await parts(env, pid);
    const me = ps.find(x => x.id === body.id && !x.managed_by);
    if (!me) fail(404, "Diese Person gibt es nicht.");
    const k = "user:" + me.id;
    await guardTries(env, k);
    if (!pinOk(body.pin) || !await checkPin(body.pin, me.pin_hash)) { await failTry(env, k); fail(401, "Die PIN ist falsch."); }
    await okTry(env, k);
    const keys = [me, ...ps.filter(x => x.managed_by === me.id)].map(x => ({ id: x.id, priv: JSON.parse(x.priv) }));
    return json({ token: await newSession(env, pid, me.id), keys });
  }
  // GET /api/p/:pid/assign – eigene (verschlüsselte) Einteilung
  if (act === "assign" && m === "GET") {
    const who = await requireUser(env, req, pid);
    const ids = [who, ...(await parts(env, pid)).filter(x => x.managed_by === who).map(x => x.id)];
    const out = {};
    for (const uid of ids) {
      const r = await env.DB.prepare("SELECT sealed FROM assign WHERE pid = ? AND uid = ?").bind(pid, uid).first();
      if (r) out[uid] = JSON.parse(r.sealed);
    }
    return json({ items: out });
  }
  // PUT /api/p/:pid/wishes/:owner – Wünsche ersetzen (vor der Auslosung)
  if (act === "wishes" && arg && m === "PUT") {
    const who = await requireUser(env, req, pid);
    if (!await mayActFor(env, pid, who, arg)) fail(403, "Nicht erlaubt.");
    if (!["open", "closed"].includes(p.phase)) fail(409, "Nach der Auslosung kannst du nur noch Wünsche hinzufügen.");
    await writeWishes(env, pid, arg, cleanWishes(body.wishes));
    return json({ ok: true });
  }
  // POST /api/p/:pid/wishes/:owner – Wünsche hinzufügen (nach der Auslosung)
  if (act === "wishes" && arg && m === "POST") {
    const who = await requireUser(env, req, pid);
    if (!await mayActFor(env, pid, who, arg)) fail(403, "Nicht erlaubt.");
    if (p.phase !== "drawn") fail(409, "Gerade nicht möglich.");
    const list = cleanWishes(body.wishes);
    const cnt = (await env.DB.prepare("SELECT COUNT(*) AS c FROM wishes WHERE pid = ? AND owner = ?").bind(pid, arg).first()).c;
    if (cnt + list.length > 20) fail(400, "Höchstens 20 Wünsche.");
    await env.DB.batch(list.map((w, i) => env.DB.prepare("INSERT INTO wishes(id, pid, owner, n, text, link, res, created_at) VALUES(?,?,?,?,?,?,NULL,?)").bind(rid(), pid, arg, cnt + i + 1, w.text, w.link, Date.now())));
    return json({ ok: true });
  }
  // POST /api/p/:pid/reserve – Wunsch reservieren / freigeben
  if (act === "reserve" && m === "POST") {
    await requireUser(env, req, pid);
    if (p.phase !== "drawn") fail(409, "Reservieren geht nur nach der Auslosung.");
    const tag = str(body.tag, 40, "Kennung");
    const w = await env.DB.prepare("SELECT res FROM wishes WHERE id = ? AND pid = ?").bind(body.wishId, pid).first();
    if (!w) fail(404, "Diesen Wunsch gibt es nicht mehr.");
    if (body.on) {
      if (w.res && w.res !== tag) fail(409, "Diesen Wunsch hat schon jemand reserviert.");
      await env.DB.prepare("UPDATE wishes SET res = ? WHERE id = ? AND (res IS NULL OR res = ?)").bind(tag, body.wishId, tag).run();
    } else if (w.res === tag) {
      await env.DB.prepare("UPDATE wishes SET res = NULL WHERE id = ?").bind(body.wishId).run();
    }
    return json({ ok: true });
  }
  // DELETE /api/p/:pid/participants/:id – Person entfernen (Admin, vor der Auslosung)
  if (act === "participants" && arg && m === "DELETE") {
    await requireAdmin(env, req, pid);
    if (!["open", "closed"].includes(p.phase)) fail(409, "Nach der Auslosung nicht mehr möglich. Setze zuerst die Auslosung zurück.");
    const ids = [arg, ...(await parts(env, pid)).filter(x => x.managed_by === arg).map(x => x.id)];
    const st = [];
    for (const id of ids) {
      st.push(env.DB.prepare("DELETE FROM wishes WHERE pid = ? AND owner = ?").bind(pid, id));
      st.push(env.DB.prepare("DELETE FROM participants WHERE id = ? AND pid = ?").bind(id, pid));
      st.push(env.DB.prepare("DELETE FROM sessions WHERE pid = ? AND who = ?").bind(pid, id));
    }
    if (p.gifts) { p.gifts = 0; st.push(env.DB.prepare("UPDATE projects SET data = ? WHERE id = ?").bind(JSON.stringify((({ id, adminHash, ...d }) => d)(p)), pid)); }
    await env.DB.batch(st);
    return json({ ok: true });
  }
  // POST /api/p/:pid/draw – Auslosung speichern (Admin). Die Einteilung kommt verschlüsselt pro Person.
  if (act === "draw" && m === "POST") {
    await requireAdmin(env, req, pid);
    if (p.phase !== "closed" || !p.gifts) fail(409, "Bitte zuerst die Anmeldung schliessen und die Anzahl Geschenke festlegen.");
    const ids = (await parts(env, pid)).map(x => x.id);
    const assign = body.assign || {};
    if (Object.keys(assign).length !== ids.length || !ids.every(id => sealedOk(assign[id])) || !sealedOk(body.reveal)) fail(400, "Die Auslosung ist unvollständig. Bitte nochmal versuchen.");
    p.phase = "drawn"; p.drawnAt = Date.now(); p.softOk = body.softOk !== false;
    const { id: _i, adminHash: _a, ...data } = p;
    await env.DB.batch([
      env.DB.prepare("DELETE FROM assign WHERE pid = ?").bind(pid),
      ...ids.map(id => env.DB.prepare("INSERT INTO assign(pid, uid, sealed) VALUES(?,?,?)").bind(pid, id, JSON.stringify(assign[id]))),
      env.DB.prepare("INSERT OR REPLACE INTO meta(pid, reveal, result) VALUES(?,?,NULL)").bind(pid, JSON.stringify(body.reveal)),
      env.DB.prepare("UPDATE wishes SET res = NULL WHERE pid = ?").bind(pid),
      env.DB.prepare("UPDATE projects SET data = ? WHERE id = ?").bind(JSON.stringify(data), pid),
    ]);
    return json({ ok: true });
  }
  // POST /api/p/:pid/undo-draw (Admin)
  if (act === "undo-draw" && m === "POST") {
    await requireAdmin(env, req, pid);
    if (p.phase !== "drawn") fail(409, "Gerade nicht möglich.");
    p.phase = "closed"; delete p.drawnAt;
    const { id: _i, adminHash: _a, ...data } = p;
    await env.DB.batch([
      env.DB.prepare("DELETE FROM assign WHERE pid = ?").bind(pid),
      env.DB.prepare("DELETE FROM meta WHERE pid = ?").bind(pid),
      env.DB.prepare("UPDATE wishes SET res = NULL WHERE pid = ?").bind(pid),
      env.DB.prepare("UPDATE projects SET data = ? WHERE id = ?").bind(JSON.stringify(data), pid),
    ]);
    return json({ ok: true });
  }
  // GET /api/p/:pid/reveal-data – verschlüsselte Gesamtliste für den Admin (nur zum Auflösen)
  if (act === "reveal-data" && m === "GET") {
    await requireAdmin(env, req, pid);
    if (p.phase !== "drawn") fail(409, "Gerade nicht möglich.");
    const r = await env.DB.prepare("SELECT reveal FROM meta WHERE pid = ?").bind(pid).first();
    if (!r || !r.reveal) fail(404, "Keine Auslosung gefunden.");
    return json({ sealed: JSON.parse(r.reveal) });
  }
  // POST /api/p/:pid/reveal – Auflösung veröffentlichen (Admin)
  if (act === "reveal" && m === "POST") {
    await requireAdmin(env, req, pid);
    if (p.phase !== "drawn") fail(409, "Gerade nicht möglich.");
    const ps = await parts(env, pid);
    const ids = new Set(ps.map(x => x.id));
    const pairs = Array.isArray(body.pairs) ? body.pairs : [];
    if (pairs.length !== ps.length * p.gifts || !pairs.every(x => ids.has(x.from) && ids.has(x.to))) fail(400, "Die Auflösung passt nicht zur Auslosung.");
    const nameOf = id => ps.find(x => x.id === id).name;
    const result = { at: Date.now(), pairs: pairs.map(x => ({ from: x.from, to: x.to, fromName: nameOf(x.from), toName: nameOf(x.to) })) };
    p.phase = "revealed"; p.revealedAt = Date.now();
    const { id: _i, adminHash: _a, ...data } = p;
    await env.DB.batch([
      env.DB.prepare("UPDATE meta SET result = ? WHERE pid = ?").bind(JSON.stringify(result), pid),
      env.DB.prepare("UPDATE projects SET data = ? WHERE id = ?").bind(JSON.stringify(data), pid),
    ]);
    return json({ ok: true });
  }
  // POST /api/p/:pid/next-year – neues Wichteljahr mit gleichen Einstellungen (Admin)
  if (act === "next-year" && m === "POST") {
    await requireAdmin(env, req, pid);
    if (p.phase !== "archived") fail(409, "Bitte das Wichteln zuerst archivieren.");
    const year = p.year + 1;
    const all = (await env.DB.prepare("SELECT data FROM projects").all()).results.map(r => JSON.parse(r.data));
    if (all.some(x => x.familyKey === p.familyKey && x.year === year)) fail(409, `Das Wichteln ${year} gibt es schon.`);
    const id = rid();
    const data = { family: p.family, familyKey: p.familyKey, year, deadline: `${year}-12-01`, budgetMin: p.budgetMin, budgetMax: p.budgetMax,
      rules: p.rules, phase: "open", gifts: 0, admin: p.admin, createdAt: Date.now() };
    await env.DB.prepare("INSERT INTO projects(id, data, admin_hash, created_at) VALUES(?,?,?,?)").bind(id, JSON.stringify(data), p.adminHash, Date.now()).run();
    return json({ id, adminToken: await newSession(env, id, "admin") });
  }
  fail(404, "Nicht gefunden.");
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS ? env.ASSETS.fetch(req) : new Response("Not found", { status: 404 });
    try {
      return await handle(req, env, url);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: "Serverfehler. Bitte nochmal versuchen." }, 500);
    }
  },
};
