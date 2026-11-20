// Lokaler Testserver: emuliert Cloudflare (D1 via node:sqlite, statische Dateien aus public/)
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import worker from "../src/worker.js";

const db = new DatabaseSync(":memory:");
class Stmt {
  constructor(sql) { this.sql = sql; this.args = []; }
  bind(...a) { this.args = a; return this; }
  async first() { return db.prepare(this.sql).get(...this.args) ?? null; }
  async all() { return { results: db.prepare(this.sql).all(...this.args) }; }
  async run() { db.prepare(this.sql).run(...this.args); return { success: true }; }
}
const D1 = {
  prepare: sql => new Stmt(sql),
  batch: async stmts => { db.exec("BEGIN"); try { const out = stmts.map(s => db.prepare(s.sql).run(...s.args)); db.exec("COMMIT"); return out; } catch (e) { db.exec("ROLLBACK"); throw e; } },
};
const root = path.resolve("public");
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };
http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (!url.pathname.startsWith("/api/")) {
    const f = path.join(root, url.pathname === "/" ? "index.html" : url.pathname);
    if (f.startsWith(root) && fs.existsSync(f)) { res.writeHead(200, { "content-type": types[path.extname(f)] || "text/plain" }); return res.end(fs.readFileSync(f)); }
    res.writeHead(404); return res.end();
  }
  const chunks = []; for await (const c of req) chunks.push(c);
  const r = await worker.fetch(new Request(url, { method: req.method, headers: req.headers, body: ["GET", "HEAD", "DELETE"].includes(req.method) ? undefined : Buffer.concat(chunks) }), { DB: D1 });
  res.writeHead(r.status, Object.fromEntries(r.headers)); res.end(Buffer.from(await r.arrayBuffer()));
}).listen(8787, () => console.log("ready"));
