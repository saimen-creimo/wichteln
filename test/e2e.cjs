const { chromium } = require("playwright");
const BASE = "http://localhost:8787/";
(async () => {
  const browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await ctx.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  page.on("console", m => { if (m.type() === "error" && !/fonts|TUNNEL/.test(m.text())) errors.push(m.text()); });
  await page.goto(BASE); await page.waitForSelector("text=Frohes Wichteln");
  await page.click("text=+ Neues Wichtelprojekt");
  await page.fill("#cf", "Muster"); await page.fill("#cp1", "9999"); await page.fill("#cp2", "9999");
  await page.click("text=Projekt anlegen");
  await page.waitForSelector("text=Anmeldung schliessen");
  const pid = await page.evaluate(() => S.pid);
  const people = [["Anna","1111"],["Beat","2222"],["Claudia","3333"],["Daniel","4444"]];
  // Jede Person in eigenem Browser-Kontext (wie eigenes Handy)
  for (const [n, pin] of people) {
    const c = await browser.newContext({ viewport: { width: 390, height: 844 } }); const pg = await c.newPage();
    await pg.goto(BASE + "#p-" + pid); await pg.click("text=Ich mache mit");
    await pg.fill("#jn", n); await pg.fill("#jp1", pin); await pg.fill("#jp2", pin);
    const wt = await pg.$$("#wl .wt"); await wt[0].fill(n + "s Wunsch A"); await wt[1].fill(n + "s Wunsch B"); await wt[2].fill(n + "s Wunsch C");
    await pg.click("#jb"); await pg.waitForSelector("text=Hallo " + n);
    if (n === "Anna") {
      await pg.click("text=Person ohne Handy eintragen");
      await pg.fill("#mn", "Lina"); await pg.fill("#mp", "1111");
      const w2 = await pg.$$("#wl .wt"); await w2[0].fill("Lego"); await w2[1].fill("Buch");
      await pg.click("#sheet button.btn.block"); await pg.waitForSelector("text=Lina ist dabei");
    }
    await c.close();
  }
  // Falsche PIN-Sperre
  const c2 = await browser.newContext(); const pg2 = await c2.newPage();
  await pg2.goto(BASE + "#p-" + pid); await pg2.click(".tabs >> text=Mein Wichteln"); await pg2.click("text=Mit PIN anmelden");
  await pg2.selectOption("#ln", { label: "Beat" });
  for (let i = 0; i < 6; i++) { await pg2.fill("#lp", "000" + i); await pg2.click("#lb"); await pg2.waitForTimeout(250); }
  console.log("Sperre:", await pg2.textContent("#le"));
  await c2.close();
  // Admin (Ersteller ist noch entsperrt)
  await page.waitForTimeout(500); await page.evaluate(() => refreshProject());
  await page.waitForSelector("text=5 Personen");
  await page.click("text=Anmeldung schliessen"); await page.click("#cOk");
  await page.waitForSelector("text=höchstens");
  await page.selectOption("#nSel", "2"); await page.click("button:has-text('Speichern')");
  await page.waitForSelector("text=Festgelegt: 2");
  await page.click("text=Jetzt auslosen"); await page.click("#cOk");
  await page.waitForSelector("text=Auflösung veröffentlichen");
  // Admin-API darf Einteilung nicht im Klartext liefern; fremde Einteilung ohne Login nicht abrufbar
  const st = await page.evaluate(async pid => (await fetch(`/api/p/${pid}/assign`)).status, pid);
  console.log("Einteilung ohne Login:", st);
  const all = [];
  for (const [n, pin] of people) {
    const c = await browser.newContext({ viewport: { width: 390, height: 844 } }); const pg = await c.newPage();
    await pg.goto(BASE + "#p-" + pid); await pg.click(".tabs >> text=Mein Wichteln"); await pg.click("text=Mit PIN anmelden");
    await pg.selectOption("#ln", { label: n }); await pg.fill("#lp", pin); await pg.click("#lb");
    if (n === "Beat") { await pg.waitForTimeout(400); const t = await pg.textContent("#le").catch(()=>""); if (t) { console.log("Beat gesperrt (erwartet):", t); await c.close(); continue; } }
    await pg.waitForFunction(() => S.session && Object.keys(S.session.pay).length === Object.keys(S.session.keys).length);
    all.push(...await pg.evaluate(() => Object.entries(S.session.pay).flatMap(([id, p]) => p.gives.map(g => [partName(id), partName(g.to)]))));
    if (n === "Daniel") {
      await pg.click("button:has-text('Reservieren')"); await pg.waitForSelector("text=✓ Reserviert");
      await pg.screenshot({ path: "test/shot_mine.png", fullPage: true });
    }
    await c.close();
  }
  console.log("Einteilungen gesehen:", all.length, JSON.stringify(all));
  const bad = all.filter(x => x[0] === x[1] || (x[0]==="Anna"&&x[1]==="Lina") || (x[0]==="Lina"&&x[1]==="Anna"));
  console.log("Regelverstösse:", bad.length);
  await page.click("text=Auflösung veröffentlichen"); await page.click("#cOk");
  await page.waitForSelector("text=Wer hat wen beschenkt?");
  const pairs = await page.evaluate(() => S.result.pairs.map(x => [x.fromName, x.toName]));
  const out = {}, inn = {}; pairs.forEach(([a, b]) => { out[a] = (out[a]||0)+1; inn[b] = (inn[b]||0)+1; });
  console.log("Auflösung:", pairs.length, "regulär:", Object.values(out).every(v=>v===2) && Object.values(inn).every(v=>v===2), "passt zu Einteilung:", all.every(x => pairs.some(y => y[0]===x[0] && y[1]===x[1])));
  await page.screenshot({ path: "test/shot_result.png", fullPage: true });
  await page.click(".tabs >> text=Admin"); await page.click("text=Im Archiv speichern");
  await page.click("text=Neues Wichteljahr"); await page.click("#cOk");
  await page.waitForSelector("text=Wichteln 2027"); await page.waitForSelector("text=Anmeldung schliessen");
  await page.click("text=‹ Alle Projekte"); await page.waitForSelector("text=Archiv");
  await page.screenshot({ path: "test/shot_home.png", fullPage: true });
  console.log("Fehler:", errors.length ? errors : "keine");
  await browser.close();
})().catch(e => { console.error("TEST ABBRUCH", e.message); process.exit(1); });
