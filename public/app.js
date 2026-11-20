// Wichteln – Frontend
// ================= Hilfen =================
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const rid = (n=10) => { const a="abcdefghijkmnopqrstuvwxyz23456789"; const u=crypto.getRandomValues(new Uint8Array(n)); return [...u].map(x=>a[x%a.length]).join(""); };
const PHASES = ["open","closed","drawn","revealed","archived"];
const PHASE_LABEL = {open:"Anmeldung offen",closed:"Anmeldung geschlossen",drawn:"Ausgelost",revealed:"Aufgelöst",archived:"Archiviert"};
const COLORS = ["#1F4D3A","#B3362C","#C49A2C","#3F6E8C","#7A4E8A","#2E6B52","#A3583A","#5B6B2E"];
const colorFor = id => COLORS[[...String(id)].reduce((a,c)=>a+c.charCodeAt(0),0)%COLORS.length];
const initials = n => String(n).trim().split(/\s+/).map(w=>w[0]).slice(0,2).join("").toUpperCase();
const fmtDate = d => { if(!d) return ""; const [y,m,dd]=d.split("-"); return `${+dd}.${+m}.${y}`; };
const famKey = s => s.trim().toLowerCase().replace(/\s+/g," ");
let toastT;
function toast(msg){ const t=$("#toast"); t.textContent=msg; t.classList.add("on"); clearTimeout(toastT); toastT=setTimeout(()=>t.classList.remove("on"),3000); }
function openSheet(html){ $("#sheet").innerHTML=html; $("#ov").classList.add("on"); const f=$("#sheet input, #sheet textarea"); if(f) setTimeout(()=>f.focus(),50); }
function closeSheet(){ $("#ov").classList.remove("on"); $("#sheet").innerHTML=""; }
function confirmSheet(title, text, okLabel, danger){
  return new Promise(res=>{
    openSheet(`<div class="hd"><h2 class="grow">${esc(title)}</h2></div><p class="muted">${text}</p>
      <div class="row" style="margin-top:18px"><button class="btn sec grow" id="cNo">Abbrechen</button><button class="btn ${danger?"red":""} grow" id="cOk">${esc(okLabel)}</button></div>`);
    $("#cNo").onclick=()=>{closeSheet();res(false)}; $("#cOk").onclick=()=>{closeSheet();res(true)};
  });
}
async function busy(btn, fn){ const old=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span class="spin"></span>'; try{ return await fn(); } finally { if(btn.isConnected){btn.disabled=false; btn.innerHTML=old;} } }
const errText = e => (e && e.message) || "Etwas ist schiefgelaufen. Bitte nochmal versuchen.";

// ================= Server =================
async function api(method, path, body){
  const headers = {"content-type":"application/json"};
  if(S.session && S.session.pid===S.pid) headers["x-session"]=S.session.token;
  if(S.admin && S.admin.pid===S.pid) headers["x-admin"]=S.admin.token;
  let r;
  try{ r = await fetch("/api/"+path, {method, headers, body: body?JSON.stringify(body):undefined}); }
  catch(e){ throw new Error("Keine Verbindung. Bist du online?"); }
  let data={}; try{ data = await r.json(); }catch(e){}
  if(!r.ok){
    if(r.status===401 && headers["x-admin"] && /Admin/.test(data.error||"")) { S.admin=null; render(); }
    else if(r.status===401 && headers["x-session"] && /anmelden/.test(data.error||"")) { S.session=null; render(); }
    const err = new Error(data.error || "Fehler "+r.status); err.status=r.status; throw err;
  }
  return data;
}

// ================= Krypto (Einteilung nur mit eigener PIN lesbar) =================
const te=new TextEncoder(), td=new TextDecoder();
const b64 = buf => { const b=new Uint8Array(buf); let s=""; for(let i=0;i<b.length;i+=0x8000) s+=String.fromCharCode.apply(null,b.subarray(i,i+0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
async function pinKey(pin, salt){
  const base = await crypto.subtle.importKey("raw", te.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt:unb64(salt), iterations:150000, hash:"SHA-256"}, base, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
async function newIdentity(pin){
  const kp = await crypto.subtle.generateKey({name:"RSA-OAEP", modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256"}, true, ["encrypt","decrypt"]);
  const pub = b64(await crypto.subtle.exportKey("spki", kp.publicKey));
  const pk = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, await pinKey(pin, salt), pk);
  return { pub, priv:{ salt, iv:b64(iv), ct:b64(ct) } };
}
async function unlock(pin, priv){
  const pk = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(priv.iv)}, await pinKey(pin, priv.salt), unb64(priv.ct));
  return crypto.subtle.importKey("pkcs8", pk, {name:"RSA-OAEP", hash:"SHA-256"}, false, ["decrypt"]);
}
async function seal(pubB64, obj){
  const pub = await crypto.subtle.importKey("spki", unb64(pubB64), {name:"RSA-OAEP", hash:"SHA-256"}, false, ["encrypt"]);
  const k = await crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, k, te.encode(JSON.stringify(obj)));
  const wk = await crypto.subtle.encrypt({name:"RSA-OAEP"}, pub, await crypto.subtle.exportKey("raw", k));
  return { k:b64(wk), iv:b64(iv), ct:b64(ct) };
}
async function unseal(key, s){
  const raw = await crypto.subtle.decrypt({name:"RSA-OAEP"}, key, unb64(s.k));
  const k = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  return JSON.parse(td.decode(await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(s.iv)}, k, unb64(s.ct))));
}
async function tagFor(secret, wishId){
  const h = await crypto.subtle.digest("SHA-256", te.encode(secret+":"+wishId));
  return [...new Uint8Array(h)].slice(0,10).map(b=>b.toString(16).padStart(2,"0")).join("");
}
const pinOk = p => /^\d{4}$/.test(p);

// ================= Zustand =================
const S = { projects:[], projLoaded:false, listErr:false, pid:null, proj:null, parts:[], wishes:[], result:null, missing:false,
  tab:"wishes", session:null, admin:null, nSel:null, maxN:null, lastProjJson:"", lastListJson:"" };
// session: {pid, me, token, privs:{id:priv}, keys:{id:CryptoKey}, pay:{id:payload}, tags:{id:Set}}
// admin:   {pid, token, key}
const P = () => S.proj;
const partName = id => S.parts.find(p=>p.id===id)?.name || "?";
const wishesOf = id => S.wishes.filter(w=>w.owner===id).sort((a,b)=>(a.n||0)-(b.n||0));

async function refreshList(){
  try{
    const d = await api("GET","projects");
    S.listErr=false;
    const j = JSON.stringify(d.projects);
    S.projects = d.projects; S.projLoaded = true;
    if(j!==S.lastListJson){ S.lastListJson=j; if(!S.pid) render(); }
  }catch(e){ if(!S.projLoaded){ S.listErr=true; render(); } }
}
async function refreshProject(){
  const pid=S.pid; if(!pid) return;
  try{
    const d = await api("GET","p/"+pid);
    if(pid!==S.pid) return;
    S.missing=false;
    const j = JSON.stringify(d);
    if(j===S.lastProjJson) return;
    S.lastProjJson=j;
    const oldPhase = S.proj?.phase, oldCount = S.parts.length;
    S.proj=d.project; S.parts=d.participants; S.wishes=d.wishes; S.result=d.result;
    if(oldCount!==S.parts.length || oldPhase!==S.proj.phase) S.maxN=null;
    render();
    if(S.session && oldPhase!==S.proj.phase) loadAssignments(); else refreshTags();
  }catch(e){ if(e.status===404){ S.missing=true; render(); } }
}
const refresh = () => S.pid ? refreshProject() : refreshList();

// ================= Start / Routing =================
window.addEventListener("hashchange", route);
setInterval(()=>{ if(document.visibilityState==="visible") refresh(); }, 6000);
document.addEventListener("visibilitychange", ()=>{ if(document.visibilityState==="visible") refresh(); });
refreshList(); route();

function go(h){ if(h) location.hash=h; else history.replaceState(null,"",location.pathname); route(); }
function route(){
  const h = location.hash.replace("#","");
  const pid = h.startsWith("p-") ? h.slice(2) : null;
  if(pid !== S.pid){
    S.pid=pid; S.proj=null; S.parts=[]; S.wishes=[]; S.result=null; S.missing=false; S.tab="wishes"; S.nSel=null; S.maxN=null; S.lastProjJson="";
    if(S.session && S.session.pid!==pid) S.session=null;
    if(S.admin && S.admin.pid!==pid) S.admin=null;
    if(pid) refreshProject(); else refreshList();
  }
  render();
}

// ================= Render =================
function render(){
  const m = $("#main");
  if(!S.pid){
    if(S.listErr){ m.innerHTML = `<div class="card"><h2>Keine Verbindung</h2><p class="muted">Der Server ist gerade nicht erreichbar. Bitte versuche es gleich nochmal.</p></div>`; return; }
    if(!S.projLoaded){ m.innerHTML = `<div class="empty"><span class="spin"></span></div>`; return; }
    return renderHome(m);
  }
  if(S.missing){ m.innerHTML = `<div class="card empty">Dieses Wichtelprojekt gibt es nicht (mehr).<br><br><button class="btn sec" onclick="go('')">Zur Übersicht</button></div>`; return; }
  if(!S.proj){ m.innerHTML = `<div class="empty"><span class="spin"></span></div>`; return; }
  renderProject(m);
}

function starPath(cx,cy,r){ let d=""; for(let i=0;i<10;i++){ const a=Math.PI/5*i-Math.PI/2, rr=i%2?r*.42:r; d+=(i?"L":"M")+(cx+rr*Math.cos(a)).toFixed(1)+" "+(cy+rr*Math.sin(a)).toFixed(1); } return `<path d="${d}Z"/>`; }

function renderHome(m){
  const active = S.projects.filter(p=>p.phase!=="archived").sort((a,b)=>(b.year-a.year)||a.family.localeCompare(b.family));
  const arch = S.projects.filter(p=>p.phase==="archived").sort((a,b)=>(b.year-a.year));
  const card = p => `<div class="card proj" onclick="go('p-${p.id}')">
      <div class="yr">${esc(p.year)}</div>
      <div class="grow"><h3>Familie ${esc(p.family)}</h3><div class="small muted">${p.deadline && p.phase==="open" ? "Anmeldung bis "+fmtDate(p.deadline) : p.count+" Teilnehmer"}</div></div>
      <span class="badge ${p.phase==="open"?"":p.phase==="drawn"?"red":p.phase==="revealed"?"gold":"grey"}">${PHASE_LABEL[p.phase]}</span></div>`;
  m.innerHTML = `
    <div class="card hero">
      <svg class="stars" width="170" height="170" viewBox="0 0 100 100" fill="#fff">${starPath(70,28,16)}${starPath(30,70,10)}${starPath(85,75,7)}</svg>
      <h1>Frohes Wichteln</h1>
      <p class="muted" style="margin:6px 0 16px">Familie anlegen, Wünsche sammeln, auslosen. Jeder sieht nur, wen er selbst beschenkt.</p>
      <button class="btn" style="background:#fff;color:var(--green)" onclick="sheetCreate()">+ Neues Wichtelprojekt</button>
    </div>
    ${active.length ? `<div class="sec-title"><h3>Aktuell</h3></div>${active.map(card).join("")}` : `<div class="card empty">Noch kein Wichtelprojekt. Lege das erste an.</div>`}
    ${arch.length ? `<div class="sec-title"><h3>Archiv</h3></div>${arch.map(card).join("")}` : ""}`;
}

function renderProject(m){
  const p = P(), ph = PHASES.indexOf(p.phase);
  const tabs = [];
  if(p.phase==="revealed"||p.phase==="archived") tabs.push(["result","Auflösung"]);
  tabs.push(["wishes","Wünsche"],["mine","Mein Wichteln"],["admin","Admin"]);
  if(!tabs.find(t=>t[0]===S.tab)) S.tab=tabs[0][0];
  const budget = (p.budgetMin||p.budgetMax) ? `${p.budgetMin||0}–${p.budgetMax||"?"} CHF` : "";
  m.innerHTML = `
    <button class="btn ghost sm" onclick="go('')" style="margin:-6px 0 6px -8px">‹ Alle Projekte</button>
    <div class="card hero">
      <svg class="stars" width="150" height="150" viewBox="0 0 100 100" fill="#fff">${starPath(72,30,15)}${starPath(36,72,9)}</svg>
      <div class="small muted">Wichteln ${esc(p.year)}</div>
      <h1>Familie ${esc(p.family)}</h1>
      <div class="rules">
        ${budget?`<span class="chip">🎁 ${esc(budget)} pro Geschenk</span>`:""}
        ${p.gifts?`<span class="chip">${p.gifts} ${p.gifts>1?"Geschenke":"Geschenk"} pro Person</span>`:""}
        <span class="chip">${S.parts.length} Teilnehmer</span>
        ${p.deadline&&p.phase==="open"?`<span class="chip">Anmeldung bis ${fmtDate(p.deadline)}</span>`:""}
      </div>
      ${p.rules?`<p style="margin:12px 0 0;font-size:14px;white-space:pre-wrap">${esc(p.rules)}</p>`:""}
      <div class="steps">${PHASES.map((x,i)=>`<div class="${i<=ph?"on":""}"></div>`).join("")}</div>
      <div class="steplabel">${PHASE_LABEL[p.phase]}</div>
    </div>
    <div class="tabs">${tabs.map(([k,l])=>`<button class="${S.tab===k?"on":""}" onclick="S.tab='${k}';render()">${l}</button>`).join("")}</div>
    <div id="tab"></div>`;
  const t = $("#tab");
  if(S.tab==="wishes") renderWishes(t);
  else if(S.tab==="mine") renderMine(t);
  else if(S.tab==="admin") renderAdmin(t);
  else renderResult(t);
}
function safeUrl(u){ u=String(u).trim(); if(!/^https?:\/\//i.test(u)) u="https://"+u; return u; }

// ---------- Wünsche (alle) ----------
function renderWishes(t){
  const p=P(), ses=S.session;
  const mine = ses ? Object.keys(ses.keys) : [];
  const allTags = ses ? Object.values(ses.tags||{}).reduce((s,x)=>{x.forEach(v=>s.add(v));return s;}, new Set()) : new Set();
  let html = "";
  if(p.phase==="open") html += `<button class="btn block" style="margin-bottom:14px" onclick="sheetJoin()">Ich mache mit</button>`;
  if(!S.parts.length) html += `<div class="card empty">Noch niemand angemeldet.</div>`;
  if(ses && p.phase==="drawn") html += `<div class="notice green small">Reservierte Wünsche sind durchgestrichen. Bei deinen eigenen Wünschen siehst du das nicht.</div>`;
  for(const pa of S.parts){
    const ws = wishesOf(pa.id), own = mine.includes(pa.id);
    html += `<div class="card"><div class="person"><div class="av" style="background:${colorFor(pa.id)}">${esc(initials(pa.name))}</div>
      <div class="grow"><h3>${esc(pa.name)}</h3>${pa.managedBy?`<div class="small muted">eingetragen von ${esc(partName(pa.managedBy))}</div>`:""}</div>
      <span class="badge grey">${ws.length} ${ws.length===1?"Wunsch":"Wünsche"}</span></div>
      ${ws.length? ws.map(w=>{
        const showRes = ses && !own && w.res && p.phase==="drawn";
        const isMine = showRes && allTags.has(w.res);
        return `<div class="wish ${showRes?"res":""}"><div class="n">${w.n}</div><div class="grow"><div class="txt">${esc(w.text)}</div>
          ${w.link?`<a class="small" href="${esc(safeUrl(w.link))}" target="_blank" rel="noopener">Link öffnen ↗</a>`:""}</div>
          ${showRes?`<span class="badge ${isMine?"":"grey"}">${isMine?"von dir reserviert":"reserviert"}</span>`:""}</div>`;
      }).join("") : `<div class="small muted">Noch keine Wünsche.</div>`}
    </div>`;
  }
  if(!ses && p.phase==="drawn" && S.parts.length) html += `<p class="small muted" style="text-align:center">Melde dich unter „Mein Wichteln“ an, um zu sehen, welche Wünsche schon reserviert sind.</p>`;
  t.innerHTML = html;
}

// ---------- Mein Wichteln ----------
function renderMine(t){
  const p=P(), ses=S.session;
  if(!ses){
    const own = S.parts.filter(x=>!x.managedBy);
    t.innerHTML = `<div class="card"><h2>Anmelden</h2><p class="muted small" style="margin:4px 0 12px">Wähle deinen Namen und gib deine PIN ein. Danach siehst du, wen du beschenkst.</p>
      ${own.length?`<button class="btn block" onclick="sheetLogin()">Mit PIN anmelden</button>`:`<div class="muted">Es hat sich noch niemand angemeldet.</div>`}
      ${p.phase==="open"?`<div class="hr"></div><button class="btn sec block" onclick="sheetJoin()">Neu mitmachen</button>`:""}</div>`;
    return;
  }
  const me = S.parts.find(x=>x.id===ses.me);
  if(!me){ S.session=null; return renderMine(t); }
  const people = [me, ...S.parts.filter(x=>x.managedBy===me.id)];
  let html = `<div class="row" style="margin-bottom:12px"><div class="grow"><h2>Hallo ${esc(me.name)}</h2></div><button class="btn ghost sm" onclick="logout()">Abmelden</button></div>`;
  if(p.phase==="open"||p.phase==="closed"){
    html += `<div class="notice">Die Auslosung hat noch nicht stattgefunden. ${p.gifts?`Es gibt <b>${p.gifts} ${p.gifts>1?"Geschenke":"Geschenk"} pro Person</b>, bitte erfasse mindestens so viele Wünsche.`:"Du kannst deine Wünsche bis zur Auslosung bearbeiten."}</div>`;
  }
  for(const pe of people){
    const who = pe.id===me.id ? "Du beschenkst" : esc(pe.name)+" beschenkt";
    html += `<div class="card"><div class="person"><div class="av" style="background:${colorFor(pe.id)}">${esc(initials(pe.name))}</div><div class="grow"><h3>${pe.id===me.id?"Dein Bereich":esc(pe.name)}</h3></div></div>`;
    const pay = ses.pay[pe.id];
    if(["drawn","revealed","archived"].includes(p.phase)){
      if(!pay) html += `<div class="muted small">Die Einteilung wird geladen …</div>`;
      else {
        html += `<div class="small muted" style="margin-bottom:4px">${who}:</div>`;
        for(const g of pay.gives){
          const ws = wishesOf(g.to);
          html += `<div style="border:1px solid var(--line);border-radius:14px;padding:12px 14px;margin:10px 0">
            <div class="person" style="margin:0 0 6px"><div class="av" style="background:${colorFor(g.to)}">${esc(initials(partName(g.to)))}</div><div class="grow"><h3>${esc(partName(g.to))}</h3></div></div>
            ${ws.length? ws.map(w=>wishWithReserve(w, pe.id)).join("") : `<div class="small muted">Keine Wünsche erfasst. Ein freies Geschenk ist natürlich immer erlaubt.</div>`}
          </div>`;
        }
        if(p.phase==="drawn") html += `<div class="small muted">Du kannst einen Wunsch erfüllen oder ein freies Geschenk bringen.</div>`;
      }
    }
    const ws = wishesOf(pe.id);
    html += `<div class="hr"></div><div class="row"><div class="grow"><b>${pe.id===me.id?"Meine Wünsche":"Wünsche von "+esc(pe.name)}</b></div>
      ${(p.phase==="open"||p.phase==="closed")?`<button class="btn sec sm" onclick="sheetWishes('${pe.id}')">Bearbeiten</button>`:p.phase==="drawn"?`<button class="btn sec sm" onclick="sheetWishes('${pe.id}',true)">+ Wunsch</button>`:""}</div>
      ${ws.length?ws.map(w=>`<div class="wish"><div class="n">${w.n}</div><div class="grow txt">${esc(w.text)}${w.link?` · <a class="small" href="${esc(safeUrl(w.link))}" target="_blank" rel="noopener">Link</a>`:""}</div></div>`).join(""):`<div class="small muted" style="margin-top:6px">Noch keine Wünsche.</div>`}
    </div>`;
  }
  if(p.phase==="open") html += `<button class="btn sec block" onclick="sheetAddManaged()">+ Person ohne Handy eintragen (z. B. Kind)</button>`;
  t.innerHTML = html;
}
function wishWithReserve(w, giverId){
  const ses=S.session, tags=ses.tags[giverId]||new Set(), p=P();
  const mineRes = w.res && tags.has(w.res), other = w.res && !mineRes;
  let btn="";
  if(p.phase==="drawn"){
    if(mineRes) btn=`<button class="btn sm" onclick="reserve(this,'${w.id}','${giverId}',false)">✓ Reserviert</button>`;
    else if(other) btn=`<span class="badge grey">schon reserviert</span>`;
    else btn=`<button class="btn sec sm" onclick="reserve(this,'${w.id}','${giverId}',true)">Reservieren</button>`;
  }
  return `<div class="wish ${other?"res":""}"><div class="n">${w.n}</div><div class="grow"><div class="txt">${esc(w.text)}</div>${w.link?`<a class="small" href="${esc(safeUrl(w.link))}" target="_blank" rel="noopener">Link öffnen ↗</a>`:""}</div>${btn}</div>`;
}

// ---------- Admin ----------
function renderAdmin(t){
  const p=P();
  if(!S.admin){
    t.innerHTML = `<div class="card"><h2>Admin</h2><p class="muted small" style="margin:4px 0 12px">Mit der Admin-PIN schliesst du die Anmeldung, startest die Auslosung und veröffentlichst die Auflösung. Die Einteilung siehst du dabei nicht.</p>
      <button class="btn block" onclick="sheetAdmin()">Mit Admin-PIN entsperren</button></div>`;
    return;
  }
  const n = S.parts.length;
  const rows = S.parts.map(x=>`<tr><td>${esc(x.name)}${x.managedBy?` <span class="small muted">(von ${esc(partName(x.managedBy))})</span>`:""}</td><td>${wishesOf(x.id).length}</td>
     <td style="text-align:right">${(p.phase==="open"||p.phase==="closed")?`<button class="btn ghost sm" onclick="removePart(this,'${x.id}')">Entfernen</button>`:""}</td></tr>`).join("");
  let action = "";
  if(p.phase==="open"){
    action = `<h3>1. Anmeldung</h3><p class="small muted">${n} Personen haben sich angemeldet${p.deadline?`, Anmeldeschluss ${fmtDate(p.deadline)}`:""}. Wenn alle dabei sind, schliesst du die Anmeldung.</p>
      <button class="btn block" onclick="setPhase(this,'closed')" ${n<2?"disabled":""}>Anmeldung schliessen</button>
      <p class="small muted" style="margin-top:12px">Link für die Familie: <b>${esc(location.origin+location.pathname+"#p-"+p.id)}</b> <button class="btn ghost sm" onclick="copyLink()">Kopieren</button></p>`;
  } else if(p.phase==="closed"){
    if(S.maxN===null) S.maxN = Draw.maxN(S.parts.map(x=>x.id), hardExclusions());
    const max = S.maxN;
    const sel = S.nSel || p.gifts || Math.min(max||1, 3);
    action = `<h3>2. Geschenke pro Person</h3>
      ${max===0?`<div class="notice red">Mit diesen Teilnehmern und Ausschlüssen ist keine Auslosung möglich.</div>`:`
      <p class="small muted">Bei ${n} Teilnehmern sind höchstens <b>${max}</b> Geschenke pro Person möglich. Jeder beschenkt so viele verschiedene Personen.</p>
      <div class="row"><select id="nSel" onchange="S.nSel=+this.value" class="grow">${Array.from({length:max},(_,i)=>i+1).map(i=>`<option value="${i}" ${i===sel?"selected":""}>${i} ${i>1?"Geschenke":"Geschenk"} pro Person</option>`).join("")}</select>
      <button class="btn sec" onclick="saveGifts(this)">Speichern</button></div>
      ${p.gifts?`<p class="small" style="margin-top:8px">✓ Festgelegt: ${p.gifts}. Die Teilnehmer sehen jetzt, wie viele Wünsche sie erfassen sollen.</p>`:""}
      <div class="hr"></div><h3>3. Auslosung</h3>
      <p class="small muted">Wer jemanden eingetragen hat, zieht diese Person nicht (und umgekehrt). Paarungen vom letzten Jahr werden möglichst vermieden.</p>
      <button class="btn block" onclick="doDraw(this)" ${p.gifts?"":"disabled"}>Jetzt auslosen</button>`}
      <button class="btn ghost sm" style="margin-top:10px" onclick="setPhase(this,'open')">Anmeldung wieder öffnen</button>`;
  } else if(p.phase==="drawn"){
    action = `<h3>4. Auflösung</h3><p class="small muted">Ausgelost am ${new Date(p.drawnAt).toLocaleDateString("de-CH")}. ${p.softOk===false?"Hinweis: Einige Paarungen vom Vorjahr liessen sich nicht vermeiden. ":""}Wenn alle beschenkt wurden, veröffentlichst du, wer wen beschenkt hat.</p>
      <button class="btn block" onclick="doReveal(this)">Auflösung veröffentlichen</button>
      <button class="btn ghost sm" style="margin-top:10px" onclick="undoDraw(this)">Auslosung zurücksetzen</button>`;
  } else if(p.phase==="revealed"){
    action = `<h3>5. Speichern</h3><p class="small muted">Die Auflösung ist für alle sichtbar. Speichere das Wichteln im Archiv. Danach kannst du ein neues Jahr starten.</p>
      <button class="btn block" onclick="setPhase(this,'archived')">Im Archiv speichern</button>`;
  } else {
    const next = S.projects.find(x=>x.familyKey===p.familyKey && x.year>p.year);
    action = `<h3>Archiviert</h3><p class="small muted">Dieses Wichteln ist gespeichert.</p>
      ${next?`<button class="btn sec block" onclick="go('p-${next.id}')">Zum Wichteln ${next.year}</button>`:`<button class="btn block" onclick="newYear(this)">Neues Wichteljahr ${p.year+1} starten</button>`}`;
  }
  t.innerHTML = `<div class="card">${action}</div>
    <div class="card"><div class="row"><h3 class="grow">Einstellungen</h3><button class="btn sec sm" onclick="sheetSettings()">Bearbeiten</button></div>
      <p class="small muted" style="margin:6px 0 0">Familie, Anmeldeschluss, Budget und Spielregeln.</p></div>
    <div class="card"><h3>Teilnehmer</h3><table><tr><th>Name</th><th>Wünsche</th><th></th></tr>${rows||`<tr><td colspan="3" class="muted">Noch niemand</td></tr>`}</table></div>
    ${p.phase==="open"&&!S.parts.length?`<button class="btn ghost sm" onclick="deleteProject(this)">Projekt löschen</button>`:""}
    <button class="btn ghost sm" onclick="S.admin=null;render()">Admin sperren</button>`;
}
async function copyLink(){ try{ await navigator.clipboard.writeText(location.origin+location.pathname+"#p-"+S.pid); toast("Link kopiert"); }catch(e){ toast("Kopieren nicht möglich – bitte von Hand markieren."); } }

// ---------- Auflösung ----------
function renderResult(t){
  if(!S.result){ t.innerHTML=`<div class="card empty"><span class="spin"></span></div>`; return; }
  const pairs = [...S.result.pairs].sort((a,b)=>a.toName.localeCompare(b.toName)||a.fromName.localeCompare(b.fromName));
  const byTo = {}; pairs.forEach(x=>(byTo[x.toName]=byTo[x.toName]||[]).push(x));
  t.innerHTML = `<div class="card"><h2>Wer hat wen beschenkt?</h2><p class="small muted" style="margin:4px 0 8px">Veröffentlicht am ${new Date(S.result.at).toLocaleDateString("de-CH")}</p>
    ${Object.entries(byTo).map(([to,xs])=>`<div class="hr"></div><div class="person" style="margin-bottom:6px"><div class="av" style="background:${colorFor(xs[0].to)}">${esc(initials(to))}</div><h3>${esc(to)}</h3></div>
      ${xs.map(x=>`<div class="row small" style="padding:4px 0 4px 46px"><span>🎁 von <b>${esc(x.fromName)}</b></span></div>`).join("")}`).join("")}
  </div>`;
}

// ================= Formulare =================
function wishRows(list){
  return list.map((w,i)=>`<div class="wrow" data-id="${w.id||""}"><div class="n" style="width:24px;color:var(--muted);font-weight:600">${i+1}</div>
    <div class="grow"><input class="wt" placeholder="Wunsch" value="${esc(w.text||"")}" maxlength="200"><input class="wl small" placeholder="Link (optional)" value="${esc(w.link||"")}" maxlength="500" style="margin-top:6px;padding:8px 12px;font-size:13px"></div>
    <button class="btn ghost sm" onclick="this.closest('.wrow').remove();renum()" title="Entfernen">✕</button></div>`).join("");
}
function renum(){ document.querySelectorAll("#wl .wrow").forEach((r,i)=>r.querySelector(".n").textContent=i+1); }
function addWishRow(){ const d=document.createElement("div"); d.innerHTML=wishRows([{}]); $("#wl").appendChild(d.firstElementChild); renum(); const ins=$("#wl").querySelectorAll(".wt"); ins[ins.length-1].focus(); }
function readWishRows(){ return [...document.querySelectorAll("#wl .wrow")].map(r=>({id:r.dataset.id||null, text:r.querySelector(".wt").value.trim(), link:r.querySelector(".wl").value.trim()})).filter(w=>w.text); }
function wishHint(){ const g=P()?.gifts; return g?`Bitte mindestens ${g} Wünsche erfassen.`:"Die Anzahl Geschenke wird nach der Anmeldung festgelegt. Erfasse gern ein paar Wünsche mehr."; }
const pinInputs = (a,b) => `<div class="row"><input id="${a}" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="••••" autocomplete="off"><input id="${b}" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="wiederholen" autocomplete="off"></div>`;

function sheetCreate(){
  const y = new Date().getFullYear();
  openSheet(`<div class="hd"><h2 class="grow">Neues Wichtelprojekt</h2><button class="btn ghost" onclick="closeSheet()">✕</button></div>
    <label>Familienname</label><input id="cf" placeholder="z. B. Müller" maxlength="40">
    <div class="row"><div class="grow"><label>Jahr</label><input id="cy" type="number" value="${y}"></div><div class="grow"><label>Anmeldeschluss</label><input id="cd" type="date" value="${y}-12-01"></div></div>
    <label>Budget pro Geschenk (CHF)</label><div class="row"><input id="cmin" type="number" placeholder="von" value="20"><span class="muted">–</span><input id="cmax" type="number" placeholder="bis" value="50"></div>
    <label>Weitere Spielregeln (optional)</label><textarea id="cr" placeholder="z. B. Geschenke werden am 24. Dezember nach dem Essen verteilt."></textarea>
    <label>Admin-PIN (4 Ziffern)</label>${pinInputs("cp1","cp2")}
    <p class="small muted">Mit der Admin-PIN steuerst du den Ablauf. Die Einteilung zeigt sie dir nicht. Wenn du selbst mitmachst, meldest du dich danach separat an.</p>
    <div class="err" id="ce"></div>
    <button class="btn block" style="margin-top:12px" onclick="createProject(this)">Projekt anlegen</button>`);
}
async function createProject(btn){
  const f=$("#cf").value.trim(), year=+$("#cy").value, p1=$("#cp1").value, p2=$("#cp2").value, e=$("#ce");
  if(!f) return e.textContent="Bitte einen Familiennamen eingeben.";
  if(!pinOk(p1)) return e.textContent="Die PIN muss aus 4 Ziffern bestehen.";
  if(p1!==p2) return e.textContent="Die beiden PINs stimmen nicht überein.";
  if(S.projects.some(x=>x.familyKey===famKey(f)&&x.year===year)) return e.textContent=`Für Familie ${f} gibt es ${year} schon ein Wichteln.`;
  await busy(btn, async()=>{
    const admin = await newIdentity(p1);
    const r = await api("POST","projects",{ family:f, year, deadline:$("#cd").value||"", budgetMin:+$("#cmin").value||0, budgetMax:+$("#cmax").value||0, rules:$("#cr").value.trim(), adminPin:p1, admin });
    const key = await unlock(p1, admin.priv);
    closeSheet(); go("p-"+r.id); S.admin={pid:r.id, token:r.adminToken, key}; S.tab="admin"; render(); refreshList();
    toast("Projekt angelegt. Teile jetzt den Link mit der Familie.");
  }).catch(err=>{ e.textContent = errText(err); });
}

function sheetSettings(){
  const p=P();
  openSheet(`<div class="hd"><h2 class="grow">Einstellungen</h2><button class="btn ghost" onclick="closeSheet()">✕</button></div>
    <label>Familienname</label><input id="sf" value="${esc(p.family)}" maxlength="40">
    <label>Anmeldeschluss</label><input id="sd" type="date" value="${esc(p.deadline)}">
    <label>Budget pro Geschenk (CHF)</label><div class="row"><input id="smin" type="number" value="${p.budgetMin||""}"><span class="muted">–</span><input id="smax" type="number" value="${p.budgetMax||""}"></div>
    <label>Weitere Spielregeln</label><textarea id="sr">${esc(p.rules)}</textarea>
    <div class="err" id="se"></div>
    <button class="btn block" style="margin-top:12px" onclick="saveSettings(this)">Speichern</button>`);
}
async function saveSettings(btn){
  const f=$("#sf").value.trim(); if(!f) return $("#se").textContent="Bitte einen Familiennamen eingeben.";
  await busy(btn, ()=>api("PATCH","p/"+S.pid,{family:f, deadline:$("#sd").value||"", budgetMin:+$("#smin").value||0, budgetMax:+$("#smax").value||0, rules:$("#sr").value.trim()}))
    .then(()=>{closeSheet();toast("Gespeichert");refreshProject();}).catch(err=>$("#se").textContent=errText(err));
}

function sheetJoin(){
  openSheet(`<div class="hd"><h2 class="grow">Mitmachen</h2><button class="btn ghost" onclick="closeSheet()">✕</button></div>
    <label>Dein Name</label><input id="jn" maxlength="30" placeholder="Vorname">
    <label>Deine PIN (4 Ziffern)</label>${pinInputs("jp1","jp2")}
    <p class="small muted">Merk sie dir gut: Mit ihr siehst du später, wen du beschenkst. Vergessene PINs lassen sich nicht wiederherstellen.</p>
    <label>Deine Wünsche</label><p class="small muted" style="margin:0 0 8px">${wishHint()}</p>
    <div id="wl">${wishRows([{},{},{}])}</div><button class="btn ghost sm" onclick="addWishRow()">+ Weiterer Wunsch</button>
    <div class="err" id="je"></div>
    <button class="btn block" id="jb" style="margin-top:12px" onclick="joinProject(this)">Anmelden</button>`);
}
async function joinProject(btn){
  const name=$("#jn").value.trim(), p1=$("#jp1").value, p2=$("#jp2").value, e=$("#je");
  if(!name) return e.textContent="Bitte deinen Namen eingeben.";
  if(S.parts.some(x=>x.name.toLowerCase()===name.toLowerCase())) return e.textContent="Diesen Namen gibt es schon. Ergänze z. B. den Anfangsbuchstaben des Nachnamens.";
  if(!pinOk(p1)) return e.textContent="Die PIN muss aus 4 Ziffern bestehen.";
  if(p1!==p2) return e.textContent="Die beiden PINs stimmen nicht überein.";
  const wishes = readWishRows();
  await busy(btn, async()=>{
    const idn = await newIdentity(p1);
    const r = await api("POST",`p/${S.pid}/join`,{ name, pin:p1, pub:idn.pub, priv:idn.priv, wishes });
    const key = await unlock(p1, idn.priv);
    S.session = { pid:S.pid, me:r.id, token:r.token, privs:{[r.id]:idn.priv}, keys:{[r.id]:key}, pay:{}, tags:{} };
    closeSheet(); S.tab="mine"; await refreshProject(); render(); toast("Du bist dabei!");
  }).catch(err=>e.textContent=errText(err));
}

function sheetLogin(){
  const own = S.parts.filter(x=>!x.managedBy);
  openSheet(`<div class="hd"><h2 class="grow">Anmelden</h2><button class="btn ghost" onclick="closeSheet()">✕</button></div>
    <label>Wer bist du?</label><select id="ln">${own.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join("")}</select>
    <label>PIN</label><input id="lp" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="••••" autocomplete="off" onkeydown="if(event.key==='Enter')$('#lb').click()">
    <div class="err" id="le"></div>
    <button class="btn block" id="lb" style="margin-top:12px" onclick="login(this)">Anmelden</button>`);
}
async function login(btn){
  const id=$("#ln").value, pin=$("#lp").value;
  await busy(btn, async()=>{
    const r = await api("POST",`p/${S.pid}/login`,{id, pin});
    const keys={}, privs={};
    for(const k of r.keys){ privs[k.id]=k.priv; keys[k.id]=await unlock(pin, k.priv); }
    S.session = { pid:S.pid, me:id, token:r.token, privs, keys, pay:{}, tags:{} };
    closeSheet(); render(); loadAssignments();
  }).catch(err=>{ const le=$("#le"); if(le) le.textContent=errText(err); });
}
async function loadAssignments(){
  const ses=S.session; if(!ses || !["drawn","revealed","archived"].includes(P()?.phase)) return;
  try{
    const r = await api("GET",`p/${S.pid}/assign`);
    for(const [id, sealed] of Object.entries(r.items)){
      if(!ses.keys[id]) continue;
      ses.pay[id] = await unseal(ses.keys[id], sealed);
    }
    ses.tags={}; await refreshTags(true);
  }catch(e){ console.warn(e); }
  render();
}
async function refreshTags(force){
  const ses=S.session; if(!ses) return; let changed=!!force;
  for(const [id,pay] of Object.entries(ses.pay)){
    const tags=ses.tags[id]=ses.tags[id]||new Set();
    for(const g of pay.gives) for(const w of wishesOf(g.to)){ const t=await tagFor(pay.secret,w.id); if(!tags.has(t)){tags.add(t);changed=true;} }
  }
  if(changed && !force) render();
}
function logout(){ S.session=null; render(); }

function sheetAddManaged(){
  openSheet(`<div class="hd"><h2 class="grow">Person eintragen</h2><button class="btn ghost" onclick="closeSheet()">✕</button></div>
    <p class="small muted">Für Kinder oder andere ohne Handy. Du verwaltest die Person mit deiner PIN und siehst auch, wen sie beschenkt. Ihr beide zieht euch gegenseitig nicht.</p>
    <label>Name</label><input id="mn" maxlength="30">
    <label>Deine PIN zur Bestätigung</label><input id="mp" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="••••" autocomplete="off">
    <label>Wünsche</label><p class="small muted" style="margin:0 0 8px">${wishHint()}</p>
    <div id="wl">${wishRows([{},{},{}])}</div><button class="btn ghost sm" onclick="addWishRow()">+ Weiterer Wunsch</button>
    <div class="err" id="me"></div>
    <button class="btn block" style="margin-top:12px" onclick="addManaged(this)">Eintragen</button>`);
}
async function addManaged(btn){
  const name=$("#mn").value.trim(), pin=$("#mp").value, e=$("#me"), ses=S.session;
  if(!name) return e.textContent="Bitte einen Namen eingeben.";
  if(S.parts.some(x=>x.name.toLowerCase()===name.toLowerCase())) return e.textContent="Diesen Namen gibt es schon.";
  await busy(btn, async()=>{
    try{ await unlock(pin, ses.privs[ses.me]); }catch(x){ e.textContent="Die PIN ist falsch."; return; }
    const idn=await newIdentity(pin);
    const r = await api("POST",`p/${S.pid}/join`,{ name, managedBy:ses.me, pub:idn.pub, priv:idn.priv, wishes:readWishRows() });
    ses.privs[r.id]=idn.priv; ses.keys[r.id]=await unlock(pin, idn.priv);
    closeSheet(); await refreshProject(); render(); toast(name+" ist dabei!");
  }).catch(err=>e.textContent=errText(err));
}

function sheetWishes(owner, addOnly){
  const pe=S.parts.find(x=>x.id===owner);
  const list = addOnly ? [{}] : (wishesOf(owner).length?wishesOf(owner):[{}]);
  openSheet(`<div class="hd"><h2 class="grow">${addOnly?"Wunsch hinzufügen":"Wünsche von "+esc(pe.name)}</h2><button class="btn ghost" onclick="closeSheet()">✕</button></div>
    ${addOnly?`<p class="small muted">Nach der Auslosung kannst du nur noch neue Wünsche hinzufügen.</p>`:`<p class="small muted">${wishHint()}</p>`}
    <div id="wl">${wishRows(list)}</div><button class="btn ghost sm" onclick="addWishRow()">+ Weiterer Wunsch</button>
    <div class="err" id="we"></div>
    <button class="btn block" style="margin-top:12px" onclick="saveWishSheet(this,'${owner}',${!!addOnly})">Speichern</button>`);
}
async function saveWishSheet(btn, owner, addOnly){
  const list = readWishRows();
  await busy(btn, ()=>api(addOnly?"POST":"PUT", `p/${S.pid}/wishes/${owner}`, {wishes:list}))
    .then(()=>{ closeSheet(); toast("Wünsche gespeichert"); refreshProject(); }).catch(err=>$("#we").textContent=errText(err));
}

async function reserve(btn, wishId, giverId, on){
  const ses=S.session, pay=ses.pay[giverId];
  await busy(btn, async()=>{
    const tag=await tagFor(pay.secret, wishId);
    await api("POST",`p/${S.pid}/reserve`,{wishId, tag, on});
    (ses.tags[giverId]=ses.tags[giverId]||new Set()).add(tag);
    toast(on?"Reserviert. Die anderen sehen nicht, von wem.":"Reservierung aufgehoben");
    await refreshProject();
  }).catch(err=>{ toast(errText(err)); refreshProject(); });
}

// ---------- Admin-Aktionen ----------
function sheetAdmin(){
  openSheet(`<div class="hd"><h2 class="grow">Admin entsperren</h2><button class="btn ghost" onclick="closeSheet()">✕</button></div>
    <label>Admin-PIN</label><input id="ap" class="pin" inputmode="numeric" maxlength="4" type="password" placeholder="••••" autocomplete="off" onkeydown="if(event.key==='Enter')$('#ab').click()">
    <div class="err" id="ae"></div><button class="btn block" id="ab" style="margin-top:12px" onclick="adminLogin(this)">Entsperren</button>`);
}
async function adminLogin(btn){
  const pin=$("#ap").value;
  await busy(btn, async()=>{
    const r = await api("POST",`p/${S.pid}/admin-login`,{pin});
    const key = await unlock(pin, r.priv);
    S.admin={pid:S.pid, token:r.token, key}; closeSheet(); render();
  }).catch(err=>{ const ae=$("#ae"); if(ae) ae.textContent=errText(err); });
}
async function setPhase(btn, phase){
  if(phase==="closed" && !await confirmSheet("Anmeldung schliessen?","Danach kann sich niemand mehr anmelden. Du kannst sie bei Bedarf wieder öffnen.","Schliessen")) return;
  await busy(btn, ()=>api("PATCH","p/"+S.pid,{phase})).then(refreshProject).catch(err=>toast(errText(err)));
}
function hardExclusions(){ const h=[]; for(const x of S.parts) if(x.managedBy){ h.push([x.id,x.managedBy],[x.managedBy,x.id]); } return h; }
async function saveGifts(btn){
  const n = +($("#nSel").value);
  await busy(btn, ()=>api("PATCH","p/"+S.pid,{gifts:n})).then(()=>{toast("Gespeichert");refreshProject();}).catch(err=>toast(errText(err)));
}
async function lastYearPairs(){
  const p=P();
  const prev = S.projects.filter(x=>x.familyKey===p.familyKey && x.year<p.year && (x.phase==="revealed"||x.phase==="archived")).sort((a,b)=>b.year-a.year)[0];
  if(!prev) return [];
  try{
    const d = await api("GET","p/"+prev.id); if(!d.result) return [];
    const byName = Object.fromEntries(S.parts.map(x=>[x.name.toLowerCase(), x.id]));
    return d.result.pairs.map(x=>[byName[x.fromName.toLowerCase()], byName[x.toName.toLowerCase()]]).filter(([a,b])=>a&&b);
  }catch(e){ return []; }
}
async function doDraw(btn){
  const p=P(), N=p.gifts;
  const few = S.parts.filter(x=>wishesOf(x.id).length<N).map(x=>x.name);
  const txt = `${S.parts.length} Teilnehmer, ${N} ${N>1?"Geschenke":"Geschenk"} pro Person.` + (few.length?`<br><br>Noch nicht genug Wünsche: <b>${few.map(esc).join(", ")}</b>. Sie können nach der Auslosung noch Wünsche hinzufügen.`:"") + "<br><br>Danach sieht jeder nach PIN-Eingabe, wen er beschenkt.";
  if(!await confirmSheet("Jetzt auslosen?", txt, "Auslosen")) return;
  await busy(btn, async()=>{
    await refreshList();
    const ids=S.parts.map(x=>x.id);
    const res = Draw.run(ids, N, hardExclusions(), await lastYearPairs());
    if(!res){ toast("Auslosung nicht möglich. Bitte weniger Geschenke wählen."); return; }
    const assign={};
    for(const id of ids){
      const pe=S.parts.find(x=>x.id===id);
      const gives = res.pairs.filter(([a])=>a===id).map(([,b])=>({to:b}));
      assign[id] = await seal(pe.pub, {gives, secret:rid(20)});
    }
    const reveal = await seal(p.admin.pub, {pairs: res.pairs.map(([a,b])=>({from:a, to:b}))});
    await api("POST",`p/${S.pid}/draw`,{assign, reveal, softOk:res.softRespected});
    toast("Ausgelost! Alle können jetzt nachsehen, wen sie beschenken.");
    await refreshProject();
  }).catch(err=>toast(errText(err)));
}
async function undoDraw(btn){
  if(!await confirmSheet("Auslosung zurücksetzen?","Die aktuelle Einteilung und alle Reservierungen werden gelöscht. Danach kannst du neu auslosen. Sinnvoll z. B., wenn jemand seine PIN vergessen hat: Person entfernen, neu anmelden lassen, neu auslosen.","Zurücksetzen",true)) return;
  await busy(btn, async()=>{
    await api("POST",`p/${S.pid}/undo-draw`);
    if(S.session){ S.session.pay={}; S.session.tags={}; }
    await refreshProject();
  }).catch(err=>toast(errText(err)));
}
async function doReveal(btn){
  const before = new Date() < new Date(P().year, 11, 24);
  if(!await confirmSheet("Auflösung veröffentlichen?", (before?"<b>Achtung, es ist noch nicht Weihnachten.</b><br><br>":"")+"Danach sehen alle, wer wen beschenkt hat.", "Veröffentlichen", before)) return;
  await busy(btn, async()=>{
    const r = await api("GET",`p/${S.pid}/reveal-data`);
    const data = await unseal(S.admin.key, r.sealed);
    await api("POST",`p/${S.pid}/reveal`,{pairs:data.pairs});
    S.tab="result"; toast("Die Auflösung ist veröffentlicht 🎄");
    await refreshProject();
  }).catch(err=>toast(errText(err)));
}
async function removePart(btn, id){
  const pe=S.parts.find(x=>x.id===id), kids=S.parts.filter(x=>x.managedBy===id);
  if(!await confirmSheet(pe.name+" entfernen?", "Die Person und ihre Wünsche werden gelöscht."+(kids.length?` Auch ${kids.map(k=>esc(k.name)).join(", ")} (von ${esc(pe.name)} eingetragen) werden entfernt.`:""), "Entfernen", true)) return;
  await busy(btn, ()=>api("DELETE",`p/${S.pid}/participants/${id}`)).then(refreshProject).catch(err=>toast(errText(err)));
}
async function deleteProject(btn){
  if(!await confirmSheet("Projekt löschen?","Das leere Projekt wird endgültig gelöscht.","Löschen",true)) return;
  await busy(btn, ()=>api("DELETE","p/"+S.pid)).then(()=>{ go(""); refreshList(); }).catch(err=>toast(errText(err)));
}
async function newYear(btn){
  const p=P(), year=p.year+1;
  if(!await confirmSheet(`Wichteln ${year} starten?`, "Familie, Budget, Spielregeln und Admin-PIN werden übernommen. Alle melden sich neu an.", "Starten")) return;
  await busy(btn, async()=>{
    const r = await api("POST",`p/${S.pid}/next-year`);
    const key = S.admin.key;
    go("p-"+r.id); S.admin={pid:r.id, token:r.adminToken, key}; S.tab="admin"; render(); refreshList();
    toast(`Wichteln ${year} ist eröffnet`);
  }).catch(err=>toast(errText(err)));
}
