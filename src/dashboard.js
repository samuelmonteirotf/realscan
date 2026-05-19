// Landing + shareable report, on-brand with monteirotf.com.
// IMPORTANT: report content includes data from the *scanned* site
// (headers, CSP strings, secret matches) — everything dynamic is
// HTML-escaped before it reaches the page.

const esc = (s) =>
  String(s == null ? "" : s).replace(/[<>&"']/g, (c) =>
    ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" }[c])
  );

const CSS = `
  :root{--cyber:#0066FF;--ice:#9FD0FF;--ink:#03060E}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--ink);color:#DCE7FF;font-family:'Space Grotesk',system-ui,sans-serif;line-height:1.55;
    background-image:linear-gradient(rgba(122,174,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(122,174,255,.04) 1px,transparent 1px);
    background-size:64px 64px;min-height:100vh}
  .wrap{max-width:880px;margin:0 auto;padding:60px 24px 90px}
  .eyebrow{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.32em;text-transform:uppercase;color:var(--cyber)}
  h1{font-family:'Orbitron',sans-serif;font-weight:900;font-size:clamp(2rem,6vw,3.4rem);line-height:1.05;margin:14px 0 16px;
    background:linear-gradient(110deg,#fff,#7AAEFF,#0066FF,#fff);-webkit-background-clip:text;background-clip:text;color:transparent}
  .sub{color:#9FB2D8;max-width:62ch}
  .card{background:linear-gradient(135deg,rgba(15,28,60,.5),rgba(7,11,26,.35));border:1px solid rgba(122,174,255,.14);
    border-radius:18px;padding:22px;backdrop-filter:blur(10px)}
  form{display:flex;gap:12px;margin-top:28px;flex-wrap:wrap}
  input{flex:1;min-width:240px;background:#04081A;border:1px solid rgba(122,174,255,.2);color:#DCE7FF;
    border-radius:999px;padding:14px 20px;font-family:'JetBrains Mono',monospace;font-size:14px;outline:none}
  input:focus{border-color:var(--cyber)}
  button{font-family:'JetBrains Mono',monospace;font-size:12px;letter-spacing:.18em;text-transform:uppercase;
    background:var(--cyber);color:var(--ink);border:0;border-radius:999px;padding:14px 26px;font-weight:600;cursor:pointer}
  button:hover{background:#fff} button:disabled{opacity:.5;cursor:wait}
  .err{color:#ff8080;font-family:'JetBrains Mono',monospace;font-size:13px;margin-top:14px}
  .gradewrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap}
  .grade{font-family:'Orbitron',sans-serif;font-weight:900;font-size:5rem;line-height:1;width:120px;text-align:center;
    border-radius:18px;padding:18px 0;border:1px solid rgba(122,174,255,.2)}
  .gA{color:#46e0a8} .gB{color:#9fe06b} .gC{color:#ffc94d} .gD{color:#ff9d5c} .gF{color:#ff6b6b}
  .row{display:flex;justify-content:space-between;gap:14px;padding:14px 0;border-bottom:1px solid rgba(122,174,255,.08)}
  .row:last-child{border:0}
  .sev{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;
    padding:4px 9px;border-radius:999px;white-space:nowrap;height:fit-content}
  .s-high{background:rgba(255,107,107,.15);color:#ff6b6b;border:1px solid rgba(255,107,107,.4)}
  .s-medium{background:rgba(255,201,77,.13);color:#ffc94d;border:1px solid rgba(255,201,77,.35)}
  .s-low{background:rgba(159,208,255,.1);color:#9FD0FF;border:1px solid rgba(159,208,255,.3)}
  .s-info{background:rgba(127,144,181,.12);color:#9aa9c9;border:1px solid rgba(127,144,181,.3)}
  .s-pass{background:rgba(70,224,168,.12);color:#46e0a8;border:1px solid rgba(70,224,168,.32)}
  .ft{font-weight:600} .fd{color:#8fa1c4;font-size:13.5px;margin-top:3px}
  .fd code{font-family:'JetBrains Mono',monospace;background:#04081A;padding:1px 6px;border-radius:5px;font-size:12px}
  .muted{color:#7e90b5;font-size:13px} h2{font-family:'Orbitron',sans-serif;font-size:1.05rem;margin:34px 0 8px}
  .bar{height:7px;border-radius:4px;background:rgba(122,174,255,.12);overflow:hidden;margin-top:6px}
  .bar>i{display:block;height:100%;background:var(--cyber)}
  .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:18px}
  .stats div{text-align:center} .stats .n{font-family:'Orbitron',sans-serif;font-size:1.4rem}
  footer{margin-top:46px;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.2em;color:#5f739b;text-transform:uppercase}
  a{color:var(--ice)}
`;

const HEAD = (title) => `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" /><title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com" /><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Orbitron:wght@700;900&display=swap" rel="stylesheet" />
<style>${CSS}</style></head><body><div class="wrap">`;

const FOOT = `<footer>RealScan · open source · S. Monteiro · <a href="https://monteirotf.com">monteirotf.com</a></footer></div></body></html>`;

export function renderLanding(host, error) {
  return `${HEAD("RealScan — web posture scanner")}
  <div class="eyebrow">RealScan · live</div>
  <h1>Scan a site.<br>See what it leaks.</h1>
  <p class="sub">An external posture check from a Cloudflare Worker: HTTPS &amp; HSTS,
  security headers, SPF/DMARC/DNSSEC, origin-bypass subdomains, and secrets
  exposed in client code. It only reports what can actually be verified.</p>

  <form id="f">
    <input id="u" placeholder="example.com" autocomplete="off" autocapitalize="off" spellcheck="false" />
    <button id="b" type="submit">Scan →</button>
  </form>
  <div class="err" id="e">${error ? esc(error) : ""}</div>

  <h2>Scans run · grade distribution</h2>
  <div class="card"><div class="stats" id="st">
    <div><div class="n" id="n-t">—</div><div class="muted">total</div></div>
    <div><div class="n gA" id="n-A">—</div><div class="muted">A</div></div>
    <div><div class="n gB" id="n-B">—</div><div class="muted">B</div></div>
    <div><div class="n gC" id="n-C">—</div><div class="muted">C</div></div>
    <div><div class="n gF" id="n-F">—</div><div class="muted">D/F</div></div>
  </div></div>

  <script>
    const f=document.getElementById('f'),b=document.getElementById('b'),e=document.getElementById('e');
    f.onsubmit=async(ev)=>{ev.preventDefault();e.textContent='';b.disabled=true;b.textContent='Scanning…';
      try{const r=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({url:document.getElementById('u').value.trim()})});
        const j=await r.json(); if(j.path) location.href=j.path;
        else { e.textContent=j.error||'Scan failed'; b.disabled=false; b.textContent='Scan →'; }
      }catch(x){ e.textContent='Network error'; b.disabled=false; b.textContent='Scan →'; }};
    (async()=>{try{const t=await(await fetch('/api/stats',{cache:'no-store'})).json();const g=t.grades||{};
      n_t.textContent=t.total||0;n_A.textContent=g.A||0;n_B.textContent=g.B||0;n_C.textContent=g.C||0;
      n_F.textContent=(g.D||0)+(g.F||0);}catch(_){}}) ();
  </script>${FOOT}`;
}

export function renderReport(rep, host, id) {
  const g = rep.grade;
  const chip = (s) => `<span class="sev s-${s}">${s}</span>`;
  const rows = rep.findings
    .map(
      (f) => `<div class="row"><div><div class="ft">${esc(f.title)}</div>
      ${f.detail ? `<div class="fd">${esc(f.detail).replace(/&#39;([^&]+?)&#39;|\`([^\`]+?)\`/g, (m,a,bq)=>'<code>'+(a||bq)+'</code>')}</div>` : ""}</div>${chip(f.sev)}</div>`
    )
    .join("");
  const c = rep.counts || {};
  return `${HEAD("RealScan · " + rep.host)}
  <div class="eyebrow"><a href="/">RealScan</a> · report</div>
  <h1 style="font-size:clamp(1.6rem,5vw,2.6rem)">${esc(rep.host)}</h1>
  <p class="muted">Scanned ${esc(rep.scannedAt)} · ${esc(rep.meta && rep.meta.scheme)}${
    rep.meta && rep.meta.behindCdn ? " · behind Cloudflare" : ""
  }</p>

  <div class="card" style="margin-top:22px"><div class="gradewrap">
    <div class="grade g${g}">${g}</div>
    <div>
      <div style="font-family:'Orbitron';font-size:1.6rem">Score ${rep.score}/100</div>
      <div class="muted" style="margin-top:6px">
        ${c.high || 0} high · ${c.medium || 0} medium · ${c.low || 0} low ·
        ${c.pass || 0} passed</div>
    </div>
  </div></div>

  <h2>Findings</h2>
  <div class="card">${rows}</div>

  <form id="f" style="margin-top:30px">
    <input id="u" placeholder="scan another site…" autocomplete="off" />
    <button id="b" type="submit">Scan →</button>
  </form>
  <div class="err" id="e"></div>
  <p class="muted" style="margin-top:18px">Shareable: <a href="https://${esc(host)}/r/${esc(id)}">https://${esc(host)}/r/${esc(id)}</a></p>

  <script>
    const f=document.getElementById('f'),b=document.getElementById('b'),e=document.getElementById('e');
    f.onsubmit=async(ev)=>{ev.preventDefault();e.textContent='';b.disabled=true;b.textContent='Scanning…';
      try{const r=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({url:document.getElementById('u').value.trim()})});
        const j=await r.json(); if(j.path) location.href=j.path;
        else { e.textContent=j.error||'Scan failed'; b.disabled=false; b.textContent='Scan →'; }
      }catch(x){ e.textContent='Network error'; b.disabled=false; b.textContent='Scan →'; }};
  </script>${FOOT}`;
}
