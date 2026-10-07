#!/usr/bin/env python3
"""Build bench/report.html from bench/results/*.json (stdlib only).

The page is self-contained: data is embedded as JSON and drawn as inline SVG
by a small script, with hover tooltips and a data table under every chart.
"""
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent
res = root / "results"


def load(name):
    p = res / name
    return json.loads(p.read_text()) if p.exists() else None


data = {
    "v1b": load("v1-broker.json"),
    "v1m": load("v1-mailbox.json"),
    "v2": load("v2-relay.json"),
    "pow": load("pow.json"),
    "spam": load("spam.json"),
    "ledger": load("ledger.json"),
    "crash": load("crash.json"),
    "live": load("live.json"),
    "live_before_push": load("history/live-prefetch-before-push.json"),
    "live_before": load("history/live-before-prefetch.json"),
    "iters": [
        {"name": "1 · database/sql + savepoints", "file": load("history/v2-iter1-databasesql-savepoints.json")},
        {"name": "2 · write overlay, compact records", "file": load("history/v2-iter2-overlay-compact-records.json")},
        {"name": "bbolt backend (rejected)", "file": load("history/v2-rejected-bbolt.json"), "rejected": True},
        {"name": "3 · low-level SQLite, 4 procs", "file": load("history/v2-iter3-lowlevel-sqlite-gomaxprocs.json")},
    ],
    "pg_rtt": {"before": 11.5, "after": 3.5},
}
def slim_sys(d):
    keep = ("send_throughput", "roundtrip_ms", "wire_bytes", "rss_mb", "cpu_ms_per_msg", "cold_start_ms", "install_mb")
    out = {k: d[k] for k in keep}
    out["send_throughput"] = [{k: t[k] for k in ("concurrency", "msgs_per_sec", "p50_ms", "p99_ms", "errors")} for t in d["send_throughput"]]
    return out


for k in ("v1b", "v1m", "v2"):
    data[k] = slim_sys(data[k])
for k in ("live", "live_before", "live_before_push"):
    if data[k]:
        data[k] = {x: data[k][x] for x in ("send_ms", "receive_ms", "ack_ms", "roundtrip_ms", "push_ms") if x in data[k]}
if data["spam"]:
    for f in data["spam"]["fill"]:
        f.pop("curve", None)
    for x in ("model", "old_rule", "new_rule", "price_by_load", "price_by_declines", "timestamp"):
        data["spam"].pop(x, None)
for x in ("method", "note", "timestamp"):
    data["crash"].pop(x, None)
data["pow"] = {"rows": data["pow"]["rows"], "verify_ns": data["pow"]["verify_ns"]}
data["ledger"] = {"points": data["ledger"]["points"]}
for it in data["iters"]:
    f = it.pop("file")
    t16 = next(x for x in f["send_throughput"] if x["concurrency"] == 16)
    it["throughput"] = t16["msgs_per_sec"]
    it["cpu"] = f["cpu_ms_per_msg"]
    it["peak"] = f["rss_mb"]["peak"]

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Silk v2 benchmarks</title>
<style>
.viz-root{
  --ink: var(--foreground, #0b0b0b);
  --ink2: var(--muted-foreground, #52514e);
  --ink3: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --gray: #b9b8b1; --surface: var(--background, #fcfcfb);
  --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100;
  --good:#006300;
  color: var(--ink); font: 14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;
}
.viz-root.dark{
  --ink: var(--foreground, #ffffff); --ink2: var(--muted-foreground, #c3c2b7);
  --grid:#2c2c2a; --axis:#383835; --gray:#55544f; --surface: var(--background, #1a1a19);
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500; --good:#0ca30c;
}
@media (prefers-color-scheme: dark){ html:not([data-light]) .viz-root:not(.light){
  --ink: var(--foreground, #ffffff); --ink2: var(--muted-foreground, #c3c2b7);
  --grid:#2c2c2a; --axis:#383835; --gray:#55544f; --surface: var(--background, #1a1a19);
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500; --good:#0ca30c; } }
body{margin:0}
html.standalone{background:#fcfcfb}
html.standalone body{max-width:960px;margin:0 auto;padding:28px 20px 48px}
html.standalone h1{font-size:24px;margin:0 0 4px}
html.standalone a{color:inherit}
@media (prefers-color-scheme: dark){ html.standalone{background:#1a1a19} }
h2{font-size:15px;font-weight:600;margin:28px 0 2px}
h2:first-of-type{margin-top:4px}
.sub{color:var(--ink2);margin:0 0 10px;font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px 16px;margin:8px 0 6px}
.kpi .l{color:var(--ink2);font-size:12px}
.kpi .v{font-size:22px;font-weight:600;letter-spacing:-.01em}
.kpi .d{font-size:12px;color:var(--ink2)}
.kpi .x{color:var(--good);font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;color:var(--ink2);margin:0 0 4px}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px}
.legend i.line{height:2px;width:14px;border-radius:1px}
svg{display:block;overflow:visible}
svg text{fill:var(--ink2);font-size:11px}
svg .val{fill:var(--ink);font-size:11px;font-weight:600}
svg .muted{fill:var(--ink3)}
.grid line{stroke:var(--grid);stroke-width:1}
.axis{stroke:var(--axis);stroke-width:1}
.mark{cursor:default}
.mark:hover,.mark:focus{opacity:.82;outline:none}
details{margin:2px 0 0;font-size:12px;color:var(--ink2)}
details summary{cursor:pointer;width:max-content}
table{border-collapse:collapse;margin:6px 0 2px;font-variant-numeric:tabular-nums}
th,td{padding:2px 10px 2px 0;text-align:right;border-bottom:1px solid var(--grid)}
th:first-child,td:first-child{text-align:left}
th{font-weight:600;color:var(--ink)}
.row2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:4px 28px}
.mini h3{font-size:13px;font-weight:600;margin:10px 0 0}
.note{font-size:12px;color:var(--ink2);margin:6px 0 0}
#tip{position:fixed;pointer-events:none;z-index:9;background:var(--surface);color:var(--ink);border:1px solid var(--grid);
  border-radius:8px;padding:6px 9px;font-size:12px;box-shadow:0 2px 10px rgba(0,0,0,.12);display:none;max-width:260px}
#tip b{font-size:13px}
#tip .k{display:inline-block;width:12px;height:2px;margin-right:6px;vertical-align:middle}
</style>
</head>
<body>
<div class="viz-root" id="root">
<div class="kpis" id="kpis"></div>
<p class="note" id="kpinote"></p>

<h2>Throughput by client concurrency</h2>
<p class="sub">Accepted sends per second, higher is better. Same machine, same method, fresh server per level.</p>
<div class="legend" data-legend="sys"></div>
<div id="c-thr"></div>

<h2>Tail latency (p99) by client concurrency</h2>
<p class="sub">Milliseconds per send, log scale, lower is better.</p>
<div class="legend" data-legend="sys" data-line="1"></div>
<div id="c-p99"></div>

<h2>Message roundtrip: send → recipient reads → acknowledgment</h2>
<p class="sub">Milliseconds, log scale. Dot is the median; the bar spans p50 to p99.</p>
<div class="legend" data-legend="sys"></div>
<div id="c-rt"></div>

<h2>Efficiency</h2>
<p class="sub">Lower is better on every panel.</p>
<div class="legend" data-legend="sys"></div>
<div class="row2" id="c-eff"></div>

<h2>How v2 got here: iterations</h2>
<p class="sub">Each change was measured, kept only if it won. Throughput at 16 concurrent clients; CPU per message.</p>
<div id="c-iter"></div>

<h2>Live hosted relay (silk-relay.vercel.app)</h2>
<p class="sub">Measured from a residential connection: Vercel edge (Cleveland) → Go function (iad1) → Neon Postgres.</p>
<div class="row2" id="c-live"></div>

<h2>Spam: what it costs to block someone</h2>
<p class="sub">Attacker compute needed to keep one stranger out of a recipient's request queue, versus what that stranger pays once. Invited and trusted senders skip the queue entirely (0 bits).</p>
<div class="legend" data-legend="atk" data-line="1"></div>
<div id="c-spam"></div>

<div class="row2">
<div class="mini"><h3>Proof-of-work stamp cost (this laptop)</h3><p class="sub">Milliseconds to solve by stamp size in bits, log scale. The relay verifies any stamp in <span id="verifyns"></span>.</p><div class="legend" data-legend="pow" data-line="1"></div><div id="c-pow"></div></div>
<div class="mini"><h3>Ledger proof size</h3><p class="sub">Bytes to prove one entry is on the ledger, log–log.</p><div class="legend" data-legend="led" data-line="1"></div><div id="c-led"></div></div>
</div>

<h2>Crash safety: <span id="crashtitle"></span></h2>
<p class="sub" id="crashsub"></p>
<div id="c-crash"></div>
<div id="tip" role="status"></div>
</div>
<script>
const D = __DATA__;
const root = document.getElementById('root');
// Pick the palette from the actual page background (works inside a themed host and standalone).
// Standalone (no host theme): give the page its own surface, width and title.
const hosted = getComputedStyle(document.documentElement).getPropertyValue('--background').trim() !== '';
if (!hosted) {
  document.documentElement.classList.add('standalone');
  const h=document.createElement('header'); const t=document.createElement('h1'); t.textContent='Silk v2 benchmarks';
  const p=document.createElement('p'); p.className='sub'; p.append('Measured results, regenerated from bench/results by bench/make_report.py. Source: ');
  const a=document.createElement('a'); a.href='https://github.com/21J3phy/silk'; a.textContent='github.com/21J3phy/silk'; p.append(a);
  h.append(t,p); root.prepend(h);
}
(function(){
  if (!hosted) return; // standalone pages follow the OS color scheme via CSS
  const bg = getComputedStyle(document.body).backgroundColor;
  const m = bg && bg.match(/\d+(\.\d+)?/g);
  if (m && m.length >= 3 && (m.length < 4 || +m[3] > 0)) {
    const [r,g,b] = m.map(Number), L = 0.2126*r + 0.7152*g + 0.0722*b;
    root.classList.add(L < 128 ? 'dark' : 'light');
  }
})();
const fmt = (v,d=0) => v==null?'–':Number(v).toLocaleString('en-US',{maximumFractionDigits:d,minimumFractionDigits:0});
const SYS = [{k:'v2',name:'Silk v2 (Go)',c:'--s1'},{k:'v1m',name:'v1 MCP mailbox (Python)',c:'--s2'},{k:'v1b',name:'v1 local broker (Python)',c:'--s3'}];
const ATK = D.spam ? D.spam.fill.map((f,i)=>({k:f.attacker,name:f.attacker+' ('+fmtHps(f.hashes_per_sec)+')',c:['--s1','--s2','--s3','--s4'][i]})) : [];
function fmtMs(v){ if(v==null) return '–'; if(v>=1000) return fmt(v/1000, v>=10000?0:1)+' s'; if(v>=10) return fmt(v,0)+' ms'; if(v>=1) return fmt(v,1)+' ms'; return fmt(v,2)+' ms'; }
function fmtSec(v){ if(v<0.001) return fmt(v*1e6,0)+' µs'; if(v<1) return fmt(v*1000,v<0.01?1:0)+' ms'; if(v<120) return fmt(v,1)+' s'; if(v<7200) return fmt(v/60,0)+' min'; if(v<172800) return fmt(v/3600,1)+' h'; return fmt(v/86400,0)+' days'; }
function fmtHps(h){ return h>=1e12?fmt(h/1e12,0)+' TH/s':h>=1e9?fmt(h/1e9,0)+' GH/s':fmt(h/1e6,0)+' MH/s'; }
function fmtBytes(b){ return b>=1e6?fmt(b/1e6,1)+' MB':b>=1e3?fmt(b/1e3,1)+' KB':fmt(b,0)+' B'; }

// legends
const LEG = {sys:SYS, atk:ATK, pow:[{name:'all cores',c:'--s1'},{name:'one core',c:'--s2'}], led:[{name:'Silk ledger (Merkle tree)',c:'--s1'},{name:'plain hash chain',c:'--s2'}]};
document.querySelectorAll('[data-legend]').forEach(el=>{
  for (const s of LEG[el.dataset.legend]) { const sp=document.createElement('span'); const i=document.createElement('i'); if(el.dataset.line) i.className='line'; i.style.background='var('+s.c+')'; sp.append(i, document.createTextNode(s.name)); el.append(sp); }
});

// tooltip
const tip = document.getElementById('tip');
function bindTip(node, rows){
  node.setAttribute('tabindex','0');
  const show = e => { tip.replaceChildren();
    rows().forEach((r,i)=>{ const d=document.createElement('div'); if(r.c){const k=document.createElement('span');k.className='k';k.style.background='var('+r.c+')';d.append(k);} const b=document.createElement(i===0?'b':'span'); b.textContent=r.v; d.append(b); if(r.l){d.append(document.createTextNode('  '+r.l));} tip.append(d); });
    tip.style.display='block'; const x=(e.clientX||node.getBoundingClientRect().right), y=(e.clientY||node.getBoundingClientRect().top);
    const w=tip.offsetWidth; tip.style.left=Math.min(x+12, innerWidth-w-8)+'px'; tip.style.top=(y+14)+'px'; };
  node.addEventListener('pointermove', show); node.addEventListener('focus', show);
  node.addEventListener('pointerleave', ()=>tip.style.display='none'); node.addEventListener('blur', ()=>tip.style.display='none');
}
const NS='http://www.w3.org/2000/svg';
function el(tag, attrs, parent){ const n=document.createElementNS(NS, tag); for(const k in attrs) n.setAttribute(k, attrs[k]); if(parent) parent.append(n); return n; }
function txt(parent, x, y, s, cls, anchor){ const t=el('text',{x,y,'text-anchor':anchor||'start',class:cls||''},parent); t.textContent=s; return t; }
function svgBox(container, h){ const w=Math.max(280, container.clientWidth||680); const s=el('svg',{width:w,height:h,viewBox:'0 0 '+w+' '+h,role:'img'},container); return [s,w]; }
function roundTop(x,y,w,h,r){ r=Math.min(r,w/2,h); return `M${x},${y+h}V${y+r}Q${x},${y} ${x+r},${y}H${x+w-r}Q${x+w},${y} ${x+w},${y+r}V${y+h}Z`; }
function roundRight(x,y,w,h,r){ r=Math.min(r,h/2,w); return `M${x},${y}H${x+w-r}Q${x+w},${y} ${x+w},${y+r}V${y+h-r}Q${x+w},${y+h} ${x+w-r},${y+h}H${x}Z`; }
function niceMax(v){ const p=Math.pow(10,Math.floor(Math.log10(v))); for(const m of [1,1.5,2,2.5,3,4,5,6,8,10]) if(m*p>=v) return m*p; return 10*p; }
function table(container, head, rows){ const d=document.createElement('details'); const s=document.createElement('summary'); s.textContent='Table'; d.append(s); const t=document.createElement('table'); const tr=document.createElement('tr'); head.forEach(h=>{const th=document.createElement('th');th.textContent=h;tr.append(th);}); t.append(tr); rows.forEach(r=>{const tr=document.createElement('tr'); r.forEach(c=>{const td=document.createElement('td');td.textContent=c;tr.append(td);}); t.append(tr);}); d.append(t); container.append(d); }
function logTicks(lo,hi){ const t=[]; for(let e=Math.floor(Math.log10(lo)); e<=Math.ceil(Math.log10(hi)); e++) t.push(Math.pow(10,e)); return t; }

// ---------- KPIs
(function(){
  const v2=D.v2, b=D.v1b, m=D.v1m; const k=document.getElementById('kpis');
  const at=(r,c)=>r.send_throughput.find(x=>x.concurrency===c);
  const tiles=[
    ['Throughput, 16 clients', fmt(at(v2,16).msgs_per_sec)+'/s', at(v2,16).msgs_per_sec/Math.max(at(b,16).msgs_per_sec, at(m,16).msgs_per_sec), 'x', 'v1 best '+fmt(Math.max(at(b,16).msgs_per_sec, at(m,16).msgs_per_sec))+'/s'],
    ['Roundtrip, median', fmtMs(v2.roundtrip_ms.p50), m.roundtrip_ms.p50/v2.roundtrip_ms.p50, 'x faster', 'v1 best '+fmtMs(m.roundtrip_ms.p50)],
    ['p99 send, 64 clients', fmtMs(at(v2,64).p99_ms), Math.min(at(b,64).p99_ms, at(m,64).p99_ms)/at(v2,64).p99_ms, 'x lower', 'v1 best '+fmtMs(Math.min(at(b,64).p99_ms, at(m,64).p99_ms))],
    ['Bytes per send', fmtBytes(v2.wire_bytes.send), Math.min(b.wire_bytes.send, m.wire_bytes.send)/v2.wire_bytes.send, 'x smaller', 'v1 best '+fmtBytes(Math.min(b.wire_bytes.send, m.wire_bytes.send))],
    ['Server CPU per message', fmtMs(v2.cpu_ms_per_msg), Math.min(b.cpu_ms_per_msg, m.cpu_ms_per_msg)/v2.cpu_ms_per_msg, 'x less', 'v1 best '+fmtMs(Math.min(b.cpu_ms_per_msg, m.cpu_ms_per_msg))],
    ['Idle memory', fmt(v2.rss_mb.idle,1)+' MB', Math.min(b.rss_mb.idle, m.rss_mb.idle)/v2.rss_mb.idle, 'x less', 'v1 best '+fmt(Math.min(b.rss_mb.idle, m.rss_mb.idle),1)+' MB'],
    ['Cold start', fmtMs(v2.cold_start_ms), Math.min(b.cold_start_ms, m.cold_start_ms)/v2.cold_start_ms, 'x faster', 'v1 best '+fmtMs(Math.min(b.cold_start_ms, m.cold_start_ms))],
    ['Lost writes in 20 crashes', fmt(D.crash.total_lost), null, '', fmt(D.crash.total_acknowledged)+' acknowledged'],
  ];
  for(const [l,v,ratio,word,d] of tiles){ const t=document.createElement('div'); t.className='kpi';
    const a=document.createElement('div'); a.className='l'; a.textContent=l; const bv=document.createElement('div'); bv.className='v'; bv.textContent=v;
    const c=document.createElement('div'); c.className='d'; if(ratio){const x=document.createElement('span'); x.className='x'; x.textContent=fmt(ratio, ratio<10?1:0)+word+' '; c.append(x);} c.append(document.createTextNode(ratio?'· '+d:d));
    t.append(a,bv,c); k.append(t); }
  document.getElementById('kpinote').textContent = 'v1 numbers are the existing Python implementations measured on the same machine with their rate limits lifted (bench/v1/README.md). v2 does strictly more work per message: post-quantum end-to-end encryption, signature checks, and a transparency-ledger append in every write.';
})();

// ---------- grouped columns: throughput
(function(){
  const c=document.getElementById('c-thr'); const lv=[1,4,16,64];
  const [s,w]=svgBox(c, 250); const L=46,R=8,T=12,B=26, H=250-T-B, PW=w-L-R;
  const max=niceMax(Math.max(...SYS.flatMap(x=>D[x.k].send_throughput.map(t=>t.msgs_per_sec))));
  const g=el('g',{class:'grid'},s); for(let i=0;i<=4;i++){const y=T+H-H*i/4; el('line',{x1:L,x2:w-R,y1:y,y2:y},g); txt(s,L-6,y+4,fmt(max*i/4),'muted','end');}
  const band=PW/lv.length, bw=Math.min(24,(band-24)/3);
  lv.forEach((l,i)=>{ const cx=L+band*i+band/2; txt(s,cx,T+H+16,l+(i===0?' client':' clients'),'', 'middle');
    SYS.forEach((sy,j)=>{ const t=D[sy.k].send_throughput.find(x=>x.concurrency===l); const v=t.msgs_per_sec; const h=H*v/max; const x=cx+(j-1)*(bw+2)-bw/2;
      const p=el('path',{d:roundTop(x,T+H-h,bw,Math.max(h,1),4),fill:'var('+sy.c+')',class:'mark'},s);
      bindTip(p,()=>[{v:fmt(v)+' msg/s',c:sy.c,l:sy.name},{v:'',l:l+' concurrent clients · p50 '+fmtMs(t.p50_ms)+' · errors '+t.errors}]);
      if(sy.k==='v2') txt(s,x+bw/2,T+H-h-5,fmt(v),'val','middle'); }); });
  el('line',{x1:L,x2:w-R,y1:T+H,y2:T+H,class:'axis'},s);
  table(c,['Concurrency',...SYS.map(x=>x.name)], lv.map(l=>[l, ...SYS.map(x=>fmt(D[x.k].send_throughput.find(t=>t.concurrency===l).msgs_per_sec))]));
})();

// ---------- line chart helper (categorical or numeric x; log or linear y)
function lineChart(c, o){
  const h=o.height||230; const [s,w]=svgBox(c,h); const L=o.left||52,R=o.right||10,T=10,B=26,H=h-T-B,PW=w-L-R;
  const ylo=o.ylo, yhi=o.yhi; const ly=v=>T+H-H*(Math.log10(v)-Math.log10(ylo))/(Math.log10(yhi)-Math.log10(ylo));
  const xs=o.x; const xlog=o.xlog; const lx = xlog ? (v=>L+PW*(Math.log10(v)-Math.log10(xs[0]))/(Math.log10(xs[xs.length-1])-Math.log10(xs[0]))) : (i=>L+PW*(i+0.5)/xs.length);
  const g=el('g',{class:'grid'},s); for(const t of logTicks(ylo,yhi)){ if(t<ylo||t>yhi) continue; const y=ly(t); el('line',{x1:L,x2:w-R,y1:y,y2:y},g); txt(s,L-6,y+4,o.yfmt(t),'muted','end'); }
  xs.forEach((x,i)=>{ const px=xlog?lx(x):lx(i); if(!o.xskip||o.xskip(x,i)) txt(s,px,T+H+16,o.xfmt(x),'','middle'); });
  el('line',{x1:L,x2:w-R,y1:T+H,y2:T+H,class:'axis'},s);
  for(const se of o.series){ const pts=se.values.map((v,i)=>v==null?null:[xlog?lx(xs[i]):lx(i), ly(Math.max(v,ylo))]);
    const d=pts.filter(Boolean).map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+','+p[1].toFixed(1)).join(''); el('path',{d,fill:'none',stroke:'var('+se.c+')','stroke-width':2,'stroke-linejoin':'round','stroke-linecap':'round'},s);
    pts.forEach((p,i)=>{ if(!p) return; el('circle',{cx:p[0],cy:p[1],r:4,fill:'var('+se.c+')',stroke:'var(--surface)','stroke-width':2},s);
      const hit=el('circle',{cx:p[0],cy:p[1],r:12,fill:'transparent',class:'mark'},s); bindTip(hit,()=>[{v:o.vfmt(se.values[i]),c:se.c,l:se.name},{v:'',l:o.xfmt(xs[i])+(o.xlabel||'')}]); });
    if(se.label){ const last=pts.filter(Boolean).pop(); txt(s,last[0]+8,last[1]+4,se.label,'val'); }
  }
  return s;
}

// ---------- p99
(function(){
  const c=document.getElementById('c-p99'); const lv=[1,4,16,64];
  lineChart(c,{x:lv, xfmt:x=>x+(x===1?' client':' clients'), ylo:0.1, yhi:10000, yfmt:fmtMs, vfmt:v=>fmtMs(v)+' p99', right:60,
    series:SYS.map(sy=>({name:sy.name,c:sy.c,values:lv.map(l=>D[sy.k].send_throughput.find(t=>t.concurrency===l).p99_ms), label:fmtMs(D[sy.k].send_throughput.find(t=>t.concurrency===64).p99_ms)}))});
  table(c,['Concurrency',...SYS.map(x=>x.name+' p50'),...SYS.map(x=>x.name+' p99')], lv.map(l=>[l,...SYS.map(x=>fmtMs(D[x.k].send_throughput.find(t=>t.concurrency===l).p50_ms)),...SYS.map(x=>fmtMs(D[x.k].send_throughput.find(t=>t.concurrency===l).p99_ms))]));
})();

// ---------- roundtrip range plot
(function(){
  const c=document.getElementById('c-rt'); const h=150; const [s,w]=svgBox(c,h); const L=150,R=70,T=8,B=24,H=h-T-B,PW=w-L-R;
  const lo=0.1,hi=1000; const lx=v=>L+PW*(Math.log10(v)-Math.log10(lo))/(Math.log10(hi)-Math.log10(lo));
  const g=el('g',{class:'grid'},s); for(const t of logTicks(lo,hi)){ const x=lx(t); el('line',{x1:x,x2:x,y1:T,y2:T+H},g); txt(s,x,T+H+16,fmtMs(t),'muted','middle'); }
  SYS.forEach((sy,i)=>{ const r=D[sy.k].roundtrip_ms; const y=T+H*(i+0.5)/3; txt(s,L-10,y+4,sy.name.replace(/ \(.*\)/,''),'','end');
    const x1=lx(r.p50), x2=lx(r.p99); el('path',{d:roundRight(x1,y-3,Math.max(x2-x1,2),6,3),fill:'var('+sy.c+')',opacity:.35},s);
    el('circle',{cx:x1,cy:y,r:5,fill:'var('+sy.c+')',stroke:'var(--surface)','stroke-width':2},s); txt(s,x2+8,y+4,fmtMs(r.p50)+' median','val');
    const hit=el('rect',{x:x1-12,y:y-12,width:Math.max(x2-x1,2)+24,height:24,fill:'transparent',class:'mark'},s);
    bindTip(hit,()=>[{v:fmtMs(r.p50)+' median',c:sy.c,l:sy.name},{v:'',l:'p90 '+fmtMs(r.p90)+' · p99 '+fmtMs(r.p99)+' · '+r.samples+' samples'}]); });
  table(c,['System','p50','p90','p99','mean'], SYS.map(x=>{const r=D[x.k].roundtrip_ms; return [x.name,fmtMs(r.p50),fmtMs(r.p90),fmtMs(r.p99),fmtMs(r.mean)];}));
  const n=document.createElement('p'); n.className='note'; n.textContent='The v1 broker hands messages to recipients on a 500 ms background poll; the v1 mailbox and v2 deliver on request. v2 includes client-side encryption, decryption and signing inside the timing.'; c.append(n);
})();

// ---------- efficiency small multiples
function hbars(c, title, rows, f, note){
  const box=document.createElement('div'); box.className='mini'; const h3=document.createElement('h3'); h3.textContent=title; box.append(h3); c.append(box);
  const h=rows.length*26+8; const [s,w]=svgBox(box,h); const L=96,R=92,PW=w-L-R; const max=Math.max(...rows.map(r=>r.v));
  rows.forEach((r,i)=>{ const y=4+i*26; txt(s,L-8,y+13,r.name,'','end'); const bw=Math.max(PW*r.v/max,2);
    const p=el('path',{d:roundRight(L,y+3,bw,14,4),fill:'var('+r.c+')',class:'mark'},s); txt(s,L+bw+6,y+14,f(r.v),'val');
    bindTip(p,()=>[{v:f(r.v),c:r.c,l:r.full||r.name}]); });
  el('line',{x1:L,x2:L,y1:2,y2:h-2,class:'axis'},s);
  if(note){const n=document.createElement('p'); n.className='note'; n.textContent=note; box.append(n);}
}
(function(){
  const c=document.getElementById('c-eff'); const short={v2:'Silk v2',v1m:'v1 mailbox',v1b:'v1 broker'};
  const rows=get=>SYS.map(sy=>({name:short[sy.k],full:sy.name,c:sy.c,v:get(D[sy.k])}));
  hbars(c,'HTTP bytes per send',rows(r=>r.wire_bytes.send),fmtBytes);
  hbars(c,'HTTP bytes per roundtrip',rows(r=>r.wire_bytes.roundtrip),fmtBytes);
  hbars(c,'Server CPU per message',rows(r=>r.cpu_ms_per_msg),fmtMs,'At 16 concurrent clients.');
  hbars(c,'Memory at idle',rows(r=>r.rss_mb.idle),v=>fmt(v,1)+' MB');
  hbars(c,'Memory peak under load',rows(r=>r.rss_mb.peak),v=>fmt(v,1)+' MB','v1 broker dropped connections at 64 clients (listen backlog 5), so it held fewer requests in flight.');
  hbars(c,'Cold start to first response',rows(r=>r.cold_start_ms),fmtMs);
  hbars(c,'Install size',rows(r=>r.install_mb),v=>fmt(v,1)+' MB','v2 is one static binary; v1 sizes are Python site-packages only, excluding the interpreter.');
  table(c,['Metric',...SYS.map(x=>x.name)],[
    ['Bytes per send',...SYS.map(x=>fmt(D[x.k].wire_bytes.send))],['Bytes per roundtrip',...SYS.map(x=>fmt(D[x.k].wire_bytes.roundtrip))],
    ['CPU ms per message',...SYS.map(x=>fmt(D[x.k].cpu_ms_per_msg,3))],['RSS idle MB',...SYS.map(x=>fmt(D[x.k].rss_mb.idle,1))],
    ['RSS peak MB',...SYS.map(x=>fmt(D[x.k].rss_mb.peak,1))],['Cold start ms',...SYS.map(x=>fmt(D[x.k].cold_start_ms,1))],['Install MB',...SYS.map(x=>fmt(D[x.k].install_mb,1))]]);
})();

// ---------- iterations (emphasis: kept steps in blue, rejected in gray)
(function(){
  const c=document.getElementById('c-iter'); const it=D.iters;
  function iterBars(title, get, f, lowerBetter){ const box=document.createElement('div'); box.className='mini'; const h3=document.createElement('h3'); h3.textContent=title; box.append(h3); c.append(box);
    const h=it.length*26+8; const [s,w]=svgBox(box,h); const L=232,R=80,PW=w-L-R; const max=Math.max(...it.map(get));
    it.forEach((r,i)=>{ const y=4+i*26; txt(s,L-8,y+13,r.name,r.rejected?'muted':'','end'); const v=get(r); const bw=Math.max(PW*v/max,2); const col=r.rejected?'--gray':'--s1';
      const p=el('path',{d:roundRight(L,y+3,bw,14,4),fill:'var('+col+')',class:'mark'},s); txt(s,L+bw+6,y+14,f(v),'val'); bindTip(p,()=>[{v:f(v),c:col,l:r.name}]); });
    el('line',{x1:L,x2:L,y1:2,y2:h-2,class:'axis'},s); }
  iterBars('Throughput, 16 clients', r=>r.throughput, v=>fmt(v)+'/s');
  iterBars('Server CPU per message', r=>r.cpu, fmtMs);
  table(c,['Iteration','msg/s @16','CPU ms/msg','peak RSS MB'], it.map(r=>[r.name,fmt(r.throughput),fmt(r.cpu,3),fmt(r.peak,1)]));
  const n=document.createElement('p'); n.className='note'; n.textContent='Iteration 1→2: replaced per-request SQLite savepoints (which wrote sub-journal pages to disk) with an in-memory undo log, and split hot-path records from large post-quantum key material. 2→3: dropped database/sql for a low-level SQLite API with cached statements; 4 OS threads measured faster and lighter than 12. bbolt was tried and rejected: it forces a full disk flush per commit on macOS and allocates heavily under load.'; c.append(n);
})();

// ---------- live
(function(){
  const c=document.getElementById('c-live'); const L=D.live, B=D.live_before_push;
  hbars(c,'Push latency: recipient already waiting', [{name:'before',full:'polling across serverless instances',c:'--gray',v:B?B.push_ms?.p50??521.1:521.1},{name:'after',full:'Postgres LISTEN/NOTIFY wakeups',c:'--s1',v:L.push_ms.p50}], fmtMs,'Median time from send until the waiting recipient has the message. The listener runs only while someone is waiting, so the free-tier database can still sleep.');
  hbars(c,'Database round trips per message', [{name:'before',full:'one query per read',c:'--gray',v:D.pg_rtt.before},{name:'after',full:'prefetch in one round trip',c:'--s1',v:D.pg_rtt.after}], v=>fmt(v,1),'Message admission on PostgreSQL (counted against a local server).');
  hbars(c,'Live request latency (median)', [{name:'send',c:'--s1',v:L.send_ms.p50},{name:'receive',c:'--s1',v:L.receive_ms.p50},{name:'acknowledge',c:'--s1',v:L.ack_ms.p50}], fmtMs,'A request that touches no database takes ~64 ms on this route (edge → function), so most of each number is network and platform overhead.');
  table(c,['Live metric','p50','p90','p99'],[['send',fmtMs(L.send_ms.p50),fmtMs(L.send_ms.p90),fmtMs(L.send_ms.p99)],['receive',fmtMs(L.receive_ms.p50),fmtMs(L.receive_ms.p90),fmtMs(L.receive_ms.p99)],['acknowledge',fmtMs(L.ack_ms.p50),fmtMs(L.ack_ms.p90),fmtMs(L.ack_ms.p99)],['push (waiting recipient)',fmtMs(L.push_ms.p50),fmtMs(L.push_ms.p90),fmtMs(L.push_ms.p99)],['send+receive+ack',fmtMs(L.roundtrip_ms.p50),fmtMs(L.roundtrip_ms.p90),fmtMs(L.roundtrip_ms.p99)]]);
})();

// ---------- spam
(function(){
  if(!D.spam) return; const c=document.getElementById('c-spam'); const bl=D.spam.blocking; const xs=bl.map(b=>b.legit_seconds_laptop);
  const series=ATK.map(a=>({name:a.name,c:a.c,values:bl.map(b=>b.attacker_seconds_to_block[a.k]),label:a.k}));
  lineChart(c,{x:xs,xlog:true,xfmt:v=>fmtSec(v),xlabel:' of laptop CPU for the legitimate sender',ylo:0.0001,yhi:100000,yfmt:fmtSec,vfmt:v=>fmtSec(v)+' of attacker compute',right:96,left:56,series,height:250});
  table(c,['Stamp bits','Legit cost (laptop)',...ATK.map(a=>a.k)], bl.map(b=>[b.legit_bits,fmtSec(b.legit_seconds_laptop),...ATK.map(a=>fmtSec(b.attacker_seconds_to_block[a.k]))]));
  const n=document.createElement('p'); n.className='note';
  n.textContent='A full request queue is an auction: a stranger evicts the cheapest pending request by paying one bit more, so holding all '+D.spam.config.queue_slots+' slots costs the attacker '+D.spam.config.queue_slots+'× the stranger\'s price, re-paid every time it is outbid. That defeats CPU- and single-GPU-scale spam; a GPU farm can still price strangers out of one recipient, which is why owners hand out single-use invites (silk invite) and trust lists. Existing conversations never queue or pay.'; c.append(n);
})();

// ---------- pow
(function(){
  if(!D.pow) return; document.getElementById('verifyns').textContent=fmt(D.pow.verify_ns)+' ns';
  const c=document.getElementById('c-pow'); const rows=D.pow.rows;
  lineChart(c,{x:rows.map(r=>r.bits),xfmt:b=>String(b),xlabel:'-bit stamp',ylo:0.1,yhi:10000,yfmt:fmtMs,vfmt:v=>fmtMs(v)+' mean',height:200,left:48,
    series:[{name:'all cores',c:'--s1',values:rows.map(r=>r.all_cores_mean_ms)},{name:'one core',c:'--s2',values:rows.map(r=>r.one_core_mean_ms||null)}]});
  table(c,['Bits','Expected hashes','All cores mean','One core mean'], rows.map(r=>[r.bits,fmt(r.expected_hashes),fmtMs(r.all_cores_mean_ms),r.one_core_mean_ms?fmtMs(r.one_core_mean_ms):'–']));
})();

// ---------- ledger
(function(){
  if(!D.ledger) return; const c=document.getElementById('c-led'); const p=D.ledger.points;
  lineChart(c,{x:p.map(x=>x.size),xlog:true,xfmt:n=>n>=1e6?fmt(n/1e6)+'M':n>=1e3?fmt(n/1e3)+'K':fmt(n),xlabel:' entries',ylo:100,yhi:1e8,yfmt:fmtBytes,vfmt:fmtBytes,height:200,left:52,
    xskip:(x,i)=>[0,2,4,p.length-1].includes(i),
    series:[{name:'Silk ledger (Merkle tree)',c:'--s1',values:p.map(x=>x.inclusion_proof_bytes)},{name:'plain hash chain',c:'--s2',values:p.map(x=>x.hash_chain_proof_bytes)}]});
  table(c,['Entries','Merkle proof','Hash-chain proof','Append µs','Verify µs'], p.map(x=>[fmt(x.size),fmtBytes(x.inclusion_proof_bytes),fmtBytes(x.hash_chain_proof_bytes),fmt(x.append_us_each,1),fmt(x.verify_inclusion_us,2)]));
})();

// ---------- crash
(function(){
  const C=D.crash; document.getElementById('crashtitle').textContent=fmt(C.total_lost)+' acknowledged messages lost in '+C.rounds.length+' kill -9 crashes';
  document.getElementById('crashsub').textContent='Relay killed with SIGKILL at a random moment under 16 concurrent senders, restarted, then every previously acknowledged message looked up on the ledger. Ledger history verified consistent across every restart: '+(C.rounds.every(r=>r.consistent)?'yes':'NO')+'.';
  const c=document.getElementById('c-crash'); const h=170; const [s,w]=svgBox(c,h); const L=46,R=8,T=10,B=26,H=h-T-B,PW=w-L-R; const rs=C.rounds;
  const max=niceMax(Math.max(...rs.map(r=>r.acknowledged))); const g=el('g',{class:'grid'},s);
  for(let i=0;i<=2;i++){const y=T+H-H*i/2; el('line',{x1:L,x2:w-R,y1:y,y2:y},g); txt(s,L-6,y+4,fmt(max*i/2),'muted','end');}
  const band=PW/rs.length, bw=Math.min(24,band-2);
  rs.forEach((r,i)=>{ const x=L+band*i+(band-bw)/2, hh=H*r.acknowledged/max; const p=el('path',{d:roundTop(x,T+H-hh,bw,Math.max(hh,1),4),fill:'var(--s1)',class:'mark'},s);
    bindTip(p,()=>[{v:fmt(r.acknowledged)+' acknowledged',c:'--s1',l:'round '+r.round},{v:'',l:'killed after '+r.killed_after_ms+' ms · lost '+r.lost+' · ledger '+fmt(r.ledger_size_before_kill)+' → '+fmt(r.ledger_size_after_restart)}]);
    if(i%4===0) txt(s,x+bw/2,T+H+16,'#'+r.round,'','middle'); });
  el('line',{x1:L,x2:w-R,y1:T+H,y2:T+H,class:'axis'},s);
  table(c,['Round','Killed after','Acknowledged','Lost','In flight','Ledger before → after','Consistent'], rs.map(r=>[r.round,r.killed_after_ms+' ms',fmt(r.acknowledged),r.lost,r.in_flight_at_kill,fmt(r.ledger_size_before_kill)+' → '+fmt(r.ledger_size_after_restart),r.consistent?'yes':'no']));
})();
</script>
</body>
</html>
"""

out = TEMPLATE.replace("__DATA__", json.dumps(data, separators=(",", ":")))
(root / "report.html").write_text(out)
print(f"wrote {root / 'report.html'} ({len(out)//1024} KB)")
