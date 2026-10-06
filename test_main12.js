

const LOGIN_HTML=`<div class="box"><h3>Sign in to FRAUD//CONTROL</h3>
<form id="lf" onsubmit="event.preventDefault();login()">
<label>Email<input type="email" id="lemail" required autocomplete="username"></label>
<label>Password<input type="password" id="lpass" required autocomplete="current-password"></label>
<label>Role<select id="lrole"><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></label>
<div class="row-f"><button type="submit" class="p">Sign in</button></div>
<div id="lerr" class="tag crit" style="display:none"></div></form></div>`;

const PAGES=[
["start","Start Here","0",["overview","What FRAUD//CONTROL is and the first things to try"],
 {"what":"Your entry point: a short, task-oriented map of the whole console.",
  "how":["Pick a task below or press its hotkey.","Or open the Command Palette (Cmd+K) and type."],
  "controls":"Each card links directly to the view it describes.",
  "calm":"All health dots green; baseline drift < 5%; bus lag < 50 ms.",
  "worry":"Any component shows red or baseline drift > 15%.",
  "tips":["Bookmark #/start to land here after login.","Press ? anywhere for contextual help."],
  "related":["cmd","alerts","analytics"]}],
["cmd","Command Center","1",["overview","Live traffic, triage queue, and system health"],
 {"what":"Real-time stream of decisions with instant drill-down.",
  "how":["Watch the feed.","Click a row -> event drawer.","Filter by level / campaign / user."],
  "controls":"Pause toggles live updates. Filters persist in the URL.",
  "calm":"Steady flow; CRITICAL < 1% of traffic.",
  "worry":"Sudden spike in CRITICAL or bus lag > 200 ms.",
  "tips":["Shift-click to open multiple drawers.","Drag the drawer edge to resize."],
  "related":["alerts","user","logs"]}],
["alerts","Alert Center","2",["overview","Every HIGH / CRITICAL decision that crossed the alert threshold"],
 {"what":"Curated list of events that need human attention.",
  "how":["Open an alert -> investigation.","Mark acknowledged / resolved.","Block all entities from an incident."],
  "controls":"Filter by status, level, time. Column sort by clicking headers.",
  "calm":"Alert rate matches baseline; most alerts get acknowledged within SLA.",
  "worry":"Alert flood or many unacknowledged > 30 min.",
  "tips":["Use the incident link to see the full cluster.","Bulk-acknowledge from the API."],
  "related":["cmd","incidents","user"]}],
["user","Investigations","3",["investigation","Per-user and per-alert deep dives"],
 {"what":"Full context for one identity: timeline, graph, recommendations, block actions.",
  "how":["Search a user id.","Switch between Event / Graph / Recommendations tabs.","Block / unblock entities."],
  "controls":"Tabs keep their state in the URL. Time window selector top-right.",
  "calm":"Single user, low risk, no graph clusters.",
  "worry":"Multiple devices / IPs / campaigns; graph cluster size > 10.",
  "tips":["Graph shows shared device / IP / subnet edges.","Export the report as JSON."],
  "related":["alerts","incidents","cmd"]}],
["incidents","Incidents","4",["analysis","Merged clusters of related HIGH / CRITICAL activity"],
 {"what":"Automatic correlation: same user / device / IP / subnet / campaign-attack window.",
  "how":["Open an incident -> combined view.","Block all entities with one click.","Watch the timeline for recurrence."],
  "controls":"Status filter (open / closed). Click an incident id for the detail page.",
  "calm":"Incidents close after 5 min of inactivity; no new merges.",
  "worry":"Incident keeps re-opening; campaign+attack merge fires repeatedly.",
  "tips":["Incident summary lists top reasons and rules.","Block-all records the incident id on every entity."],
  "related":["alerts","user","combined","patterns"]}],
["analytics","Combined Analysis","5",["analysis","Cross-layer signal merge: worst clusters, totals, trend"],
 {"what":"One screen that groups every suspicious decision by its strongest shared attribute.",
  "how":["Pick a time window.","Sort clusters by peak risk or volume.","Drill into a cluster -> incident or user."],
  "controls":"Min-risk slider; time window; limit selector.",
  "calm":"Few clusters, low peak risk, steady timeline.",
  "worry":"A single cluster dominates volume or risk; trend climbing.",
  "tips":["Clusters use campaign -> advert -> device -> fallback.","Export clusters as CSV."],
  "related":["incidents","target","search"]}],
["target","Targeted Analysis","6",["analysis","Who is being targeted, which campaigns, and the cost"],
 {"what":"Victim-centric view: high-risk users, the campaigns hitting them, and clean traffic for contrast.",
  "how":["Adjust the look-back window.","Click a victim -> investigation.","Compare wasted vs clean spend."],
  "controls":"Since-minutes; limit. Campaign filter via URL.",
  "calm":"Wasted clicks near zero; victims list empty.",
  "worry":"Many victims; wasted clicks rising; clean campaigns contaminated.",
  "tips":["Wasted spend is a proxy for budget loss.","Save the view as a recurring report."],
  "related":["combined","campaigns","search"]}],
["campaigns","Campaign Analytics","7",["analysis","Campaign-level performance and risk breakdown"],
 {"what":"Aggregate stats per campaign: clicks, users, risk, criticals.",
  "how":["Sort by criticals to find the riskiest campaigns.","Drill into a campaign -> targeted analysis."],
  "controls":"Time window; sort columns.",
  "calm":"All campaigns low risk; criticals zero.",
  "worry":"A campaign has > 5% critical rate or sudden volume jump.",
  "tips":["Cross-reference with the advertiser's own dashboards.","Use the campaign id in targeted analysis."],
  "related":["target","combined","search"]}],
["logs","Event Logs","8",["analysis","Searchable, filterable log of every decision"],
 {"what":"Raw decision feed with full filters: level, user, campaign, source, run id, free text.",
  "how":["Apply filters.","Click a row -> event drawer.","Export visible rows as CSV."],
  "controls":"All filters persist in the URL. Pagination via limit / before cursor.",
  "calm":"Expected volume; familiar distributions.",
  "worry":"Sudden new source / run id; level distribution shifts.",
  "tips":["Combine level=CRITICAL with campaign to isolate a burst.","Save the filter URL for recurring checks."],
  "related":["cmd","analytics","saved"]}],
["patterns","Pattern Library","9",["analysis","Analyst-authored signatures that label (never block) recurring schemes"],
 {"what":"Saved patterns classify HIGH/CRITICAL decisions. Two+ conditions required; max 200 patterns.",
  "how":["Create a pattern from the built-in conditions or custom numeric rules.","Preview against history before saving.","Hits are counted per pattern."],
  "controls":"Name / description / action (label / alert). Condition builder with field / op / value.",
  "calm":"Patterns match known schemes; hit counts stable.",
  "worry":"A pattern suddenly spikes; a built-in condition you disabled is now firing.",
  "tips":["Preview shows up to 10 matching events.","Hits are recorded per event for trend charts."],
  "related":["incidents","analytics","target"]}],
["saved","Saved Attacks","10",["analysis","Named, replayable scenarios for testing and regression"],
 {"what":"Give any simulation a name, notes, tags. Replay at any speed, duplicate, compare, export / import JSON.",
  "how":["Run a simulation -> Save -> name it.","Replay from the list (1x .. 50x).","Compare two runs side by side."],
  "controls":"Name (required), notes, tags. Confirm on delete.",
  "calm":"Saved attacks replay cleanly; level counts match original.",
  "worry":"Replay produces different counts -> schema drift or model change.",
  "tips":["Export JSON to share with other environments.","Import creates a new saved attack automatically."],
  "related":["logs","analytics","cmd"]}],
["search","Search","11",["analysis","One box across users, campaigns, adverts, devices, incidents, alerts"],
 {"what":"Instant cross-index search. Type a user id, campaign, advert, device, incident id, or alert text.",
  "how":["Type in the palette or the search page.","Results grouped by type. Click to jump."],
  "controls":"Debounced; minimum 1 character.",
  "calm":"Query returns expected handful of rows.",
  "worry":"No results for a known id -> data gap or filter issue.",
  "tips":["Press Cmd+K anywhere to open the palette with your query pre-filled.","Results link directly to investigations."],
  "related":["user","campaigns","incidents","alerts"]}],
["models","Model Monitor","12",["ml","Drift, importance, retrain / rollback"],
 {"what":"PSI drift, feature importance, version history, one-click retrain or rollback.",
  "how":["Watch the drift bar.","Retrain when PSI > 0.2.","Rollback if new version degrades."],
  "controls":"Baseline reset button (admin only).",
  "calm":"PSI < 0.1; importance stable.",
  "worry":"PSI > 0.2 or retrain fails validation.",
  "tips":["Retrain uses the same split config; version bump is automatic.","Rollback is instant and audited."],
  "related":["pipeline","settings"]}],
["pipeline","Pipeline","13",["ml","Layer status, weights, latency, quality gates"],
 {"what":"Live component health: rules, ML, anomaly, graph, online; weights and latency per layer.",
  "how":["Watch component states.","Renormalised weights shown when a layer fails.","Quality gate pass / fail."],
  "controls":"Refresh interval top-right.",
  "calm":"All green; weights near default; latency p95 < 30 ms.",
  "worry":"Any component degraded; ML weight dropped to 0.",
  "tips":["System events log every component flip.","Online learner window size in settings."],
  "related":["models","cmd","settings"]}],
["blocklist","Blocklist","14",["admin","Manual and automatic blocks with reasons"],
 {"what":"Every active block: entity type, id, reason, score, who/when, incident link.",
  "how":["Filter by type / source.","Unblock (confirm).","See which incident caused an auto-block."],
  "controls":"Sortable columns; auto-blocks show 'engine' as author.",
  "calm":"Block count stable; reasons clear.",
  "worry":"Rapid growth; many blocks without incident id (orphaned).",
  "tips":["Unblocking clears the in-memory set immediately.","Audit log records every block / unblock."],
  "related":["incidents","alerts","cmd"]}],
["rules","Rules","15",["admin","Rule editor: conditions, weights, activation"],
 {"what":"Create / edit / toggle rules. Each rule has conditions, a weight, and an enabled flag.",
  "how":["Add a rule -> set conditions -> weight -> enable.","Test against recent traffic before enabling.","Disable instead of deleting for history."],
  "controls":"Weight 0..1; condition field / op / value builder.",
  "calm":"Rules fire as expected; no stale rules enabled.",
  "worry":"Many rules fire on the same events (overlap).",
  "tips":["Rules are evaluated before ML; they can force BLOCK.","Export / import rule sets as JSON."],
  "related":["settings","models","pipeline"]}],
["settings","Settings","16",["admin","System, security, AI, retention, login limits"],
 {"what":"Central configuration: risk thresholds, retention windows, login rate, AI provider, keys.",
  "how":["Edit a value -> Save (audited).","Test AI connection before saving.","Reset to defaults via button."],
  "controls":"Inline validation; confirmation on destructive changes.",
  "calm":"All settings saved; AI test green.",
  "worry":"AI test fails; retention too short for compliance.",
  "tips":["Login rate limit is per-minute per IP.","Risk.auto_block toggles engine auto-blocking."],
  "related":["rules","models","pipeline"]}],
["datarst","Data & Reset","17",["admin","Scoped, previewed, audited data clearing"],
 {"what":"Choose exactly what to clear: events, alerts, incidents, recommendations, live state, blocklist, learning, saved attacks, patterns. Presets for network / factory reset. Never clears users, audit, models, API keys.",
  "how":["Open preview -> confirm -> Execute.","Select individual scopes or a preset.","Audit log entry created automatically."],
  "controls":"Preview shows per-scope row counts. Confirm checkbox required.",
  "calm":"Preview counts match expectations; preserved tables untouched.",
  "worry":"Preview shows zero for a scope you expected to clear.",
  "tips":["Factory reset is the only scope that touches blocklist + learning.","Use the CLI script for CI pipelines."],
  "related":["settings","blocklist","saved"]}]
]

// Build VIEWS (for nav rendering) and ROUTES / VIEW_ROUTE from PAGES
const VIEWS=PAGES.map(p=>[p[0],p[1],p[2]])
function navItem(v){return '<a data-v="'+v[0]+'" tabindex="0" onclick="go("user")" onkeydown="if(event.key===\'Enter\')go("user")">'+v[1]+'<kbd>'+v[2]+'</kbd></a>'};const groupOrder=[["overview",["start","cmd","alerts","user"]],["analysis",["incidents","analytics","target","campaigns","logs","patterns","saved","search"]],["ml",["models","pipeline"]],["admin",["blocklist","rules","settings","datarst"]]]
$('#nav').innerHTML=groupOrder.map(([title,keys])=>title?'<h6>'+title.toUpperCase()+'</h6>':'').join('')+groupOrder.map(([,keys])=>keys.map(k=>navItem(VIEWS.find(v=>v[0]===k))).join('')).join('')

const ROUTES={}
const VIEW_ROUTE={}
for(const [key,label,hotkey,route,help] of PAGES){
  if(route[0]){ROUTES[route[0]]=route;VIEW_ROUTE[key]=route[0]}
  if(route[1]){ROUTES[route[1]]=route;VIEW_ROUTE[key]=route[1]}
}
ROUTES["#/command"]=ROUTES["#/command"]||["cmd"];
VIEW_ROUTE["cmd"]=VIEW_ROUTE["cmd"]||"#/command"

// ---------- Routing ----------
function go(v,arg,opts){const base=VIEW_ROUTE[v]||'#/command';let h=base;
 if(v==='user'&&arg)h=arg.startsWith('alert:')?base+'/alert/'+encodeURIComponent(arg.slice(6)):base+'/user/'+encodeURIComponent(arg);
 if(v==='campaigns'&&arg)h='#/analysis/target/campaign/'+encodeURIComponent(arg);
 if(v==='analytics'&&arg==='combined')h='#/analysis/combined';
 if(v==='incident'&&arg)h='#/incident/'+encodeURIComponent(arg);
 if(v==='target'&&arg)h='#/analysis/target/campaign/'+encodeURIComponent(arg);
 if(v==='patterns'&&arg)h='#/analysis/patterns/'+encodeURIComponent(arg);
 if(v==='saved'&&arg)h='#/attack/saved/'+encodeURIComponent(arg);
 if(location.hash===h){applyRoute()}else location.hash=h;if(opts&&opts.now)applyRoute()}
function routeHash(){return (location.hash||'').split('?')[0].replace(/\/+$/,'')||''}
function routeArgs(){const q=(location.hash||'').split('?')[1]||'';return Object.fromEntries(new URLSearchParams(q))}
function onRoute(){const h=routeHash();const key=Object.keys(ROUTES).filter(k=>h===k||h.startsWith(k+'/')).sort((a,b)=>b.length-a.length)[0];
  const r=ROUTES[key]||['cmd'];const seg=key?decodeURIComponent(h.slice(key.length+1)):'';
  $$('#nav a').forEach(a=>a.classList.toggle('on',a.dataset.v===S.view));S.timers.forEach(clearInterval);S.timers=[];closeDrawer();
  if(r[1]==='campaign'||r[1]==='target')S.campaignFilter=seg;else S.campaignFilter='';
  if(r[1]==='incident')S.incidentId=seg;else S.incidentId='';
  if(r[1]==='pattern')S.patternId=seg;else S.patternId='';
  if(r[1]==='saved')S.savedId=seg;else S.savedId='';
  S.routeArgs=routeArgs();render();if(r[1]==='alert')resolveAlertRoute(seg)}
function applyRoute(){onRoute()}
async function resolveAlertRoute(id){try{const all=await api('/api/alerts?limit=500');const a=all.find(x=>String(x.id)===String(id));
  if(a&&a.user_id){S.suppressHash=true;location.hash='#/investigation/user/'+encodeURIComponent(a.user_id);S.suppressHash=false;onRoute()}
  else{toast('That alert has no user attached');go("user")}}catch(e){toast(e.message);go("user")}}
async function investigateAlert(id){await resolveAlertRoute(id)}
addEventListener('hashchange',()=>{if(!S.suppressHash)onRoute()})
addEventListener('keydown',e=>{if(e.key==='?'&&e.target.tagName!=='INPUT'&&e.target.tagName!=='TEXTAREA'){e.preventDefault();openHelp(S.view)}})

// ---------- Helpers ----------
const LC={LOW:'ok',MEDIUM:'warn',HIGH:'hi',CRITICAL:'crit'};

/* ---------------- header / footer ---------------- */
function renderSys(){const h=S.health,s=S.stats;if(!h)return;
  const c=h.components,d=k=>`<span><span class="dot ${esc(c[k]?.state)}"></span>${k}</span>`;
  $('#sys').innerHTML=`<span><span class="dot ${esc(h.status)}"></span>SYSTEM ${esc(h.status)}</span>`+
   ['bus','state','database','ml','anomaly','graph','online','agent'].concat(c.neo4j?['neo4j']:[]).map(d).join('')+`<span class="muted">${esc(h.mode)}</span>`;
  if(s)$('#foot').textContent=`model ${s.model_version} | ${fmt(s.events_per_sec,1)} ev/s | p50 ${s.latency_ms.p50}ms p95 ${s.latency_ms.p95}ms | bus ${s.bus.mode} lag ${s.bus.lag} | drift ${s.drift_events} | online-learned ${s.online_learned} | uptime ${fmt(s.uptime_s)}s`}

/* ---------------- Command Center ---------------- */


// ---------- Auth ----------
function ensureAuth(){
  const t=localStorage.getItem("aegis_token");
  if(!t){showLogin();return Promise.resolve(false)}
  return api("/api/me").then(r=>{Auth.token=t;Auth.email=r.email;Auth.role=r.role;return true})
         .catch(()=>{localStorage.removeItem("aegis_token");showLogin();return false});
}
function showLogin(){$('#login').innerHTML=LOGIN_HTML;$('#login').classList.add("on");$('#lemail').focus()}
function hideLogin(){$('#login').classList.remove("on")}
async function login(){
  const e=$('#lemail').value.trim(),p=$('#lpass').value,r=$('#lrole').value;
  $('#lerr').style.display="none";
  try{
    const res=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:e,password:p,role:r})});
    Auth.token=res.token;Auth.email=res.email;Auth.role=res.role;
    localStorage.setItem("aegis_token",res.token);
    hideLogin();window.onAuthed();
  }catch(err){$('#lerr').textContent=err.message;$('#lerr').style.display="block"}}
function logout(){Auth.token="";Auth.email="";Auth.role="viewer";localStorage.removeItem("aegis_token");S.ws&&S.ws.close();location.reload()}

// ---------- State ----------
const S={view:'cmd',events:[],paused:false,filter:'',lvl:'',stats:null,health:null,series:[],lastSec:0,acc:{n:0,sum:0,max:0},fresh:new Set(),ws:null,userId:'',timers:[],pending:[],campaignFilter:'',incidentId:'',patternId:'',savedId:'',routeArgs:{},suppressHash:false};

// ---------- Boot ----------
function vCmd(m){
  m.innerHTML=`<div class="kpis" id="kpis"></div>
  <div class="grid g2"><div class="panel"><h3>LIVE EVENT STREAM <span class="row-f"><input id="flt" placeholder="filter user/ad/campaign (/)" value="${esc(S.filter)}" style="width:210px">
   <select id="lvl" aria-label="Level"><option value="">all levels</option>${['MEDIUM','HIGH','CRITICAL'].map(l=>`<option ${S.lvl===l?'selected':''}>${l}</option>`).join('')}</select>
   <button id="pbtn">${S.paused?'RESUME':'PAUSE'}</button><button id="xbtn">EXPORT</button></span></h3>
   <div class="scroll" style="max-height:440px"><table><thead><tr><th>TIME</th><th>USER</th><th>AD</th><th>CAMPAIGN</th><th>RISK</th><th>LEVEL</th><th>ACTION</th></tr></thead><tbody id="tb"></tbody></table><div id="emp" class="empty" style="display:none">NO EVENTS YET<br><span class="hint">Open the <a href="/sim" target="_blank">Ad Network Simulator</a> and start traffic.</span></div></div></div>
  <div style="display:grid;gap:10px;align-content:start"><div class="panel"><h3>OPEN ALERTS</h3><div class="scroll" style="max-height:200px" id="almini"></div></div>
   <div class="panel"><h3>TOP RISK USERS</h3><div class="scroll" style="max-height:200px" id="topu"></div></div></div></div>
  <div class="grid g22" style="margin-top:10px"><div class="panel"><h3>RISK TIMELINE <span class="hint">avg (blue) / max (red) risk per second</span></h3><canvas id="tl" height="120"></canvas></div>
  <div class="panel"><h3>RISK DISTRIBUTION</h3><div class="body" id="dist"></div></div></div>`;
  $('#flt').oninput=e=>{S.filter=e.target.value.toLowerCase();drawStream(true)};$('#lvl').onchange=e=>{S.lvl=e.target.value;drawStream(true)};
  $('#pbtn').onclick=togglePause;$('#xbtn').onclick=exportCsv;
  drawKpis();drawStream(true);drawDist();drawTl();
  every(()=>safe($('#topu'),async()=>{const r=await api('/api/fraud/top-users?limit=8');$('#topu').innerHTML=r.length?`<table>${r.map(u=>`<tr class="row" onclick="go("user","${esc(u.user_id)}")"><td class="m">${esc(u.user_id)}</td><td class="m">${(u.max_risk).toFixed(2)}</td><td class="muted">${u.flagged} flagged</td></tr>`).join('')}</table>`:'<div class="empty">No data yet</div>'}),4000);
  every(()=>safe($('#almini'),async()=>{const r=await api('/api/alerts?status=open&limit=6');$('#almini').innerHTML=r.length?r.map(a=>`<div style="padding:6px 10px;border-top:1px solid var(--bd)">${tag(a.severity)} ${esc(a.title)}<div class="hint">${hms(a.ts)}</div></div>`).join(''):'<div class="empty">NO ACTIVE FRAUD ALERTS<br><span class="hint">No critical threats detected.</span></div>'}),4000);
}
function drawKpis(){const el=$('#kpis');if(!el||!S.stats)return;const s=S.stats;
  const k=(l,v,sub='')=>`<div class="kpi"><label>${l}</label><b>${v}</b><br><small>${sub}</small></div>`;
  el.innerHTML=k('EVENTS / SEC',fmt(s.events_per_sec,1),`total ${fmt(s.total_events)}`)+k('FRAUD RATE',pct(s.fraud_rate,2),`${fmt(s.flagged)} flagged`)+
   k('BLOCKED',fmt(s.blocked_users),`${fmt(s.rejected)} rejected clicks`)+k('ACTIVE USERS',fmt(s.active_users),`${s.active_campaigns} campaigns`)+
   k('AVG DETECTION',s.latency_ms.avg+'ms',`p95 ${s.latency_ms.p95}ms`)+k('MODEL',esc(s.model_version),`${s.online_learned} online updates`)}
function matches(e){if(S.lvl==='MEDIUM'){if(e.level==='LOW')return false}else if(S.lvl&&e.level!==S.lvl)return false;
  return !S.filter||(e.user+' '+e.ad+' '+e.campaign+' '+e.ip).toLowerCase().includes(S.filter)}
function rowHtml(e,fresh){return `<tr class="row ${fresh?'new':''}" tabindex="0" onclick="openEvent("${esc(e.id)}")" onkeydown="if(event.key===\'Enter\')openEvent('${esc(e.id)}')">
 <td class="m">${hms(e.ts)}</td><td class="m">${esc(e.user)}</td><td class="m">${esc(e.ad)}</td><td class="m">${esc(e.campaign)}</td><td class="m">${e.risk.toFixed(3)}</td><td>${tag(e.level)}</td><td>${tag(e.action)}</td></tr>`}
function drawStream(full){const tb=$('#tb');if(!tb)return;const list=S.events.filter(matches).slice(0,120);
  $('#emp').style.display=S.events.length?'none':'block';
  tb.innerHTML=list.map(e=>rowHtml(e,!full&&S.fresh.has(e.id))).join('');S.fresh.clear()}
function togglePause(){S.paused=!S.paused;const b=$('#pbtn');if(b)b.textContent=S.paused?'RESUME':'PAUSE';toast(S.paused?'Stream paused':'Stream resumed');
  if(!S.paused&&S.pending.length){S.events=S.pending.concat(S.events).slice(0,400);S.pending=[];drawStream(true)}}
function exportCsv(){const rows=[['time','user','ad','campaign','risk','level','action'],...S.events.filter(matches).map(e=>[hms(e.ts),e.user,e.ad,e.campaign,e.risk,e.level,e.action])];
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([rows.map(r=>r.join(',')).join('\n')],{type:'text/csv'}));a.download='aegis_events.csv';a.click()}
function drawDist(){const el=$('#dist');if(!el||!S.stats)return;const L=S.stats.levels||{},t=Math.max(1,Object.values(L).reduce((a,b)=>a+b,0));
  el.innerHTML=['LOW','MEDIUM','HIGH','CRITICAL'].map(l=>`<div class="row-f" style="margin:5px 0"><span style="width:80px">${tag(l)}</span><div class="bar" style="flex:1"><i style="width:${100*(L[l]||0)/t}%;background:var(--${LC[l]})"></i></div><span class="m" style="width:70px;text-align:right">${fmt(L[l]||0)}</span></div>`).join('')}
function drawTl(){const c=$('#tl');if(!c)return;const w=c.width=c.clientWidth*devicePixelRatio,h=c.height=120*devicePixelRatio,x=c.getContext('2d');x.clearRect(0,0,w,h);
  x.strokeStyle='#20262D';x.lineWidth=1;for(let i=0;i<=4;i++){x.beginPath();x.moveTo(0,h*i/4);x.lineTo(w,h*i/4);x.stroke()}
  const d=S.series.slice(-120);if(d.length<2)return;const line=(key,col)=>{x.strokeStyle=col;x.lineWidth=1.5*devicePixelRatio;x.beginPath();d.forEach((p,i)=>{const X=w*i/(d.length-1),Y=h-(h-4)*p[key];i?x.lineTo(X,Y):x.moveTo(X,Y)});x.stroke()};
  line('max','#e5484d');line('avg','#4aa3d8')}
function track(items){for(const e of items){const sec=Math.floor(Date.now()/1000);if(sec!==S.lastSec){if(S.acc.n)S.series.push({avg:S.acc.sum/S.acc.n,max:S.acc.max});S.acc={n:0,sum:0,max:0};S.lastSec=sec}S.acc.n++;S.acc.sum+=e.risk;S.acc.max=Math.max(S.acc.max,e.risk)}
  if(S.series.length>300)S.series.splice(0,100)}

/* ---------------- Event drawer ---------------- */
function closeDrawer(){$('#drawer').classList.remove('open')}
function factorBars(f){if(!f||!f.length)return '<div class="hint">No attribution available (rules-only / reduced confidence).</div>';
  const mx=Math.max(...f.map(x=>Math.abs(x.contribution||0)),0.001);
  return f.map(x=>x.contribution==null?`<div class="row-f"><span>${esc(x.label)}</span></div>`:`<div style="margin:5px 0"><div class="row-f" style="justify-content:space-between"><span>${esc(x.label)}</span><span class="m">${x.contribution>0?'+':''}${x.contribution.toFixed(3)}</span></div>
   <div class="bar ${x.contribution>=0?'pos':'neg'}"><i style="width:${100*Math.abs(x.contribution)/mx}%"></i></div><div class="hint m">value ${esc(x.value)} | typical legit ${esc(x.typical)}</div></div>`).join('')}
async function openEvent(id){const d=$('#drawer');d.classList.add('open');d.innerHTML='<div class="skeleton">loading...</div>';
  let r=null;try{r=await api('/api/fraud/events/'+encodeURIComponent(id))}catch{}
  const mem=S.events.find(e=>e.id===id)||S.pending.find(e=>e.id===id);
  if(!r&&!mem){d.innerHTML='<div class="empty">Event not found</div>';return}
  const sc=(r?r.scores:mem.scores)||{},risk=r?r.risk:mem.risk,lvl=r?r.level:mem.level,act=r?r.action:mem.action,fac=(r&&r.factors&&r.factors.length?r.factors:(mem&&mem.factors))||[],user=r?r.user_id:mem.user;
  const bar=(l,v)=>v==null?`<div class="row-f" style="margin:3px 0"><span style="width:80px" class="muted">${l}</span><span class="muted">unavailable</span></div>`:`<div class="row-f" style="margin:3px 0"><span style="width:80px" class="muted">${l}</span><div class="bar ai" style="flex:1"><i style="width:${v*100}%"></i></div><span class="m" style="width:50px;text-align:right">${v.toFixed(3)}</span></div>`;
  d.innerHTML=`<div class="row-f" style="justify-content:space-between"><b class="m">${esc(id)}</b><button onclick="closeDrawer()" aria-label="Close">Esc</button></div>
  <div class="risk" style="color:var(--${LC[lvl]||'tx'})">${(risk*100).toFixed(2)}</div><div>${tag(lvl)} ${tag(act)} <span class="muted">confidence ${esc(r?r.confidence:mem.conf)}</span></div>
  <h4>MODEL SCORES</h4>${bar('Rules',sc.rules)}${bar('ML (NN+GB)',sc.ml)}${bar('Online',sc.online)}${bar('Anomaly',sc.anomaly)}${bar('Graph',sc.graph)}
  <h4>WHY? <span class="ai">${esc(r?r.explanation_method||'':'')}</span></h4>${factorBars(fac)}${r&&r.explanation_text?`<div class="hint" style="margin-top:6px">${esc(r.explanation_text)}</div>`:''}
  <h4>DETAILS</h4><div class="kv"><span>user</span><span class="m">${esc(user)}</span><span>ad / campaign</span><span class="m">${esc(r?r.ad_id:mem.ad)} / ${esc(r?r.campaign_id:mem.campaign)}</span>
  <span>device</span><span class="m">${esc(r?r.device_id:mem.device)}</span><span>ip</span><span class="m">${esc(r?r.ip_mask:mem.ip)}</span><span>rules fired</span><span class="m">${esc(((r?r.rules:mem.rules)||[]).join(', ')||'none')}</span>
  <span>model</span><span class="m">${esc(r?r.model_version:'-')}</span><span>latency</span><span class="m">${esc(r?r.latency_ms:mem.lat)} ms</span></div>
  <h4>ACTIONS</h4><div class="row-f"><button onclick="go("user","${esc(user)}")">OPEN USER</button><button class="d" onclick="blockUser("${esc(user)}")">BLOCK USER</button>
  <button onclick="fb("${esc(id)}",1)">MARK FRAUD</button><button onclick="fb("${esc(id)}",0)">MARK LEGIT</button></div>`}
async function blockUser(u){if(!confirm('Block '+u+'?'))return;try{await api('/api/blocked',{method:'POST',body:{entity_type:'user',entity_id:u,reason:'manual block from control center'}});toast('USER '+u+' BLOCKED',true)}catch(e){toast(e.message)}}
async function fb(id,l){try{const r=await api('/api/feedback',{method:'POST',body:{event_id:id,label:l}});toast('Feedback learned (online updates: '+r.online_learned+')')}catch(e){toast(e.message)}}

/* ---------------- Investigation ---------------- */
function vUser(m){m.innerHTML=`<div class="panel"><h3>USER INVESTIGATION <span class="row-f"><input id="uq" placeholder="user id e.g. U001" value="${esc(S.userId)}"><button class="p" id="ugo">OPEN</button></span></h3><div id="ubody" class="body"><div class="empty">Enter a user id.</div></div></div>`;
  $('#ugo').onclick=()=>{S.userId=$('#uq').value.trim();loadUser()};$('#uq').onkeydown=e=>{if(e.key==='Enter')$('#ugo').click()};if(S.userId)loadUser()}
async function loadUser(){const el=$('#ubody');if(!el)return;el.innerHTML='<div class="skeleton">loading...</div>';
  try{const r=await api('/api/fraud/users/'+encodeURIComponent(S.userId));const d=r.decision,f=r.features||{},p=r.profile||{};
   const ev=(r.events||[]);
   el.innerHTML=`<div class="row-f" style="justify-content:space-between"><div><b class="m" style="font-size:18px">${esc(r.user_id)}</b> ${d?tag(d.level):''} ${r.blocked?tag('BLOCKED'):''}</div>
    <div class="row-f"><button class="p" id="inv">AI / RULE INVESTIGATION</button>${r.blocked?`<button onclick="unblock("user",'${esc(r.user_id)}')">UNBLOCK</button>`:`<button class="d" onclick="blockUser("${esc(r.user_id)}")">BLOCK</button>`}</div></div>
    <div class="grid g3" style="margin-top:10px"><div class="panel"><h3>PROFILE</h3><div class="body kv"><span>device</span><span class="m">${esc(p.device_id)}</span><span>ip</span><span class="m">${esc(p.ip)}</span><span>country</span><span>${esc(p.country)}</span><span>account age</span><span class="m">${esc(p.account_age_days)}d</span><span>user agent</span><span class="m" style="white-space:normal">${esc(p.user_agent)}</span></div></div>
    <div class="panel"><h3>BEHAVIOR</h3><div class="body kv">${['clicks_1m','clicks_5m','avg_interval','min_interval','unique_ads_1h','unique_ips_per_device','unique_devices_per_ip','repeat_ad_ratio'].map(k=>`<span>${k}</span><span class="m">${f[k]==null?'-':(+f[k]).toFixed(2)}</span>`).join('')}</div></div>
    <div class="panel"><h3>LATEST DECISION</h3><div class="body">${d?`<div class="risk">${(d.risk*100).toFixed(1)}</div>${reasonBlock({reason:d.reason,reason_title:d.reason_title,event_id:d.event_id||d.id,user_id:r.user_id,rules:d.rules})}${factorBars(d.factors)}`:'<span class="muted">n/a</span>'}</div></div></div>
    <div id="invout"></div><div class="panel" style="margin-top:10px"><h3>COORDINATION GRAPH <span class="hint">U user / D device / I ip / S subnet, linked by shared resources</span></h3><canvas id="gc" height="260" style="height:260px"></canvas></div>
    <div class="panel" style="margin-top:10px"><h3>EVENT TIMELINE</h3><div class="scroll"><table><thead><tr><th>TIME</th><th>AD</th><th>CAMPAIGN</th><th>RISK</th><th>LEVEL</th><th>ACTION</th></tr></thead><tbody>${ev.slice(0,60).map(e=>`<tr class="row" onclick="openEvent("${esc(e.event_id)}")"><td class="m">${hms(e.ts)}</td><td class="m">${esc(e.ad_id)}</td><td class="m">${esc(e.campaign_id)}</td><td class="m">${e.risk.toFixed(3)}</td><td>${tag(e.level)}</td><td>${tag(e.action)}</td></tr>`).join('')}</tbody></table></div></div>`;
   $('#inv').onclick=async()=>{$('#invout').innerHTML='<div class="skeleton">investigating...</div>';try{const i=await api('/api/investigate/'+encodeURIComponent(r.user_id),{method:'POST'});
     $('#invout').innerHTML=`<div class="panel" style="margin-top:10px;border-color:#3b3366"><h3><span class="ai">INVESTIGATION REPORT</span><span class="tag ${i.mode==='llm'?'LOW':'MEDIUM'}">${i.mode==='llm'?'LLM AGENT':'RULE-BASED MODE (agent unavailable)'}</span></h3><div class="body"><b>${esc(i.attack_type)}</b> &middot; confidence ${(i.confidence*100).toFixed(0)}%<p>${esc(i.summary)}</p>${i.event_id?`<div class="hint m">Source event: <a href="#/investigation/user/${encodeURIComponent(r.user_id)}" onclick="go("user","${esc(r.user_id)}");return false">${esc(i.event_id)}</a></div>`:''}
      <div class="row-f">Recommendation: ${tag(i.recommendation.toUpperCase())}<button class="d" onclick="decide(${i.recommendation_id},'approve')">APPROVE</button><button onclick="decide(${i.recommendation_id},'reject')">REJECT</button></div><div class="hint">Recommendations never execute without human approval.</div></div></div>`}catch(e){$('#invout').innerHTML=`<div class="empty">${esc(e.message)}</div>`}};
   drawGraph(r.graph)}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
async function decide(id,dc){try{await api(`/api/recommendations/${id}/${dc}`,{method:'POST'});toast('Recommendation '+(dc==='approve'?'approved':'rejected'));loadUser()}catch(e){toast(e.message)}}
function drawGraph(g){const c=$('#gc');if(!c||!g||!g.nodes.length)return;const W=c.width=c.clientWidth*devicePixelRatio,H=c.height=260*devicePixelRatio,x=c.getContext('2d');
  const col={U:'#e0782f',D:'#4aa3d8',I:'#9b87f5',S:'#59636D'},N=g.nodes.map((n,i)=>({...n,x:W/2+Math.cos(i)*W/4,y:H/2+Math.sin(i)*H/4,vx:0,vy:0})),ix=Object.fromEntries(N.map((n,i)=>[n.id,i]));
  for(let it=0;it<180;it++){for(const a of N)for(const b of N){if(a===b)continue;let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1,f=2200*devicePixelRatio/(d*d);a.vx+=dx/d*f;a.vy+=dy/d*f}
   for(const [s,t] of g.edges){const a=N[ix[s]],b=N[ix[t]];if(!a||!b)continue;let dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1,f=(d-40*devicePixelRatio)*0.02;a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f}
   for(const n of N){n.vx+=(W/2-n.x)*0.004;n.vy+=(H/2-n.y)*0.004;n.x=Math.min(W-8,Math.max(8,n.x+n.vx*0.5));n.y=Math.min(H-8,Math.max(8,n.y+n.vy*0.5));n.vx*=0.6;n.vy*=0.6}}
  x.strokeStyle='#2a323b';for(const [s,t] of g.edges){const a=N[ix[s]],b=N[ix[t]];if(a&&b){x.beginPath();x.moveTo(a.x,a.y);x.lineTo(b.x,b.y);x.stroke()}}
  for(const n of N){x.fillStyle=col[n.type]||'#888';x.beginPath();x.arc(n.x,n.y,3.5*devicePixelRatio,0,7);x.fill()}
  x.fillStyle='#89939E';x.font=`${11*devicePixelRatio}px monospace`;x.fillText(N.length+' nodes',8,H-6)}

/* ---------------- Analytics ---------------- */
function vAnalytics(m){m.innerHTML=`<div class="panel"><h3>FILTERS <span class="row-f"><select id="aw"><option value="0">all time</option><option value="5">last 5 min</option><option value="60">last hour</option><option value="1440">last day</option></select>
 <input id="ac" placeholder="campaign e.g. C10" style="width:120px"><input id="ak" placeholder="country e.g. IN" style="width:90px"><select id="al"><option value="">any level</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select><button class="p" id="ago">APPLY</button></span></h3><div id="abody" class="body"></div></div>
  <div class="panel" style="margin-top:10px"><h3>FRAUD TIMELINE <span class="row-f" id="twin">${['1m','5m','1h','24h'].map(w=>`<button data-w="${w}" class="${w===S.tw?'p':''}">LAST ${w.toUpperCase()}</button>`).join('')}</span></h3><div class="body"><canvas id="atl" height="150" style="height:150px"></canvas><div class="hint" id="atlinfo"></div></div></div>`;
  $('#ago').onclick=loadAn;$('#twin').onclick=e=>{const b=e.target.closest('button');if(b){S.tw=b.dataset.w;$$('#twin button').forEach(x=>x.classList.toggle('p',x===b));loadTl()}};loadAn();every(loadTl,5000)}
S.tw='5m';
async function loadTl(){try{const r=await api('/api/analytics/timeline?window='+S.tw);const c=$('#atl');if(!c)return;const w=c.width=c.clientWidth*devicePixelRatio,h=c.height=150*devicePixelRatio,x=c.getContext('2d');x.clearRect(0,0,w,h);
  const pts=r.points;$('#atlinfo').textContent=pts.length?`bucket ${r.bucket_s}s | ${pts.reduce((a,p)=>a+p.n,0)} events | ${pts.reduce((a,p)=>a+p.flagged,0)} flagged (red) of total (blue)`:'No events in this window yet.';if(!pts.length)return;
  const span={'1m':60,'5m':300,'1h':3600,'24h':86400}[S.tw],t1=Date.now()/1000,t0=t1-span,mx=Math.max(...pts.map(p=>p.n),1),bw=Math.max(2,w*r.bucket_s/span-1);
  for(const p of pts){const X=w*(p.t-t0)/span,H=(h-6)*p.n/mx,F=(h-6)*p.flagged/mx;x.fillStyle='#2b5d80';x.fillRect(X,h-H,bw,H);x.fillStyle='#e5484d';x.fillRect(X,h-F,bw,F)}}catch{}}
async function loadAn(){const el=$('#abody');el.innerHTML='<div class="skeleton">loading...</div>';
  const q=new URLSearchParams({since_minutes:$('#aw').value});if($('#ac').value)q.set('campaign',$('#ac').value.toUpperCase());if($('#ak').value)q.set('country',$('#ak').value.toUpperCase());if($('#al').value)q.set('min_level',$('#al').value);
  try{const a=await api('/api/analytics?'+q);a.by_device=await api('/api/analytics/devices?since_minutes='+$('#aw').value);const t=a.totals,tb=(rows,title)=>{const mx=Math.max(1,...rows.map(r=>r.n));return `<div class="panel"><h3>${title}</h3><table>${rows.map(r=>`<tr><td class="m">${esc(r.k)}</td><td style="width:45%"><div class="bar"><i style="width:${100*r.n/mx}%"></i>${r.flagged!=null?`<i style="width:${100*r.flagged/mx}%;background:var(--crit)"></i>`:''}</div></td><td class="m">${fmt(r.n)}</td>${r.flagged!=null?`<td class="m" style="color:var(--crit)">${fmt(r.flagged)}</td>`:''}</tr>`).join('')||'<tr><td class="empty">no data</td></tr>'}</table></div>`};
   el.innerHTML=`<div class="kpis" style="grid-template-columns:repeat(3,1fr)"><div class="kpi"><label>EVENTS</label><b>${fmt(t.n)}</b></div><div class="kpi"><label>FLAGGED / BLOCKED</label><b>${fmt(t.flagged)}</b><br><small>${t.n?pct(t.flagged/t.n,2):'-'}</small></div><div class="kpi"><label>AVG LATENCY</label><b>${fmt(t.lat,1)}ms</b></div></div>
   <div class="grid g22">${tb(a.by_campaign,'FRAUD BY CAMPAIGN')}${tb(a.by_country,'FRAUD BY COUNTRY')}${tb(a.by_device,'FRAUD BY DEVICE TYPE')}${tb(a.by_attack_ground_truth,'BY SIMULATED ATTACK TYPE (flagged = red)')}${tb(a.by_level,'RISK LEVELS')}${tb(a.top_ips,'TOP SUSPICIOUS IPs')}${tb(a.top_devices,'TOP SUSPICIOUS DEVICES')}</div>`}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}

/* ---------------- Campaigns ---------------- */
const inr=n=>'\u20B9'+fmt(n,2);
function vCampaigns(m){m.innerHTML=`<div class="panel"><h3>CAMPAIGN ANALYTICS <span class="row-f"><select id="cw"><option value="0">all time</option><option value="5">last 5 min</option><option value="60">last hour</option><option value="1440">last day</option></select></span></h3><div id="cbody" class="body skeleton">loading...</div></div><div id="cdet"></div>`;
  $('#cw').onchange=loadCamp;every(loadCamp,5000)}
async function loadCamp(){const el=$('#cbody');if(!el)return;try{const r=await api('/api/campaigns?since_minutes='+$('#cw').value);el.className='body';
  el.innerHTML=`<div class="kpis" style="grid-template-columns:repeat(4,1fr)"><div class="kpi"><label>CLICKS</label><b>${fmt(r.totals.clicks)}</b></div><div class="kpi"><label>SPEND</label><b>${inr(r.totals.spend)}</b></div><div class="kpi"><label>WASTED ON SUSPICIOUS</label><b style="color:var(--crit)">${inr(r.totals.wasted)}</b></div><div class="kpi"><label>WASTE RATIO</label><b>${r.totals.spend?pct(r.totals.wasted/r.totals.spend,2):'-'}</b></div></div>
  <table><thead><tr><th>CAMPAIGN</th><th>CLICKS</th><th>VALID</th><th>SUSPICIOUS</th><th>FRAUD RATE</th><th>USERS</th><th>CPC</th><th>SPEND</th><th>WASTED</th></tr></thead>${r.campaigns.map(c=>`<tr class="row" onclick="campDetail("${esc(c.campaign_id)}")"><td class="m">${esc(c.campaign_id)}</td><td class="m">${fmt(c.clicks)}</td><td class="m">${fmt(c.valid)}</td><td class="m" style="color:var(--crit)">${fmt(c.suspicious)}</td><td class="m">${pct(c.fraud_rate,2)}</td><td class="m">${fmt(c.users)}</td><td class="m">${inr(c.cpc)}</td><td class="m">${inr(c.spend)}</td><td class="m" style="color:var(--crit)">${inr(c.wasted)}</td></tr>`).join('')||'<tr><td class="empty" colspan="9">No traffic yet. Start a simulation.</td></tr>'}</table>
  <div class="hint" style="margin-top:6px">${esc(r.note)}. Cost per click is configured in configs/config.yaml (campaigns.cpc). Click a row for details.</div>`}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
async function campDetail(id){const el=$('#cdet');el.innerHTML='<div class="skeleton">loading...</div>';try{const d=await api(`/api/campaigns/${encodeURIComponent(id)}?since_minutes=${$('#cw').value}`);
  const t=(rows,title)=>`<div class="panel"><h3>${title}</h3><table>${rows.map(r=>`<tr><td class="m">${esc(r.k)}</td><td class="m">${fmt(r.n)}</td><td class="m" style="color:var(--crit)">${fmt(r.flagged||0)}</td></tr>`).join('')||'<tr><td class="empty">none</td></tr>'}</table></div>`;
  el.innerHTML=`<div class="grid g3" style="margin-top:10px">${t(d.top_users,'TOP SUSPICIOUS USERS - '+esc(id))}${t(d.top_ips,'TOP SUSPICIOUS IPs')}${t(d.by_country,'BY COUNTRY')}</div>`}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}

/* ---------------- Models ---------------- */
function vModels(m){m.innerHTML='<div id="mbody" class="skeleton">loading...</div><div id="mon"></div>';safe($('#mbody'),async()=>{const r=await api('/api/models'),reg=r.registry,vs=Object.entries(reg.versions||{}).reverse();
  const bars=(o,cls)=>{const e=Object.entries(o||{}).slice(0,10),mx=Math.max(0.001,...e.map(x=>x[1]));return e.length?e.map(([k,v])=>`<div class="row-f" style="margin:4px 0"><span style="width:170px">${esc(k)}</span><div class="bar ${cls}" style="flex:1"><i style="width:${100*Math.max(0,v)/mx}%"></i></div><span class="m" style="width:56px;text-align:right">${v.toFixed(3)}</span></div>`).join(''):'<div class="empty">Not available for this model version. Run make train.</div>'};
  const col=i=>(i.metrics&&i.metrics);
  $('#mbody').className='';$('#mbody').innerHTML=`<div class="grid g22"><div class="panel"><h3><span class="ai">MODEL REGISTRY</span><span class="tag LOW">PRODUCTION ${esc(reg.production)}</span></h3><div class="scroll"><table><thead><tr><th>VER</th><th>NN</th><th>HGB</th><th>XGB</th><th>LGBM</th><th>LOGREG</th><th>ENS F1</th></tr></thead>${vs.map(([v,i])=>{const q=k=>(i.metrics[k]?.pr_auc);const f=x=>x==null?'-':x.toFixed(4);return `<tr><td class="m">${esc(v)}${v===reg.production?' *':''}</td><td class="m">${f(q('mlp'))}</td><td class="m">${f(q('hgb'))}</td><td class="m">${f(q('xgb'))}</td><td class="m">${f(q('lgbm'))}</td><td class="m">${f(q('logreg'))}</td><td class="m">${f(i.metrics.ensemble?.['f1@0.5'])}</td></tr>`}).join('')}</table></div>
  <div class="body hint">Validation PR-AUC per model (simulator data); held-out test results are in reports/. Explainer: ${esc(r.explain_method)}. Layers: ${Object.entries(r.layers).map(([k,v])=>`${k}=${v}`).join(' ')}</div></div>
  <div class="panel"><h3>GLOBAL FEATURE IMPORTANCE</h3><div class="body"><div class="hint">Permutation importance (PR-AUC drop, MLP)</div>${bars(r.importance,'ai')}<div class="hint" style="margin-top:8px">Mean |SHAP| of the XGBoost model (TreeSHAP, log-odds)</div>${bars(r.shap_importance,'')}</div></div></div>`;
  every(loadMon,3000)})}
async function resetBaseline(){try{await api('/api/monitor/baseline/reset',{method:'POST'});toast('Drift baseline reset - recapturing')}catch(e){toast(e.message)}}
async function loadMon(){const el=$('#mon');if(!el)return;try{const d=await api('/api/monitor');const st=v=>({stable:'LOW',moderate:'MEDIUM',drift:'CRITICAL'}[v]||'LOW');
  const f=d.available?Object.entries(d.feature_psi).slice(0,10):[],mx=Math.max(0.25,...f.map(x=>x[1]));
  el.innerHTML=`<div class="grid g22" style="margin-top:10px"><div class="panel"><h3>FEATURE &amp; PREDICTION DRIFT <span>${d.available?tag2(d.overall):'<span class="hint">'+esc(d.reason||'')+'</span>'}</span></h3><div class="body">${d.available?`<div class="hint">PSI of the latest ${d.window} events vs the reference window (${d.reference_size} events captured after warm-up). &lt;0.1 stable, &lt;0.25 moderate, else drift. ${Auth.role==='admin'?'<button onclick="resetBaseline()">RESET BASELINE</button>':''}</div><div class="hint">Training skew (informational): max PSI ${d.training_skew_max.toFixed(2)} - top: ${d.training_skew_top.map(x=>esc(x[0])).join(', ')}</div>`+f.map(([k,v])=>`<div class="row-f" style="margin:3px 0"><span style="width:170px">${esc(k)}</span><div class="bar"><i style="width:${100*Math.min(1,v/mx)}%;background:var(--${v<0.1?'ok':v<0.25?'warn':'crit'})"></i></div><span class="m" style="width:56px;text-align:right">${v.toFixed(3)}</span></div>`).join('')+
   `<div class="hint" style="margin-top:10px">ML score distribution: baseline (grey) vs live (blue) - PSI ${d.score.psi.toFixed(3)} ${tag2(d.score.status)}</div><canvas id="sd" height="90" style="height:90px"></canvas>`:'<div class="empty">Drift monitoring is warming up.</div>'}</div></div>
  <div class="panel"><h3>PRECISION / RECALL OVER TIME <span class="hint">vs simulated ground truth</span></h3><div class="body"><canvas id="pq" height="150" style="height:150px"></canvas><div class="hint m" id="pqi"></div></div></div></div>`;
  if(d.available)drawScoreDist(d.score);drawQuality(d)}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
const tag2=v=>`<span class="tag ${({stable:'LOW',moderate:'MEDIUM',drift:'CRITICAL'})[v]||'LOW'}">${esc(String(v).toUpperCase())}</span>`;
function drawScoreDist(sc){const c=$('#sd');if(!c)return;const w=c.width=c.clientWidth*devicePixelRatio,h=c.height=90*devicePixelRatio,x=c.getContext('2d');x.clearRect(0,0,w,h);const mx=Math.max(...sc.baseline,...sc.live,0.01),bw=w/10;
  for(let i=0;i<10;i++){x.fillStyle='#3a434d';x.fillRect(i*bw+2,h-(h-4)*sc.baseline[i]/mx,bw/2-3,(h-4)*sc.baseline[i]/mx);x.fillStyle='#4aa3d8';x.fillRect(i*bw+bw/2,h-(h-4)*sc.live[i]/mx,bw/2-3,(h-4)*sc.live[i]/mx)}}
function drawQuality(d){const c=$('#pq');if(!c)return;const w=c.width=c.clientWidth*devicePixelRatio,h=c.height=150*devicePixelRatio,x=c.getContext('2d');x.clearRect(0,0,w,h);x.strokeStyle='#20262D';for(let i=0;i<=4;i++){x.beginPath();x.moveTo(0,h*i/4);x.lineTo(w,h*i/4);x.stroke()}
  const q=d.quality,cm=d.cumulative;$('#pqi').textContent=q.length?`cumulative TP ${cm.tp} FP ${cm.fp} FN ${cm.fn} TN ${cm.tn} | precision ${cm.tp+cm.fp?(cm.tp/(cm.tp+cm.fp)).toFixed(3):'-'} recall ${cm.tp+cm.fn?(cm.tp/(cm.tp+cm.fn)).toFixed(3):'-'} (blue = precision, red = recall)`:'No ground-truth labels yet: start a built-in simulation (events sent through /api/events are unlabeled by design).';if(q.length<2)return;
  const line=(k,col)=>{x.strokeStyle=col;x.lineWidth=1.5*devicePixelRatio;x.beginPath();let first=true;q.forEach((p,i)=>{if(p[k]==null)return;const X=w*i/(q.length-1),Y=h-(h-6)*p[k]-3;first?x.moveTo(X,Y):x.lineTo(X,Y);first=false});x.stroke()};line('precision','#4aa3d8');line('recall','#e5484d')}

/* ---------------- Pipeline ---------------- */
function vPipeline(m){m.innerHTML='<div id="pbody" class="skeleton">loading...</div>';every(()=>safe($('#pbody'),async()=>{const r=await api('/api/pipeline'),c=r.health.components,s=r.stats,pub=r.topics.published||{};
  const node=(n,k,extra)=>`<div class="panel" style="text-align:center"><h3 style="justify-content:center">${n}</h3><div class="body"><span class="dot ${esc(c[k]?.state)}"></span>${esc(c[k]?.state||'')}<div class="hint m">${extra||''}</div><div class="hint">${esc(c[k]?.detail||'')}</div></div></div>`;
  $('#pbody').className='';$('#pbody').innerHTML=`<div class="grid" style="grid-template-columns:repeat(4,1fr)">${node('EVENT BUS','bus',`${r.topics.mode} | lag ${s.bus.lag}`)}${node('SHARED STATE','state','')}${node('DATABASE','database','')}${node('ML ENSEMBLE','ml',s.model_version)}${node('ANOMALY','anomaly','')}${node('GRAPH','graph','')}${node('ONLINE LEARNER','online','')}${node('AGENT','agent','')}${c.neo4j?node('NEO4J MIRROR','neo4j',''):''}</div>
  <div class="grid g22" style="margin-top:10px"><div class="panel"><h3>TOPICS (published)</h3><table>${Object.entries(pub).map(([k,v])=>`<tr><td class="m">${esc(k)}</td><td class="m">${fmt(v)}</td></tr>`).join('')||'<tr><td class="empty">none</td></tr>'}</table></div>
  <div class="panel"><h3>SYSTEM EVENTS</h3><div class="scroll">${(r.system_events||[]).map(e=>`<div style="padding:4px 10px;border-top:1px solid var(--bd)" class="m">${hms(e.ts)} ${esc(e.kind)} ${esc(e.message)}</div>`).join('')||'<div class="empty">none</div>'}</div></div></div>
  <div class="panel" style="margin-top:10px"><h3>LATENCY / THROUGHPUT</h3><div class="body m">detection p50 ${s.latency_ms.p50}ms | p95 ${s.latency_ms.p95}ms | duplicates ${s.duplicates} | invalid ${s.invalid} | rejected ${s.rejected}</div></div>`}),2000)}

/* ---------------- Blocklist / Alerts ---------------- */
function vBlocklist(m){m.innerHTML=`<div class="panel"><h3>BLOCKLIST <span class="row-f"><select id="bt"><option>user</option><option>device</option><option>ip</option></select><input id="bi" placeholder="id / ip"><button class="d" id="bb">BLOCK</button><button class="d" onclick="clearScope("blocklist")">CLEAR BLOCK-LIST</button></span></h3><div id="bbody" class="skeleton">loading...</div></div>`;
  $('#bb').onclick=async()=>{try{await api('/api/blocked',{method:'POST',body:{entity_type:$('#bt').value,entity_id:$('#bi').value.trim(),reason:'manual block'}});loadBl()}catch(e){toast(e.message)}};every(loadBl,4000)}
async function loadBl(){const el=$('#bbody');if(!el)return;try{const r=await api('/api/blocked');el.className='';el.innerHTML=r.length?`<div class="scroll" style="max-height:600px"><table><thead><tr><th>TYPE</th><th>ENTITY</th><th>WHY (PLAIN ENGLISH)</th><th>SCORE</th><th>BY</th><th>TIME</th><th></th></tr></thead>${r.map(b=>`<tr><td>${esc(b.entity_type)}</td><td class="m">${b.entity_type==='user'?`<a href="#/investigation/user/${encodeURIComponent(b.entity_id)}" onclick="go("user","${esc(b.entity_id)}");return false">${esc(b.entity_id)}</a>`:esc(b.entity_id)}</td><td>${whyCell(b)}</td><td class="m">${(b.score*100).toFixed(1)}%</td><td>${esc(b.blocked_by)}</td><td class="m">${hms(b.ts)}</td><td><button onclick="unblock("${esc(b.entity_type)}",'${esc(b.entity_id)}')">UNBLOCK</button></td></tr>`).join('')}</table></div>`:'<div class="empty">BLOCKLIST EMPTY</div>'}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
async function unblock(t,i){if(!confirm('Manually unblock '+i+'? This re-admits its traffic.'))return;try{await api(`/api/blocked/${t}/${encodeURIComponent(i)}?confirm=true`,{method:'DELETE'});toast(i+' unblocked');S.view==='blocklist'?loadBl():loadUser()}catch(e){toast(e.message)}}
function vAlerts(m){m.innerHTML=`<div class="panel"><h3>ALERT CENTER <span class="row-f"><select id="as"><option value="">all</option><option>open</option><option>acknowledged</option><option>resolved</option></select><button class="d" onclick="clearScope("alerts")">CLEAR ALERTS</button></span></h3><div id="abody2" class="skeleton">loading...</div></div>`;$('#as').onchange=loadAl;every(loadAl,4000)}
async function loadAl(){const el=$('#abody2');if(!el)return;try{const r=await api('/api/alerts'+($('#as').value?'?status='+$('#as').value:''));el.className='';
  el.innerHTML=r.length?r.map(a=>`<div style="padding:8px 12px;border-top:1px solid var(--bd)">${tag(a.severity)} <b>${esc(a.title)}</b> <span class="hint m">${hms(a.ts)} | ${esc(a.status)}</span>
   ${reasonBlock(a.details,a.id,a.user_id)}<div class="row-f" style="margin-top:4px"><button onclick="setAl(${a.id},'acknowledged')">ACK</button><button onclick="setAl(${a.id},'resolved')">RESOLVE</button>${a.user_id?`<button onclick="go("user","${esc(a.user_id)}")">INVESTIGATE</button>`:''}</div></div>`).join(''):'<div class="empty">NO ACTIVE FRAUD ALERTS<br><span class="hint">No critical threats detected.</span></div>'}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
/* Blocklist cell: the stored plain-English reason, with the raw rule reason kept as a tooltip. */
function whyCell(b){const rd=b.reason_detail||{};const txt=rd.reason||'';
 const main=txt?esc(txt):`<span class="hint">${esc(b.reason)}</span>`;
 const eid=rd.event_id?`<div class="row-f" style="margin-top:2px"><button onclick="openEvent("${esc(rd.event_id)}")">VIEW EVENT</button>${rd.rules&&rd.rules.length?`<span class="hint m">${esc(rd.rules.join(', '))}</span>`:''}</div>`:'';
 return `<span title="${esc(b.reason)}">${main}</span>${eid}`}
/* The same plain-English reason the engine stored at decision time, with a link into the evidence. */
function reasonBlock(det,alert_id,user_id){const d=det||{},rd=d.reason_detail||{};if(alert_id)d.alert_id=alert_id;if(user_id)d.user_id=d.user_id||user_id;
 const txt=esc(d.reason||rd.reason||'No reason recorded for this alert.');
 const eid=esc(rd.event_id||d.event_id||'');const uid=esc(d.user_id||rd.user_id||'');const aid=d.alert_id?esc(d.alert_id):'';
 return `<div style="margin-top:4px"><b>Why:</b> ${txt}${rd.title?` <span class="hint m">(${esc(rd.title)})</span>`:''}</div>`+
  `<div class="row-f" style="margin-top:4px">${eid?`<button onclick="openEvent("${eid}")">VIEW EVENT ${esc(eid.slice(0,10))}</button>`:''}${uid?`<button onclick="go("user","${uid}")">INVESTIGATE USER</button>`:''}${d.alert_id?`<button onclick="investigateAlert("${esc(d.alert_id)}")">WHY THIS ALERT</button>`:''}${rd.rules&&rd.rules.length?`<span class="hint m">rules: ${esc(rd.rules.join(', '))}</span>`:''}</div>`}
async function setAl(id,st){try{await api(`/api/alerts/${id}/status`,{method:'POST',body:{status:st}});loadAl()}catch(e){toast(e.message)}}

/* ---------------- Rules ---------------- */
const RULE_NUM=[['max_clicks_per_min','Max clicks / minute',1],['min_interval_s','Min click interval (s)',0.05],['min_interval_clicks','Clicks needed for interval rule',1],['max_users_per_device','Max users per device',1],['max_devices_per_ip','Max devices per IP',1],['repeat_ad_ratio','Repeat-ad ratio (0-1)',0.05],['repeat_ad_min_clicks','Repeat-ad min clicks',1]];
function vRules(m){m.innerHTML='<div id="rbody" class="skeleton">loading...</div>';safe($('#rbody'),async()=>{const r=await api('/api/rules'),ro=Auth.role!=='admin';
  $('#rbody').className='';$('#rbody').innerHTML=`<div class="grid g22"><div class="panel"><h3>RULE THRESHOLDS ${ro?'<span class="hint">read-only (admin can edit)</span>':''}</h3><div class="body">${RULE_NUM.map(([k,l,st])=>`<label class="f">${l}</label><input data-k="${k}" type="number" step="${st}" value="${r[k]}" ${ro?'disabled':''}>`).join('')}
   <label class="f">BOT USER-AGENT TOKENS (comma separated)</label><input id="rua" style="width:100%" value="${esc((r.bot_user_agents||[]).join(', '))}" ${ro?'disabled':''}>
   <label class="f">BLOCKED IPs (comma separated)</label><input id="rip" style="width:100%" value="${esc((r.blocked_ips||[]).join(', '))}" ${ro?'disabled':''}></div></div>
  <div class="panel"><h3>RULE WEIGHTS (risk contribution 0-1)</h3><div class="body">${Object.entries(r.weights).map(([k,v])=>`<label class="f">${esc(k)}</label><input data-w="${esc(k)}" type="number" min="0" max="1" step="0.05" value="${v}" ${ro?'disabled':''}>`).join('')}
   <div class="row-f" style="margin-top:12px"><button class="p" id="rsave" ${ro?'disabled':''}>APPLY LIVE</button><span id="rmsg" class="hint"></span></div><div class="hint">Changes apply immediately, are audited and survive restarts.</div></div></div></div>`;
  const sv=$('#rsave');if(sv)sv.onclick=async()=>{const b={weights:{}};$$('[data-k]').forEach(i=>b[i.dataset.k]=+i.value);$$('[data-w]').forEach(i=>b.weights[i.dataset.w]=+i.value);
    b.bot_user_agents=$('#rua').value.split(',').map(x=>x.trim()).filter(Boolean);b.blocked_ips=$('#rip').value.split(',').map(x=>x.trim()).filter(Boolean);
    try{await api('/api/rules',{method:'PUT',body:b});$('#rmsg').textContent='applied';toast('Rules updated')}catch(e){$('#rmsg').textContent=e.message}}})}

/* ---------------- Settings ---------------- */
function vSettings(m){m.innerHTML='<div id="sbody" class="skeleton">loading...</div>';safe($('#sbody'),async()=>{
  let ai=null;const sys=await api('/api/settings/system');try{ai=await api('/api/settings/ai')}catch{}
  $('#sbody').className='';$('#sbody').innerHTML=`<div class="grid g22"><div class="panel"><h3><span class="ai">AI CONFIGURATION</span><span class="hint">admin only</span></h3><div class="body">${ai?`
   <div class="hint">Agent status: ${esc(ai.status.state)} - ${esc(ai.status.detail)}. The agent is optional: without a key the platform uses rule-based explanations.</div>
   <label class="f">LLM PROVIDER</label><select id="sp">${['disabled','grok','openai','claude','ollama'].map(p=>`<option ${ai.provider===p?'selected':''}>${p}</option>`).join('')}</select>
   <label class="f">API KEY ${ai.has_key?'(stored encrypted - leave blank to keep)':''}</label><input id="sk" type="password" autocomplete="off" placeholder="${ai.has_key?'********':'paste key'}" style="width:100%">
   <label class="f">MODEL</label><input id="sm" value="${esc(ai.model)}" placeholder="e.g. grok-3" style="width:100%"><label class="f">TEMPERATURE</label><input id="st" type="number" min="0" max="1" step="0.1" value="${esc(ai.temperature)}">
   <label class="f"><input type="checkbox" id="se" ${ai.enabled?'checked':''}> ENABLE AGENT</label><div class="row-f" style="margin-top:8px"><button class="p" id="ssave">SAVE</button><button id="stest">TEST CONNECTION</button><span id="smsg" class="hint"></span></div>`:'<div class="empty">Admin role required.</div>'}</div></div>
  <div class="panel"><h3>DETECTION THRESHOLDS</h3><div class="body"><label class="f">MEDIUM</label><input id="tm" type="number" step="0.05" value="${sys.medium}"><label class="f">HIGH</label><input id="th" type="number" step="0.05" value="${sys.high}"><label class="f">CRITICAL (auto-block)</label><input id="tc" type="number" step="0.05" value="${sys.critical}">
   <label class="f">CRITICAL HITS BEFORE BLOCK</label><input id="tn" type="number" min="1" value="${sys.block_min_hits}"><label class="f"><input type="checkbox" id="ta" ${sys.auto_block?'checked':''}> AUTO-BLOCK</label>
   <div class="row-f" style="margin-top:8px"><button class="p" id="tsave">APPLY</button><button id="rt">RETRAIN (quick)</button><button id="rb">ROLLBACK MODEL</button></div><div class="hint" id="tmsg"></div></div></div></div>`;
  const ssave=$('#ssave');if(ssave){ssave.onclick=async()=>{try{const b={provider:$('#sp').value,model:$('#sm').value,temperature:+$('#st').value,enabled:$('#se').checked};if($('#sk').value)b.api_key=$('#sk').value;const r=await api('/api/settings/ai',{method:'PUT',body:b});$('#sk').value='';$('#smsg').textContent='saved - '+r.status.state}catch(e){$('#smsg').textContent=e.message}};
   $('#stest').onclick=async()=>{$('#smsg').textContent='testing...';try{const r=await api('/api/settings/ai/test',{method:'POST'});$('#smsg').textContent=(r.ok?'OK: ':'FAILED: ')+r.message}catch(e){$('#smsg').textContent=e.message}}}
  $('#tsave').onclick=async()=>{try{await api('/api/settings/system',{method:'PUT',body:{medium:+$('#tm').value,high:+$('#th').value,critical:+$('#tc').value,block_min_hits:+$('#tn').value,auto_block:$('#ta').checked}});$('#tmsg').textContent='applied'}catch(e){$('#tmsg').textContent=e.message}};
  $('#rt').onclick=async()=>{$('#tmsg').textContent='training...';try{const r=await api('/api/models/retrain',{method:'POST'});$('#tmsg').textContent='trained '+r.version}catch(e){$('#tmsg').textContent=e.message}};
  $('#rb').onclick=async()=>{try{const r=await api('/api/models/rollback',{method:'POST'});$('#tmsg').textContent='production = '+r.production}catch(e){$('#tmsg').textContent=e.message}}})}

/* ---------------- Data and Reset ---------------- */
// scope id -> [label, what it clears, minimum role]
const SCOPE_INFO={simulation_runs:['Simulation history','Runs started from the Simulator page.','analyst'],
 events:['Click events and decisions','Every stored click plus its risk score.','analyst'],
 alerts:['Alerts','Raised alerts and their status.','analyst'],
 incidents:['Incidents','Grouped attack episodes and the entities involved.','analyst'],
 recommendations:['AI recommendations','Investigation suggestions and their decisions.','analyst'],
 live_state:['Live tracking state','Active users, click counters and duplicate-event memory. Not the block-list.','analyst'],
 blocklist:['Block-list','Entities blocked by the engine or by an analyst.','admin'],
 learning:['Learned thresholds','Thresholds learned from analyst feedback. Manual rule edits are kept.','admin'],
 saved_attacks:['Saved attacks','Attack templates you named and saved.','admin'],
 patterns:['Named patterns','Pattern definitions and their hit history.','admin']};
const PRESET_INFO={reset_network:['Reset network','Clears simulated and live traffic, alerts, incidents, recommendations, the block-list and learned thresholds. Saved attacks, patterns and your rule edits are kept.','RESET NETWORK'],
 factory_reset:['Factory reset','Everything in Reset network plus saved attacks, named patterns and rule edits made on the Rules page. Users, the audit log, trained models and stored API keys are never removed.','FACTORY RESET']};
function confirmBox(o){return new Promise(res=>{
  const box=$('#confirm');
  box.innerHTML=`<div class="box" role="document"><h3 id="cf-title">${esc(o.title)}</h3><div class="body">${o.body}
   ${o.list?`<ul>${o.list.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:''}
   ${o.preserved?`<div class="preserved">Always kept: ${esc(o.preserved.join(', '))}</div>`:''}</div>
   <label class="f" for="cf-word">TYPE ${esc(o.word)} TO CONFIRM</label><input id="cf-word" autocomplete="off" spellcheck="false">
   <div class="row-f"><button class="d" id="cf-ok">CONFIRM</button><button id="cf-no">CANCEL</button><span id="cf-err" class="hint" style="color:var(--crit)"></span></div></div>`;
  box.classList.add('on');
  const inp=$('#cf-word'),done=v=>{box.classList.remove('on');box.innerHTML='';document.removeEventListener('keydown',key);res(v)};
  const attempt=()=>{const ok=inp.value.trim().toUpperCase()===o.word;if(!ok)$('#cf-err').textContent='Type '+o.word+' exactly to continue';else done(true)};
  const key=e=>{if(e.key==='Escape'){e.stopPropagation();done(false)}};
  document.addEventListener('keydown',key);
  $('#cf-ok').onclick=attempt;
  $('#cf-no').onclick=()=>done(false);
  box.onclick=e=>{if(e.target===box)done(false)};
  inp.onkeydown=e=>{if(e.key==='Enter')attempt()};
  inp.focus()})}
async function clearScope(id){
  const info=SCOPE_INFO[id];if(!info)return;
  try{
    const p=await api('/api/admin/reset/preview?scopes='+encodeURIComponent(id));
    if((p.denied||[]).length)return toast('Admin role required to clear '+info[0].toLowerCase(),true);
    const n=p.selected[id]||0;
    const ok=await confirmBox({title:'Clear '+info[0].toLowerCase()+'?',word:'CLEAR',
      body:`<p>This permanently deletes <b>${fmt(n)}</b> row${n===1?'':'s'} from this system.</p><p>${esc(info[1])}</p>`,
      list:n?[info[0]+': '+fmt(n)+' row'+(n===1?'':'s')]:[],preserved:p.preserved||['users','audit_log','model_versions','api_settings']});
    if(!ok)return;
    const r=await api('/api/admin/reset',{method:'POST',body:{scopes:[id],confirm:true}});
    toast('Cleared '+info[0].toLowerCase()+' ('+fmt(r.deleted[id]||0)+' rows)');
    go(S.view)}catch(e){toast(e.message,true)}}
async function clearPreset(id){
  const info=PRESET_INFO[id];if(!info)return;
  try{
    const p=await api('/api/admin/reset/preview?preset='+id);
    const total=p.total||0;
    const ok=await confirmBox({title:info[0]+'?',word:info[2],
      body:`<p>This permanently deletes <b>${fmt(total)}</b> row${total===1?'':'s'} in one step.</p><p>${esc(info[1])}</p>`,
      list:Object.entries(p.selected).filter(([,n])=>n>0).map(([k,n])=>k+': '+fmt(n)),
      preserved:p.preserved||['users','audit_log','model_versions','api_settings']});
    if(!ok)return;
    const r=await api('/api/admin/reset',{method:'POST',body:{scopes:[],preset:id,confirm:true}});
    toast(info[0]+' complete ('+fmt(total)+' rows)');
    go(S.view)}catch(e){toast(e.message,true)}}
function vDataReset(m){m.innerHTML='<div id="drbody" class="skeleton">loading...</div>';
  safe($('#drbody'),async()=>{
    const cat=await api('/api/admin/reset/scopes');
    const pv=await api('/api/admin/reset/preview?scopes='+cat.scopes.map(s=>s.id).join(','));
    const can=id=>cat.clearable.includes(id);
    const canPreset=id=>{const p=(cat.presets||[]).find(x=>x.id===id);return p?p.scopes.every(s=>cat.clearable.includes(s)):false};
    $('#drbody').className='';
    $('#drbody').innerHTML=`<div class="grid g2"><div class="panel"><h3>CLEAR A SUBSYSTEM <span class="hint">signed in as ${esc(cat.role)}</span></h3>
     <div class="body">${cat.scopes.map(s=>{const info=SCOPE_INFO[s.id]||[s.id,'',''],n=(pv.counts||{})[s.id]||0,ok=can(s.id);
       return `<div style="display:flex;gap:10px;align-items:flex-start;padding:7px 0;border-top:1px solid var(--bd)">
        <div style="flex:1"><b>${esc(info[0])}</b> <span class="hint">${fmt(n)} row${n===1?'':'s'}</span>
         <div class="hint">${esc(info[1])}</div>${ok?'':'<div class="hint">admin role required</div>'}</div>
        <button class="d" onclick="clearScope("${s.id}")" ${ok?'':'disabled'}>CLEAR</button></div>`}).join('')}</div></div>
     <div><div class="panel"><h3>PRESETS</h3><div class="body">${Object.entries(PRESET_INFO).map(([id,info])=>{const ok=canPreset(id);
       return `<div style="padding:7px 0;border-top:1px solid var(--bd)"><b>${esc(info[0])}</b><div class="hint">${esc(info[1])}</div>
        ${ok?'':'<div class="hint">admin role required</div>'}
        <button class="d" style="margin-top:6px" onclick="clearPreset("${id}")" ${ok?'':'disabled'}>RUN ${esc(info[2])}</button></div>`}).join('')}
       <div class="preserved hint" style="margin-top:10px">Never removed by any action: ${esc(cat.preserved.join(', '))}.<br>Every clear is written to the audit log and announced to open pages.</div></div></div>
     <div class="panel" style="margin-top:10px"><h3>RELATED</h3><div class="body"><div class="hint">Alerts and the block-list also carry CLEAR buttons on their own pages. Simulation runs can be cleared from the Simulator page.</div>
      <div class="row-f" style="margin-top:8px"><button onclick="go("user")">ALERTS</button><button onclick="go("user")">BLOCKLIST</button><button onclick="window.open("/sim",'_blank')">SIMULATOR</button></div></div></div></div></div>`})}

/* ---------------- Start Here ---------------- */
function vStart(m){
  m.innerHTML='<div id="sbody" class="skeleton">loading...</div>';
  safe(m,async()=>{
    const h=await api("/api/health");
    const cards=PAGES.filter(p=>p[3][0]!=="admin").map(p=>{
      const h4=p[4];
      return '<a class="card" onclick="go("user")" tabindex="0" onkeydown="if(event.key===\'Enter\')go("user")">'
        +'<h4>'+esc(p[1])+'</h4><p class="muted">'+esc(h4.what)+'</p>'
        +'<div class="row-f"><kbd>'+esc(p[2])+'</kbd><span class="muted">'+h4.how[0]+'</span></div></a>';
    }).join('');
    m.innerHTML='<div class="panel"><h3>START HERE</h3><div class="grid">'+cards+'</div></div>';
  });
}

/* ---------------- Incidents List ---------------- */
function vIncidents(m){
  const args=routeArgs(); const status=args.status||"open";
  m.innerHTML=`<div class="panel"><h3>INCIDENTS <span class="row-f">
    <select id="ist" onchange="go("user",'',{now:true})"><option value="open" ${status==="open"?"selected":""}>Open</option>
    <option value="closed" ${status==="closed"?"selected":""}>Closed</option></select>
    <input id="iq" placeholder="Search incidents..." oninput="debounce(()=>go("user",'',{now:true}),300)"></span></h3>
    <div id="ilist" class="skeleton">loading...</div></div>`;
  safe($('#ilist'),async()=>{
    const data=await api("/api/incidents?status="+encodeURIComponent(status)+"&limit=100");
    if(!data.length){$('#ilist').innerHTML='<div class="empty">No incidents</div>';return}
    $('#ilist').innerHTML=`<table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Risk</th><th>Users</th><th>Devices</th><th>IPs</th><th>Last seen</th><th></th></tr></thead><tbody>
      ${data.map(r=>`<tr onclick="go("incident",'${r.id}')"><td>${r.id}</td><td>${esc(r.title||"Unclassified")}</td>
        <td><span class="tag ${esc((r.status||"open").toLowerCase())}">${esc(r.status||"open")}</span></td>
        <td>${fmt(r.peak_risk||0,3)}</td><td>${r.users_n||0}</td><td>${r.devices_n||0}</td><td>${r.ips_n||0}</td>
        <td>${hms(r.last_seen||0)}</td><td class="row-f"><button class="ghost" onclick="event.stopPropagation();go("incident",'${r.id}')">Open</button></td></tr>`).join('')}
      </tbody></table>`;
  });
}function vIncident(m){
  const id=S.incidentId; if(!id){m.innerHTML='<div class="empty">No incident selected</div>';return}
  m.innerHTML=`<div class="panel"><h3>INCIDENT ${id} <span class="row-f"><button onclick="go("incidents")">Back</button></span></h3>
    <div id="idet" class="skeleton">loading...</div></div>`;
  safe($('#idet'),async()=>{
    const d=await api("/api/incidents/"+encodeURIComponent(id));
    const entities=(d.entities||[]).map(e=>`<span class="tag ${esc(e.entity_type)}">${esc(e.entity_type)}:${esc(e.entity_id)}</span>`).join(' ');
    const reasons=(d.combined?.reasons||[]).map(r=>`<li>${esc(r.title)} × ${r.n}</li>`).join('');
    const rules=(d.combined?.rules||[]).map(r=>`<li>${esc(r.rule)} × ${r.n}</li>`).join('');
    const levels=Object.entries(d.combined?.levels||{}).map(([k,v])=>`<span class="tag ${k.toLowerCase()}">${k} ${v}</span>`).join(' ');
    const btn=d.status==="closed"?"":'<button onclick="confirmBox(\"Block all entities in this incident?\",async()=>{const r=await api(\"/api/incidents/"+id+"/block-all?confirm=true\",{method:\"POST\"});toast(\"Blocked \"+r.count+" entities\");go(\"incident\",id)}">Block All</button>';
    m.innerHTML=`<div class="panel"><h3>INCIDENT ${id} <span class="row-f">${btn}<button onclick="go("incidents")">Back</button></span></h3>
      <div class="grid" style="grid-template-columns:1fr 320px">
      <div><h4>Summary</h4><p><strong>Status:</strong> <span class="tag ${esc((d.status||"open").toLowerCase())}">${esc(d.status||"open")}</span>
      <strong>Classification:</strong> ${esc(d.classification||"Unclassified")}
      <strong>Peak risk:</strong> ${fmt(d.peak_risk||0,3)} <strong>Levels:</strong> ${levels}</p>
      <p><strong>First seen:</strong> ${hms(d.first_seen)} <strong>Last seen:</strong> ${hms(d.last_seen)}
      <strong>Events:</strong> ${d.combined?.events||0} <strong>Wasted spend:</strong> ${fmt(d.combined?.wasted_spend||0,2)}</p>
      <h4>Entities (${d.combined?.users?.length||0} users, ${d.combined?.devices?.length||0} devices, ${d.combined?.ips?.length||0} IPs)</h4><p>${entities}</p>
      <h4>Top reasons</h4><ul>${reasons||'<li class="muted">None</li>'}</ul>
      <h4>Top rules</h4><ul>${rules||'<li class="muted">None</li>'}</ul>
      <h4>Events</h4><div id="ievs" class="skeleton">loading...</div></div>
      <div><h4>Timeline</h4><canvas id="itl" height="180"></canvas></div></div></div>`;
    const evs=d.events||[];
    $('#ievs').innerHTML=`<table><thead><tr><th>Time</th><th>User</th><th>Ad</th><th>Level</th><th>Reason</th></tr></thead><tbody>
      ${evs.map(e=>`<tr onclick="openEvent("${e.event_id}")"><td>${hms(e.ts)}</td><td>${esc(e.user_id)}</td><td>${esc(e.ad_id)}</td>
        <td><span class="tag ${esc((e.level||"LOW").toLowerCase())}">${esc(e.level||"LOW")}</span></td>
        <td>${esc(e.reason_title||"")}</td></tr>`).join('')}
      </tbody></table>`;
    const tl=d.combined?.timeline||[];
    if(tl.length){
      const ctx=$('#itl').getContext('2d');ctx.clearRect(0,0,$('#itl').width,$('#itl').height);
      const w=$('#itl').width,h=$('#itl').height;
      const max=Math.max(...tl.map(t=>t.peak_risk||0),1);
      ctx.strokeStyle='#66a';ctx.beginPath();
      tl.forEach((t,i)=>{const x=(i/tl.length)*w; const y=h-(t.peak_risk/max)*h; i?ctx.lineTo(x,y):ctx.moveTo(x,y);});
      ctx.stroke();
    }
  });
}function vCombined(m){
  const args=routeArgs(); const since=Math.max(parseFloat(args.since||"60"),1); const minR=parseFloat(args.min_risk||"0");
  m.innerHTML='<div class="panel"><h3>COMBINED ANALYSIS <span class="row-f">'
    +'Since: <select onchange="go("user","combined",{now:true})" id="csince">'
    +'<option value="15" '+(since===15?"selected":"")+'>15m</option>'
    +'<option value="60" '+(since===60?"selected":"")+'>1h</option>'
    +'<option value="240" '+(since===240?"selected":"")+'>4h</option>'
    +'<option value="1440" '+(since===1440?"selected":"")+'>24h</option></select>'
    +'Min risk: <input type="number" step="0.01" min="0" max="1" value="'+minR+'" id="cmin" onchange="go("user","combined",{now:true})" style="width:60px">'
    +'<button onclick="exportCsv("combined")">Export CSV</button></span></h3>'
    +'<div id="clist" class="skeleton">loading...</div></div>';
  safe($('#clist'),async()=>{
    const d=await api("/api/analysis/combined?since_minutes="+since+"&min_risk="+minR+"&limit=80");
    const rows=d.clusters.map(c=>'<tr onclick="go("user",c.k)"><td>'+esc(c.k)+'</td>'
      +'<td>'+c.events+'</td><td>'+c.users+'</td><td>'+c.devices+'</td><td>'+c.ips+'</td>'
      +'<td>'+fmt(c.peak_risk,3)+'</td><td>'+fmt(c.avg_risk,3)+'</td><td>'+c.criticals+'</td></tr>').join('');
    $('#clist').innerHTML='<h4>Clusters ('+d.clusters.length+')</h4>'
      +'<table><thead><tr><th>Key</th><th>Events</th><th>Users</th><th>Devices</th><th>IPs</th><th>Peak risk</th><th>Avg risk</th><th>Crit</th></tr></thead><tbody>'+rows+'</tbody></table>'
      +'<h4>Totals</h4><pre class="muted">'+JSON.stringify(d.kinds.totals,null,2)+'</pre>'
      +'<h4>Kinds</h4><pre class="muted">'+JSON.stringify(d.kinds,null,2)+'</pre>';
  });
}

/* ---------------- Targeted Analysis ---------------- */
function vTarget(m){
  const camp=S.campaignFilter;
  const args=routeArgs(); const since=Math.max(parseFloat(args.since||"1440"),1);
  m.innerHTML='<div class="panel"><h3>TARGETED ANALYSIS '+(camp?'<span class="muted">/ '+esc(camp)+'</span>':'')
    +' <span class="row-f">Since: <select onchange="go("user",(camp||'')+'',{now:true})" id="tsince">'
    +'<option value="60" '+(since===60?"selected":"")+'>1h</option>'
    +'<option value="1440" '+(since===1440?"selected":"")+'>24h</option>'
    +'<option value="10080" '+(since===10080?"selected":"")+'>7d</option></select>'
    +'<button onclick="exportCsv("target")">Export CSV</button></span></span></h3>'
    +'<div id="tlist" class="skeleton">loading...</div></div>';
  safe($('#tlist'),async()=>{
    const d=await api("/api/analysis/target?since_minutes="+since+"&limit=80");
    const campRows=(d.campaigns||[]).map(c=>'<tr onclick="go("user",c.campaign_id)"><td>'+esc(c.campaign_id)+'</td>'
      +'<td>'+esc(c.ad_id||"")+'</td><td>'+c.clicks+'</td><td>'+c.users+'</td><td>'+fmt(c.peak_risk||0,3)+'</td><td>'+c.criticals+'</td></tr>').join('');
    const victimRows=(d.victims||[]).map(v=>'<tr onclick="go("user",v.user_id)"><td>'+esc(v.user_id)+'</td>'
      +'<td>'+esc(v.country||"")+'</td><td>'+v.clicks+'</td><td>'+fmt(v.peak_risk||0,3)+'</td><td>'+v.campaigns+'</td><td>'+v.devices+'</td></tr>').join('');
    $('#tlist').innerHTML='<div class="grid">'
      +'<div><h4>Campaigns ('+d.campaigns.length+') Wasted clicks: '+fmt(d.wasted_clicks||0,0)+'</h4>'
      +'<table><thead><tr><th>Campaign</th><th>Advert</th><th>Clicks</th><th>Users</th><th>Peak risk</th><th>Crit</th></tr></thead><tbody>'+campRows+'</tbody></table></div>'
      +'<div><h4>Victims ('+d.victims.length+') At risk: '+d.at_risk_users+'</h4>'
      +'<table><thead><tr><th>User</th><th>Country</th><th>Clicks</th><th>Peak risk</th><th>Campaigns</th><th>Devices</th></tr></thead><tbody>'+victimRows+'</tbody></table></div>'
      +'<div><h4>Clean campaigns</h4>'
      +'<table><thead><tr><th>Campaign</th><th>Clicks</th><th>Users</th></tr></thead><tbody>'
      +(d.clean||[]).map(c=>'<tr><td>'+esc(c.campaign_id)+'</td><td>'+c.clicks+'</td><td>'+c.users+'</td></tr>').join('')
      +'</tbody></table></div></div>';
  });
}

/* ---------------- Event Logs ---------------- */
function vLogs(m){
  const args=routeArgs(); const level=args.level||""; const user=args.user_id||""; const camp=args.campaign_id||"";
  const src=args.source||""; const run=args.run_id||""; const q=args.q||""; const since=Math.max(parseFloat(args.since||"60"),1); const lim=parseInt(args.limit||"100");
  m.innerHTML='<div class="panel"><h3>EVENT LOGS <span class="row-f">'
    +'Level: <select onchange="go("user","",{now:true})" id="llvl"><option value="">All</option>'
    +'<option value="LOW" '+(level==="LOW"?"selected":"")+'>LOW</option>'
    +'<option value="MEDIUM" '+(level==="MEDIUM"?"selected":"")+'>MEDIUM</option>'
    +'<option value="HIGH" '+(level==="HIGH"?"selected":"")+'>HIGH</option>'
    +'<option value="CRITICAL" '+(level==="CRITICAL"?"selected":"")+'>CRITICAL</option></select>'
    +'User: <input placeholder="user_id" value="'+esc(user)+'" id="lusr" onchange="go("user","",{now:true})" style="width:100px">'
    +'Campaign: <input placeholder="campaign_id" value="'+esc(camp)+'" id="lcam" onchange="go("user","",{now:true})" style="width:100px">'
    +'Source: <input placeholder="source" value="'+esc(src)+'" id="lsrc" onchange="go("user","",{now:true})" style="width:80px">'
    +'Run: <input placeholder="run_id" value="'+esc(run)+'" id="lrun" onchange="go("user","",{now:true})" style="width:120px">'
    +'Search: <input placeholder="q" value="'+esc(q)+'" id="lq" onchange="go("user","",{now:true})" style="width:120px">'
    +'Since: <input type="number" min="1" value="'+since+'" id="lsince" onchange="go("user","",{now:true})" style="width:50px">m'
    +'Limit: <input type="number" min="1" max="1000" value="'+lim+'" id="llim" onchange="go("user","",{now:true})" style="width:60px">'
    +'<button onclick="exportCsv("logs")">Export CSV</button></span></h3>'
    +'<div id="llist" class="skeleton">loading...</div></div>';
  safe($('#llist'),async()=>{
    const qp=new URLSearchParams({level,user_id:user,campaign_id:camp,source:src,run_id:run,q,since_minutes:since,limit:lim});
    const data=await api("/api/logs/events?"+qp.toString());
    if(!data.length){$('#llist').innerHTML='<div class="empty">No events</div>';return}
    $('#llist').innerHTML='<table><thead><tr><th>Time</th><th>Event</th><th>User</th><th>Ad</th><th>Campaign</th><th>Device</th><th>IP</th><th>Level</th><th>Action</th><th>Risk</th><th>Reason</th></tr></thead><tbody>'
      +data.map(e=>'<tr onclick="openEvent(''+e.event_id+'')"><td>'+hms(e.ts)+'</td><td>'+esc(e.event_id)+'</td>'
        +'<td>'+esc(e.user_id)+'</td><td>'+esc(e.ad_id)+'</td><td>'+esc(e.campaign_id||"")+'</td>'
        +'<td>'+esc(e.device_id)+'</td><td>'+esc(e.ip_mask||"")+'</td>'
        +'<td><span class="tag '+esc((e.level||"LOW").toLowerCase())+'">'+esc(e.level||"LOW")+'</span></td>'
        +'<td>'+esc(e.action)+'</td><td>'+fmt(e.risk||0,3)+'</td><td>'+esc(e.reason_title||"")+'</td></tr>').join('')
      +'</tbody></table>';
  });
}

/* ---------------- Saved Attacks ---------------- */
function vSaved(m){
  m.innerHTML='<div class="panel"><h3>SAVED ATTACKS <span class="row-f"><button onclick="go("user")">Run new</button></span></h3>'
    +'<div id="slist" class="skeleton">loading...</div></div>';
  safe($('#slist'),async()=>{
    const data=await api("/api/simulations/saved?limit=100");
    if(!data.length){$('#slist').innerHTML='<div class="empty">No saved attacks</div>';return}
    $('#slist').innerHTML='<table><thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Events</th><th>Duration</th><th>Actors</th><th>Created</th><th></th></tr></thead><tbody>'
      +data.map(r=>'<tr onclick="go("user",r.id)"><td>'+r.id+'</td><td>'+esc(r.name)+'</td><td>'+esc(r.kind)+'</td>'
        +'<td>'+r.events+'</td><td>'+(r.duration?fmt(r.duration,1)+'s':'')+'</td><td>'+(r.actors_n||'')+'</td>'
        +'<td>'+hms(r.ts)+'</td><td class="row-f">'
        +'<button class="ghost" onclick="event.stopPropagation();api('/api/simulations/'+r.id+'/replay',{method:'POST'}).then(r=>toast('Replaying at 1x: '+r.sim_db_id))">Replay 1x</button>'
        +'<button class="ghost" onclick="event.stopPropagation();confirmBox("Delete?",async()=>{await api('/api/simulations/'+r.id+'?confirm=true',{method:'DELETE'});go("user")})">Delete</button></td></tr>').join('')
      +'</tbody></table>';
  });
}

/* ---------------- Saved Attack Detail ---------------- */
function vSavedDetail(m){
  const id=S.savedId; if(!id){m.innerHTML='<div class="empty">No saved attack selected</div>';return}
  m.innerHTML='<div class="panel"><h3>SAVED ATTACK '+id+' <span class="row-f"><button onclick="go("user")">Back</button></span></h3>'
    +'<div id="sdet" class="skeleton">loading...</div></div>';
  safe($('#sdet'),async()=>{
    const d=await api("/api/simulations/"+id+"/export");
    m.innerHTML='<div class="panel"><h3>SAVED ATTACK '+id+' <span class="row-f">'
      +'<button onclick="go("user")">Back</button>'
      +'<button onclick="api('/api/simulations/'+id+'/replay',{method:'POST'}).then(r=>toast('Replaying: '+r.sim_db_id))">Replay 1x</button>'
      +'<button onclick="confirmBox("Delete?",async()=>{await api('/api/simulations/'+id+'?confirm=true',{method:'DELETE'});go("user")})">Delete</button>'
      +'<button onclick="exportCsv('saved_'+id)">Export JSON</button></span></h3>'
      +'<div class="grid"><div><h4>Meta</h4><pre class="muted">'+JSON.stringify({name:d.name,notes:d.notes,tags:d.tags,kind:d.kind,duration:d.duration,actors_n:d.actors_n,events:d.events.length},null,2)+'</pre></div>'
      +'<div><h4>Events ('+d.events.length+')</h4><table><thead><tr><th>User</th><th>Ad</th><th>Campaign</th><th>Device</th><th>IP</th><th>Time</th></tr></thead><tbody>'
      +d.events.slice(0,200).map(e=>'<tr><td>'+esc(e.user_id)+'</td><td>'+esc(e.ad_id)+'</td><td>'+esc(e.campaign_id||"")+'</td>'
        +'<td>'+esc(e.device_id)+'</td><td>'+esc(e.ip_address)+'</td><td>'+hms(e.ts)+'</td></tr>').join('')
      +'</tbody></table></div></div>';
  });
}

/* ---------------- Pattern Library ---------------- */
function vPatterns(m){
  m.innerHTML='<div class="panel"><h3>PATTERN LIBRARY <span class="row-f"><button onclick="showPatternModal()">New Pattern</button></span></h3>'
    +'<div id="plist" class="skeleton">loading...</div></div>';
  safe($('#plist'),async()=>{
    const data=await api("/api/patterns");
    const builtins=data.builtins.map(b=>'<div class="builtin"><strong>'+esc(b.label)+'</strong><span class="muted"> '+b.text+'</span></div>').join('');
    const saved=data.patterns.map(p=>'<div class="pattern-card"><div class="row-f"><strong>'+esc(p.name)+'</strong>'
      +'<span class="muted">'+esc(p.description)+'</span></div>'
      +'<div class="muted">Action: '+esc(p.action)+' | Hits: '+(p.hits||0)+' | Enabled: '+(p.enabled?"yes":"no")+'</div>'
      +'<div class="row-f"><button class="ghost" onclick="go("user","+p.id+")">Edit</button>'
      +'<button class="ghost" onclick="confirmBox("Delete pattern?",async()=>{await api('/api/patterns/'+p.id+'?confirm=true',{method:'DELETE'});go("user")})">Delete</button>'
      +'<button class="ghost" onclick="previewPattern("+p.id+")">Preview</button></div></div>').join('');
    $('#plist').innerHTML='<h4>Built-in signatures ('+builtins.length+')</h4><div class="grid">'+builtins+'</div>'
      +'<h4>Saved patterns ('+data.patterns.length+'/'+data.max+')</h4><div class="grid">'+(saved||'<div class="muted">No saved patterns yet</div>')+'</div>';
  });
}

/* ---------------- Pattern Detail / Editor ---------------- */
function vPatternDetail(m){
  const id=S.patternId; const isNew=!id;
  m.innerHTML='<div class="panel"><h3>'+(isNew?'NEW PATTERN':'PATTERN '+id)+' <span class="row-f">'
    +'<button onclick="go("user")">Back</button>'
    +'<button onclick="savePattern('+(id||'')+')">Save</button></span></h3>'
    +'<div class="grid"><div><label>Name<input id="pname" placeholder="e.g. click flood" value="'+(isNew?'':'')+'"></label>'
    +'<label>Description<textarea id="pdesc" placeholder="What this pattern captures"></textarea></label>'
    +'<label>Action<select id="paction"><option value="label">label</option><option value="alert">alert</option></select></label>'
    +'<label>Conditions (JSON)<textarea id="psig" rows="10" placeholder='{"conditions":[{"field":"clicks_1m","op":">=","value":5},{"field":"min_interval","op":"<","value":0.5}],"min_match":2}'></textarea></label>'
    +'<div class="row-f"><button onclick="previewPattern('+(id||'new')+')">Preview</button></div></div>'
    +'<div id="pprev" class="muted">Run preview to see matches against recent HIGH/CRITICAL events</div></div></div>';
  if(!isNew){
    safe(m,async()=>{
      const d=await api("/api/patterns/"+id);
      $('#pname').value=d.name; $('#pdesc').value=d.description; $('#paction').value=d.action;
      $('#psig').value=JSON.stringify(d.signature,null,2);
    });
  }
}
window.showPatternModal=()=>go("user","new");
window.savePattern=async(id)=>{
  const body={name:$('#pname').value,description:$('#pdesc').value,action:$('#paction').value,signature:JSON.parse($('#psig').value||'{}')};
  try{
    const r=id?await api('/api/patterns/'+id,{method:'PUT',body:JSON.stringify(body)}):await api('/api/patterns',{method:'POST',body:JSON.stringify(body)});
    toast(id?'Pattern updated':'Pattern created'); go("user",String(r.id));
  }catch(e){toast('Save failed: '+e.message)}
};
window.previewPattern=async(id)=>{
  const body={signature:JSON.parse($('#psig').value||'{}')};
  try{
    const r=await api('/api/patterns/preview',{method:'POST',body:JSON.stringify(body)});
    $('#pprev').innerHTML='<strong>Checked '+r.checked+' events, matched '+r.matches+'</strong><ul>'
      +(r.examples||[]).map(x=>'<li>'+esc(x.event_id)+' user='+esc(x.user_id)+' ['+x.conditions.join(', ')+']</li>').join('')
      +'</ul>';
  }catch(e){$('#pprev').innerHTML='<span class="tag crit">Error: '+esc(e.message)+'</span>'}
};

/* ---------------- Search ---------------- */
function vSearch(m){
  const q=routeArgs().q||"";
  m.innerHTML='<div class="panel"><h3>SEARCH <span class="row-f"><input id="sq" placeholder="Type a user id, campaign, advert, device, incident, or alert text..." value="'+esc(q)+'" onkeydown="if(event.key===\'Enter\')go("user","",{now:true})">'
    +'<button onclick="go("user","",{now:true})">Search</button></span></h3>'
    +'<div id="sres" '+(q?'':'class="empty"')+'>'+(q?'loading...':"Enter a query above")+'</div></div>';
  if(!q)return;
  safe($('#sres'),async()=>{
    const d=await api("/api/analysis/search?q="+encodeURIComponent(q)+"&limit=30");
    const sections=[
      ["users",d.users||[],u=>'<a onclick="go("user","+JSON.stringify(u.user_id)+")">'+esc(u.user_id)+'</a> ('+u.clicks+' clicks, '+esc(u.country)+')'],
      ["campaigns",d.campaigns||[],c=>'<a onclick="go("user","+JSON.stringify(c.campaign_id)+")">'+esc(c.campaign_id)+'</a> ('+c.clicks+' clicks)'],
      ["ads",d.ads||[],a=>'<a onclick="go("user")">'+esc(a.ad_id)+'</a> ('+a.clicks+' clicks)'],
      ["devices",d.devices||[],d=>'<a onclick="go("user")">'+esc(d.device_id)+'</a> ('+d.n+' events, '+d.users+' users)'],
      ["incidents",d.incidents||[],i=>'<a onclick="go("user","+JSON.stringify(i.id)+")">#'+i.id+'</a> '+esc(i.title)+' ('+esc(i.status)+')'],
      ["alerts",d.alerts||[],a=>'<a onclick="go("user","+JSON.stringify(a.user_id)+")">Alert #'+a.id+'</a> '+esc(a.reason_title)+' ('+esc(a.level)+')']
    ];
    $('#sres').innerHTML=sections.filter(([,arr])=>arr.length).map(([title,arr,render])=>
      '<h4>'+title+' ('+arr.length+')</h4><ul>'+arr.map(render).join('')+'</ul>').join('');
  });
}


function reloadAfterReset(){if(S.view)go(S.view)}

/* ---------------- command palette & shortcuts ---------------- */
async function startSim(k){try{await api('/api/simulation/'+k,{method:'POST',body:{duration:60}});toast('Simulation started: '+k)}catch(e){toast(e.message)}}
const CMDS=[...VIEWS.map(v=>({t:'Open '+v[1],f:()=>go(v[0])})),{t:'Pause / resume event stream',f:togglePause},{t:'Open Ad Network Simulator',f:()=>window.open('/sim','_blank')},
 {t:'Start bot simulation',f:()=>startSim('bot')},{t:'Start distributed (click farm) simulation',f:()=>startSim('click_farm')},{t:'Start normal traffic',f:()=>startSim('normal')},{t:'Stop all simulations',f:async()=>{await api('/api/simulation/stop',{method:'POST'});toast('Simulations stopped')}}];
let psel=0,plist=[];
function openPalette(){$('#palette').classList.add('on');$('#pin').value='';$('#pin').focus();fillPalette()}
function openHelp(key){const p=PAGES.find(x=>x[0]===key)||PAGES[0];const h=p[4];
  const html='<div class="box" style="max-width:720px"><h3>'+esc(p[1])+' — Help</h3>'
    +'<div class="help"><p><strong>What it does:</strong> '+esc(h.what)+'</p>'
    +'<p><strong>How to use:</strong></p><ol>'+h.how.map(s=>'<li>'+esc(s)+'</li>').join('')+'</ol>'
    +'<p><strong>Controls:</strong> '+esc(h.controls)+'</p>'
    +'<p><strong>Normal:</strong> '+esc(h.calm)+'<br><strong>Worry when:</strong> '+esc(h.worry)+'</p>'
    +'<p><strong>Tips:</strong></p><ul>'+h.tips.map(s=>'<li>'+esc(s)+'</li>').join('')+'</ul>'
    +'<p><strong>Related:</strong> '+h.related.map(r=>'<a href="#" onclick="go("user");closeHelp();return false">'+r+'</a>').join(', ')+'</p></div>'
    +'<div class="row-f"><button onclick="closeHelp()">Close (Esc)</button></div></div>'
  $('#confirm').innerHTML=html;$('#confirm').classList.add('on');document.body.addEventListener('keydown',escKeyHelp,{once:true})}
function closeHelp(){$('#confirm').classList.remove('on');$('#confirm').innerHTML='';document.body.removeEventListener('keydown',escKeyHelp,{once:true})}
function escKeyHelp(e){if(e.key==='Escape')closeHelp()}
function fillPalette(){const q=$('#pin').value.toLowerCase();const items=[];
  for(const [k,l,h] of VIEWS)if(k.includes(q)||l.toLowerCase().includes(q))items.push('<li onclick="go("user");closePalette()"><kbd>'+h+'</kbd> '+l+'</li>');
  for(const p of PAGES)if(p[4]&&(p[0].includes(q)||p[1].toLowerCase().includes(q)))items.push('<li onclick="go("user");closePalette()"><kbd>'+p[2]+'</kbd> '+p[1]+' ('+p[4].what.slice(0,40)+'…)</li>');
  $('#plist').innerHTML=items.join('')||'<li class="muted">No matches</li>'});
  psel=0;$('#plist').innerHTML=plist.map((c,i)=>`<li class="${i===0?'sel':''}" data-i="${i}">${esc(c.t)}</li>`).join('')}
$('#pin').oninput=fillPalette;
$('#plist').onclick=e=>{const li=e.target.closest('li');if(li)runPal(+li.dataset.i)};
function runPal(i){$('#palette').classList.remove('on');plist[i]&&plist[i].f()}
$('#pin').onkeydown=e=>{if(e.key==='Enter')runPal(psel);else if(e.key==='ArrowDown'||e.key==='ArrowUp'){psel=(psel+(e.key==='ArrowDown'?1:-1)+plist.length)%plist.length;$$('#plist li').forEach((l,i)=>l.classList.toggle('sel',i===psel));e.preventDefault()}};
document.addEventListener('keydown',e=>{const typing=/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
  if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openPalette();return}
  if(e.key==='Escape'){$('#palette').classList.remove('on');closeDrawer();return}
  if(typing)return;if(e.key===' '&&S.view==='cmd'){e.preventDefault();togglePause()}
  else if(e.key==='/'){const f=$('#flt');if(f){e.preventDefault();f.focus()}}
  else if(/^[0-9]$/.test(e.key)){go(VIEWS[(+e.key+9)%10][0])}});
$('#palette').onclick=e=>{if(e.target.id==='palette')$('#palette').classList.remove('on')};

/* ---------------- auth ---------------- */
function ensureAuth(){
  const t=localStorage.getItem("aegis_token");
  if(!t){showLogin();return Promise.resolve(false)}
  return api("/api/me").then(r=>{Auth.token=t;Auth.email=r.email;Auth.role=r.role;return true})
         .catch(()=>{localStorage.removeItem("aegis_token");showLogin();return false});
}
function showLogin(){$('#login').classList.add("on");$('#lemail').focus()}
function hideLogin(){$('#login').classList.remove("on")}
async function login(){
  const e=$('#lemail').value.trim(),p=$('#lpass').value,r=$('#lrole').value;
  $('#lerr').style.display="none";
  try{
    const res=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:e,password:p,role:r})});
    Auth.token=res.token;Auth.email=res.email;Auth.role=res.role;
    localStorage.setItem("aegis_token",res.token);
    hideLogin();window.onAuthed();
  }catch(err){$('#lerr').textContent=err.message;$('#lerr').style.display="block"}}
function logout(){Auth.token="";Auth.email="";Auth.role="viewer";localStorage.removeItem("aegis_token");S.ws&&S.ws.close();location.reload()}

/* ---------------- boot ---------------- */
function logout(){Auth.token='';S.ws&&S.ws.close();location.reload()}
function onMsg(m){
  if(m.type==='hello'){S.stats=m.stats;S.health=m.health;S.events=m.recent.slice().reverse();renderSys();drawKpis();drawStream(true);drawDist()}
  else if(m.type==='decisions'){const items=m.items.slice().reverse();track(m.items);
    for(const e of items)if(e.blocked){S.blk=(S.blk||0)+1;S.blkLast=e;if(!S.blkT)S.blkT=setTimeout(()=>{toast(S.blk===1?'USER '+S.blkLast.user+' BLOCKED (risk '+S.blkLast.risk.toFixed(2)+')':S.blk+' users auto-blocked (latest '+S.blkLast.user+')',true);S.blk=0;S.blkT=null},1500)}
    if(!S.paused){items.forEach(e=>S.fresh.add(e.id));S.events=items.concat(S.events).slice(0,400);if(S.view==='cmd')drawStream(false)}
    else S.pending=items.concat(S.pending).slice(0,400)}
  else if(m.type==='stats'){S.stats=m.stats;S.health=m.health;renderSys();$('#alertBadge').textContent='ALERTS '+m.alerts_open;if(S.view==='cmd'){drawKpis();drawDist();drawTl()}}
  else if(m.type==='reset'){toast('Data cleared: '+(m.scopes||[]).join(', '));reloadAfterReset()}}
window.onAuthed=()=>{$('#who').textContent=Auth.email+' ['+Auth.role+']';S.ws&&S.ws.close();S.ws=connectWS(onMsg,ok=>{if(!ok)$('#foot').textContent='websocket reconnecting...'});routeOnBoot()};
(async()=>{if(await ensureAuth())window.onAuthed()})();
