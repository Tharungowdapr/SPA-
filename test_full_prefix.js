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
function navItem(v){return '<a data-v="'+v[0]+'" tabindex="0" onclick="go('+JSON.stringify(v[0])+')" onkeydown="if(event.key===\'Enter\')go('+JSON.stringify(v[0])+')">'+v[1]+'<kbd>'+v[2]+'</kbd></a>'};

const groupOrder=[["overview",["start","cmd","alerts","user"]],["analysis",["incidents","analytics","target","campaigns","logs","patterns","saved","search"]],["ml",["models","pipeline"]],["admin",["blocklist","rules","settings","datarst"]]]
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
  else{toast('That alert has no user attached');go('alerts')}catch(e){toast(e.message);go('alerts')}}
async function investigateAlert(id){await resolveAlertRoute(id)}
addEventListener('hashchange',()=>{if(!S.suppressHash)onRoute()})
addEventListener('keydown',e=>{if(e.key==='?'&&e.target.tagName!=='INPUT'&&e.target.tagName!=='TEXTAREA'){e.preventDefault();openHelp(S.view)}})

// ---------- Helpers ----------
const $=id=>document.getElementById(id);
const $$=sel=>Array.from(document.querySelectorAll(sel));
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&','<':'<','>':'>','"':'"',"'":'''}[c]));
const tag=l=>'<span class="tag '+{LOW:'ok',MEDIUM:'warn',HIGH:'hi',CRITICAL:'crit'}[l]+'">'+esc(l)+'</span>';
const toast=(msg,sticky)=>{const t=document.createElement('div');t.className='toast'+(sticky?' sticky':'');t.textContent=msg;$('#toasts').appendChild(t);if(!sticky)setTimeout(()=>t.remove(),4000)};
const every=(fn,ms)=>{fn();S.timers.push(setInterval(fn,ms))};
const safe=async(el,fn)=>{try{await fn()}catch(e){if(el)el.innerHTML='<div class="empty">ERROR: '+esc(e.message)+'</div>'}};
const hms=ts=>new Date(ts*1000).toISOString().slice(11,19);
const fmt=(n,p)=>{if(n===null||n===undefined)return'';return Number(n).toFixed(p)};
const pct=n=>n===null||n===undefined?'':(n*100).toFixed(1)+'%';
const factorBars=arr=>arr.map(f=>'<div class="bar"><i style="width:'+Math.min(100,Math.max(0,f.impact*100))+'%"></i><span>'+esc(f.name)+' '+f.impact.toFixed(2)+'</span></div>').join('');
const debounce=(fn,ms)=>{let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms)}};
const confirmBox=(msg,onYes)=>{const html='<div class="box"><p>'+esc(msg)+'</p><div class="row-f"><button onclick="closeConfirm()">Cancel</button><button class="p" onclick="closeConfirm();('+onYes.toString()+')()">Confirm</button></div></div>';$('#confirm').innerHTML=html;$('#confirm').classList.add('on')};
function closeConfirm(){$('#confirm').classList.remove('on');$('#confirm').innerHTML=''}

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
function renderSys(){const h=S.health,s=S.stats;if(!h)return;
  const c=h.components,d=k=>'<span><span class="dot '+esc(c[k]?.state)+'"></span>'+k+'</span>';
  $('#sys').innerHTML='<span><span class="dot '+esc(h.status)+'"></span>SYSTEM '+esc(h.status)+'</span>'+
    ['bus','state','database','ml','anomaly','graph','online','agent'].concat(c.neo4j?['neo4j']:[]).map(d).join('')+'<span class="muted">'+esc(h.mode)+'</span>';
  if(s)$('#foot').textContent='model '+s.model_version+' | '+fmt(s.events_per_sec,1)+' ev/s | p50 '+s.latency_ms.p50+'ms p95 '+s.latency_ms.p95+'ms | bus '+s.bus.mode+' lag '+s.bus.lag+' | drift '+s.drift_psi.toFixed(3)}

function connectWS(cb,onClose){const p=location.protocol==='https:'?'wss:':'ws:';const ws=new WebSocket(p+'//'+location.host+'/ws?token='+encodeURIComponent(Auth.token));
  ws.onopen=()=>cb(ws);ws.onmessage=e=>{try{cb.onmessage(JSON.parse(e.data))}catch{}};ws.onclose=()=>onClose(false);ws.onerror=()=>onClose(false);return ws

function render(){const m=$('#main');({cmd:vCmd,user:vUser,analytics:vAnalytics,campaigns:vCampaigns,models:vModels,pipeline:vPipeline,blocklist:vBlocklist,alerts:vAlerts,rules:vRules,settings:vSettings,datarst:vDataReset,
  incidents:vIncidents,incident:vIncident,combined:vCombined,target:vTarget,logs:vLogs,saved:vSaved,savedDetail:vSavedDetail,patterns:vPatterns,patternDetail:vPatternDetail,search:vSearch,start:vStart}[S.view]||vCmd)(m)}

function openPalette(){$('#palette').classList.add('on');$('#pin').value='';$('#pin').focus();fillPalette()}
function closePalette(){$('#palette').classList.remove('on')}

function fillPalette(){const q=$('#pin').value.toLowerCase();const items=[];
  for(const [k,l,h] of VIEWS)if(k.includes(q)||l.toLowerCase().includes(q))items.push('<li onclick="go('+JSON.stringify(k)+');closePalette()"><kbd>'+h+'</kbd> '+l+'</li>');
  for(const p of PAGES)if(p[4]&&(p[0].includes(q)||p[1].toLowerCase().includes(q)))items.push('<li onclick="go('+JSON.stringify(p[0])+');closePalette()"><kbd>'+p[2]+'</kbd> '+p[1]+' ('+p[4].what.slice(0,40)+'...)</li>');
  $('#plist').innerHTML=items.join('')||'<li class="muted">No matches</li>';}

function openHelp(key){const p=PAGES.find(x=>x[0]===key)||PAGES[0];const h=p[4];
  const html='<div class="box" style="max-width:720px"><h3>'+esc(p[1])+' \u2014 Help</h3>'
    +'<div class="help"><p><strong>What it does:</strong> '+esc(h.what)+'</p>'
    +'<p><strong>How to use:</strong></p><ol>'+h.how.map(s=>'<li>'+esc(s)+'</li>').join('')+'</ol>'
    +'<p><strong>Controls:</strong> '+esc(h.controls)+'</p>'
    +'<p><strong>Normal:</strong> '+esc(h.calm)+'<br><strong>Worry when:</strong> '+esc(h.worry)+'</p>'
    +'<p><strong>Tips:</strong></p><ul>'+h.tips.map(s=>'<li>'+esc(s)+'</li>').join('')+'</ul>'
    +'<p><strong>Related:</strong> '+h.related.map(r=>'<a href="#" onclick="go('+JSON.stringify(r)+');closeHelp();return false">'+r+'</a>').join(', ')+'</p></div>'
    +'<div class="row-f"><button onclick="closeHelp()">Close (Esc)</button></div></div>'
  $('#confirm').innerHTML=html;$('#confirm').classList.add('on');document.body.addEventListener('keydown',escKeyHelp,{once:true})}
function closeHelp(){$('#confirm').classList.remove('on');$('#confirm').innerHTML='';document.body.removeEventListener('keydown',escKeyHelp,{once:true})}
function escKeyHelp(e){if(e.key==='Escape')closeHelp()}

function routeOnBoot(){if(location.hash)onRoute();else go('cmd')}

(async()=>{$('#login').innerHTML=LOGIN_HTML;if(await ensureAuth())window.onAuthed()})();