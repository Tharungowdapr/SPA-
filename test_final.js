$('#login').innerHTML=LOGIN_HTML;
const S={user:null,ad:null,users:[],ads:[],stats:null,timers:[]};
async function loadUsers(){try{S.users=await api('/api/users?limit=200');drawUsers()}catch{}}
function drawUsers(){$('#ucount').textContent=S.users.length+' | blocked '+S.users.filter(u=>u.blocked).length;
  $('#users').innerHTML=S.users.map(u=>`<div class="ucard ${u.blocked?'blocked':''} ${S.user===u.user_id?'sel':''}" tabindex="0" data-u="${esc(u.user_id)}">
   <b class="m">${esc(u.user_id)}</b><span class="hint m">${esc(u.device_id)} ${esc(u.ip)} ${esc(u.country)} age ${esc(u.account_age_days)}d<br>risk ${(u.risk).toFixed(2)}</span>${u.blocked?'<span class="tag CRITICAL">&#9679; BLOCKED</span>':`<span class="tag ${esc(u.level)}">${esc(u.level)}</span>`}</div>`).join('')}
$('#users').onclick=e=>{const c=e.target.closest('.ucard');if(c){S.user=c.dataset.u;drawUsers();info()}};
async function loadAds(){S.ads=await api('/api/ads');$('#ads').innerHTML=S.ads.map(a=>`<div class="ad m" tabindex="0" data-a="${esc(a.ad_id)}">${esc(a.ad_id)}<br><span class="hint">${esc(a.campaign_id)}</span></div>`).join('');
  const cs=[...new Set(S.ads.map(a=>a.campaign_id))];$('#tc').innerHTML='<option value="">any</option>'+cs.map(c=>`<option>${esc(c)}</option>`).join('')}
$('#ads').onclick=e=>{const a=e.target.closest('.ad');if(a){S.ad=a.dataset.a;$$('.ad').forEach(x=>x.classList.toggle('sel',x===a));info()}};
function info(){$('#selinfo').textContent=(S.user||'?')+' -> '+(S.ad||'?')}
async function click(profile,count){if(!S.user||!S.ad){toast('Select a user and an ad first');return}
  try{const r=await api('/api/clicks',{method:'POST',body:{user_id:S.user,ad_id:S.ad,count,profile}});
   $('#clickres').textContent=`accepted ${r.accepted} | rejected ${r.rejected}`+(r.blocked?' | USER BLOCKED':'');const d=r.decision;
   $('#last').innerHTML=d?`<div class="row-f">${tag(d.level)} ${tag(d.action)} <span class="m">risk ${d.risk.toFixed(3)}</span></div><div class="hint m">rules: ${esc((d.rules||[]).join(', ')||'none')}</div>${r.blocked?`<div style="margin-top:6px;color:var(--crit)" class="m">${esc(S.user)} &#9679; BLOCKED<br>Reason: high fraud probability<br>Fraud score: ${(d.risk*100).toFixed(1)}%</div>`:''}`:''`;
   if(r.blocked)toast(S.user+' BLOCKED',true);loadUsers()}catch(e){toast(e.message)}}
$('#c1').onclick=()=>click('normal',1);$('#c2').onclick=()=>click('rapid',50);$('#c3').onclick=()=>click('bot',30);
$('#int').oninput=e=>$('#iv').textContent=(+e.target.value).toFixed(1);
$('#start').onclick=async()=>{const b={intensity:+$('#int').value,duration:+$('#dur').value};if($('#nu').value)b.number_of_users=+$('#nu').value;if($('#cr').value)b.click_rate=+$('#cr').value;if($('#tc').value)b.target_campaign=$('#tc').value;if($('#tu').value)b.target_users=$('#tu').value.split(',').map(s=>s.trim()).filter(Boolean);if($('#atk').value)b.attack_type=$('#atk').value;
  try{const r=await api('/api/simulation/'+$('#kind').value,{method:'POST',body:b});toast('Simulation running: '+r.kind+' ('+r.total+' events)')}catch(e){toast(e.message)}};
$('#stop').onclick=async()=>{try{const r=await api('/api/simulation/stop',{method:'POST'});toast('Stopped '+r.stopped+' run(s)')}catch(e){toast(e.message)}};
async function loadRuns(){
async function loadRuns(){
 try{
  const r=await api('/api/simulation/status');
  if(!r.length){$('#runs').innerHTML='<span class="muted">idle</span>'}
  else{$('#runs').innerHTML=r.slice(0,5).map(x=>'<div style="margin:4px 0"><span class="tag '+(x.state==='running'?'MEDIUM':'LOW')+'">'+esc(x.state)+'</span> #'+x.id+' '+esc(x.kind)+' '+x.emitted+'/'+x.total+' rejected '+x.rejected+'</div>').join('')}
  const h=await api('/api/simulations/saved');
  if(!h.length){$('#hist').innerHTML='<div class="empty">no saved attacks</div>';return}
  $('#hist').innerHTML='<table>'+h.map(s=>{
   const cells='<td class="m">#'+s.id+'</td><td>'+esc(s.name)+'</td><td>'+esc(s.kind)+'</td>'
     +'<td class="m">'+s.events+' ev</td><td>'+esc(s.duration||'')+'s</td>';
   const btns='<button class="ghost" data-s="'+s.id+'" data-x="1">1x</button>'
     +'<button class="ghost" data-s="'+s.id+'" data-x="10">10x</button>'
     +'<button class="ghost" data-s="'+s.id+'" data-x="50">50x</button>'
     +'<button class="ghost" data-s="'+s.id+'" onclick="exportSim(\''+s.id+'\')">Export</button>'
     +'<button class="ghost" data-s="'+s.id+'" onclick="duplicateSim(\''+s.id+'\')">Dup</button>'
     +'<button class="ghost" data-s="'+s.id+'" onclick="compareSim(\''+s.id+'\')">Compare</button>'
     +'<button class="d" data-s="'+s.id+'" onclick="deleteSim(\''+s.id+'\')">Del</button>';
   return '<tr>'+cells+'<td>'+btns+'</td></tr>'
  }).join('')+'</table>';
 }catch(e){toast(e.message)}
}
$('#hist').onclick=async e=>{const b=e.target.closest('button');if(!b)return;const id=b.dataset.s;
  if (b.dataset.x) {
      try {
        await api(\`/api/simulations/${id}/replay?speed=${b.dataset.x}\`, {method:'POST'});
        toast('Replaying #' + id + ' at ' + b.dataset.x + 'x through Kafka-style pipeline');
      } catch (er) {
        toast(er.message);
      }
    }
  else if(b.onclick&&b.onclick.toString().includes('exportSim')){exportSim(id)}
  else if(b.onclick&&b.onclick.toString().includes('duplicateSim')){duplicateSim(id)}
  else if(b.onclick&&b.onclick.toString().includes('compareSim')){compareSim(id)}
  else if(b.onclick&&b.onclick.toString().includes('deleteSim')){deleteSim(id)}
}
async function exportSim(id){try{const d=await api('/api/simulations/'+id+'/export');const blob=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='attack-'+id+'.json';a.click();URL.revokeObjectURL(url);toast('Exported attack-'+id+'.json')}catch(e){toast(e.message)}
async function duplicateSim(id){try{const d=await api('/api/simulations/'+id+'/export');const r=await api('/api/simulations/import',{method:'POST',body:d});toast('Duplicated as #'+r.id+': '+r.name);loadRuns()}catch(e){toast(e.message)}}
async function compareSim(id){const other=prompt('Compare with simulation ID:');if(!other)return;try{const c=await api('/api/simulations/compare?a='+id+'&b='+other);alert('Compare: A('+c.a.name+') '+c.a.decisions+' decisions, peak '+c.a.peak_risk.toFixed(3)+' vs B('+c.b.name+') '+c.b.decisions+' decisions, peak '+c.b.peak_risk.toFixed(3));}catch(e){toast(e.message)}}
async function deleteSim(id){if(!confirm('Delete saved attack #'+id+'?'))return;try {await api('/api/simulations/'+id+'?confirm=true',{method:'DELETE'});toast('Deleted');loadRuns()}catch(e){toast(e.message)}}
$('#hist').onclick=async e=>{const b=e.target.closest('button');if(!b)return;const id=b.dataset.s;
  if (b.dataset.x) {
        try {
            await api(`/api/simulations/${id}/replay?speed=${b.dataset.x}`,{method:'POST'});
            toast('Replaying #' + id + ' at ' + b.dataset.x + 'x through Kafka-style pipeline');
        } catch (er) {
            toast(er.message);
        }}
  else if(b.onclick&&b.onclick.toString().includes('exportSim')){exportSim(id)}
  else if(b.onclick&&b.onclick.toString().includes('duplicateSim')){duplicateSim(id)}
  else if(b.onclick&&b.onclick.toString().includes('compareSim')){compareSim(id)}
  else if(b.onclick&&b.onclick.toString().includes('deleteSim')){deleteSim(id)}
}
function onMsg(m){if(m.type==='stats'){S.stats=m.stats;const s=m.stats;$('#foot').textContent=`events ${fmt(s.total_events)} | ${fmt(s.events_per_sec,1)} ev/s | flagged ${fmt(s.flagged)} | blocked users ${s.blocked_users} | rejected clicks ${fmt(s.rejected)} | p50 ${s.latency_ms.p50}ms`;
  $('#sys').innerHTML=`<span><span class="dot ${esc(m.health.status)}"></span>${esc(m.health.status)}</span><span class="muted">${esc(m.health.mode)}</span>`}
  else if(m.type==='decisions'&&m.items.some(i=>i.blocked)){loadUsers()}\r\nwindow.onAuthed=async()=>{$('#who').textContent=Auth.email+' ['+Auth.role+']';await loadAds();await loadUsers();connectWS(onMsg);setInterval(loadUsers,3000);setInterval(loadRuns,2000);loadRuns()};
(async()=>{if(await ensureAuth())window.onAuthed()})();