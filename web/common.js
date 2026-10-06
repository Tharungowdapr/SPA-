// Shared client helpers: auth, API, websocket, formatting. All dynamic text goes through esc()/textContent (XSS-safe).
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=(n,d=0)=>n==null?'-':Number(n).toLocaleString('en-US',{maximumFractionDigits:d,minimumFractionDigits:d});
const pct=(x,d=1)=>x==null?'-':(x*100).toFixed(d)+'%';
const hms=ts=>{const d=new Date(ts*1000);return d.toTimeString().slice(0,8)+'.'+String(d.getMilliseconds()).padStart(3,'0')};
const tag=v=>`<span class="tag ${esc(v)}">${esc(v)}</span>`;
const Auth={get token(){return localStorage.getItem('aegis_token')||''},set token(v){v?localStorage.setItem('aegis_token',v):localStorage.removeItem('aegis_token')},role:'',email:''};
async function api(path,opt={}){
  const h={'Content-Type':'application/json'};if(Auth.token)h.Authorization='Bearer '+Auth.token;
  const r=await fetch(path,{...opt,headers:h,body:opt.body!==undefined?JSON.stringify(opt.body):undefined});
  if(r.status===401){Auth.token='';showLogin();throw new Error('unauthorized')}
  const t=await r.text();let j;try{j=JSON.parse(t)}catch{j=t}
  if(!r.ok)throw new Error((j&&j.detail)?(typeof j.detail==='string'?j.detail:JSON.stringify(j.detail)):('HTTP '+r.status));
  return j}
function toast(msg,crit){const box=$('#toasts');while(box.children.length>=4)box.firstChild.remove();const t=document.createElement('div');t.className='toast'+(crit?' crit':'');t.textContent=msg;$('#toasts').appendChild(t);setTimeout(()=>t.remove(),4200)}
function showLogin(){$('#login').classList.add('on');$('#lemail').focus()}
async function doLogin(){
  try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('#lemail').value,password:$('#lpass').value})});
    const j=await r.json();if(!r.ok)throw new Error(j.detail||'login failed');Auth.token=j.token;Auth.role=j.role;Auth.email=j.email;$('#login').classList.remove('on');$('#lerr').textContent='';window.onAuthed&&window.onAuthed()}
  catch(e){$('#lerr').textContent=e.message}}
async function ensureAuth(){
  if(Auth.token){try{const m=await api('/api/me');Auth.role=m.role;Auth.email=m.email;return true}catch{}}
  showLogin();return false}
function connectWS(onMsg,onState){
  let ws,retry=500,dead=false;
  const open=()=>{ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws?token='+encodeURIComponent(Auth.token));
    ws.onopen=()=>{retry=500;onState&&onState(true)};
    ws.onmessage=e=>{try{onMsg(JSON.parse(e.data))}catch(err){console.error(err)}};
    ws.onclose=ev=>{onState&&onState(false);if(!dead&&ev.code!==4401)setTimeout(open,retry=Math.min(retry*2,8000))}};
  open();return{close(){dead=true;ws&&ws.close()}}}
const LOGIN_HTML=`<div class="box"><div class="brand" style="margin-bottom:14px">FRAUD//CONTROL<small>REAL-TIME ADVERTISING INTELLIGENCE PLATFORM</small></div>
<label class="f" for="lemail">EMAIL</label><input id="lemail" autocomplete="username" value="analyst@aegis.local">
<label class="f" for="lpass">PASSWORD</label><input id="lpass" type="password" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()">
<button class="p" style="width:100%" onclick="doLogin()">SIGN IN</button><div id="lerr" class="muted" style="margin-top:8px;color:var(--crit)"></div>
<div class="hint" style="margin-top:8px">Demo accounts: admin@ / analyst@ / viewer@aegis.local (see README)</div></div>`;
