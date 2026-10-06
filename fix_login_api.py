import io

P = "web/control.html"
s = io.open(P, encoding="utf-8").read()

# Find the main script tag
script_start = s.index('<script>', 1362)
script_end = s.index('</script>', s.index('<script>', 1362))
script = s[script_start + 8:script_end]

# Fix the login function - remove role from request
old = '''async function login(){
  const e=$('#lemail').value.trim(),p=$('#lpass').value,r=$('#lrole').value;
  $('#lerr').style.display="none";
  try{
    const res=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:e,password:p,role:r})});
    Auth.token=res.token;Auth.email=res.email;Auth.role=res.role;
    localStorage.setItem("aegis_token",res.token);
    hideLogin();window.onAuthed();
  }catch(err){$('#lerr').textContent=err.message;$('#lerr').style.display="block"}}'''

new = '''async function login(){
  const e=$('#lemail').value.trim(),p=$('#lpass').value;
  $('#lerr').style.display="none";
  try{
    const res=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:e,password:p})});
    Auth.token=res.token;Auth.email=res.email;Auth.role=res.role;
    localStorage.setItem("aegis_token",res.token);
    hideLogin();window.onAuthed();
  }catch(err){$('#lerr').textContent=err.message;$('#lerr').style.display="block"}}'''

assert old in script, "old login not found"
script = script.replace(old, new)

# Rebuild
script_start = s.index('<script>', 1362)
script_end = s.index('</script>', s.index('<script>', 1362))
new_s = s[:script_start + 8] + script + s[script_end:]

io.open("web/control.html", "w", encoding="utf-8").write(new_s)
print("Fixed login function - removed role from request")