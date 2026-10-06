import urllib.request, json, time

time.sleep(3)

resp = urllib.request.urlopen('http://localhost:8000/')
html = resp.read().decode('utf-8')
print('Page loads:', len(html), 'chars')
print('Login modal:', 'id="login"' in html)
print('LOGIN_HTML:', 'const LOGIN_HTML' in html)

login_data = json.dumps({'email': 'admin@aegis.local', 'password': 'admin123'}).encode()
req = urllib.request.Request('http://localhost:8000/api/auth/login', data=json.dumps({'email': 'admin@aegis.local', 'password': 'admin123'}).encode(), headers={'Content-Type': 'application/json'})
resp = urllib.request.urlopen(req)
result = json.loads(resp.read().decode())
print('Login API works:', 'token' in result)