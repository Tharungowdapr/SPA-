import urllib.request, json

# Test login
login_data = json.dumps({'email': 'admin@aegis.local', 'password': 'admin123', 'role': 'admin'}).encode()
req = urllib.request.Request('http://localhost:8000/api/auth/login', data=login_data, headers={'Content-Type': 'application/json'})
resp = urllib.request.urlopen(req)
token = json.loads(resp.read().decode())['token']
print('Login successful, token:', token[:30] + '...')

# Check page
resp = urllib.request.urlopen('http://localhost:8000/')
html = resp.read().decode('utf-8')
print('Page loads:', len(html), 'chars')
print('Login modal:', 'id="login"' in html)
print('LOGIN_HTML:', 'const LOGIN_HTML' in html)
print('showLogin correct:', 'innerHTML=LOGIN_HTML' in html)