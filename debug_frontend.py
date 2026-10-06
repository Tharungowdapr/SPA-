import urllib.request

resp = urllib.request.urlopen('http://localhost:8000/')
html = resp.read().decode()

print('Login modal in HTML:', 'id="login"' in html)
print('LOGIN_HTML constant:', 'LOGIN_HTML' in html)
print('ensureAuth call:', 'ensureAuth' in html)

idx = html.find('window.onAuthed')
if idx != -1:
    print('window.onAuthed found at:', idx)
    print('Context:', html[idx:idx+200])

# Check for script tags
scripts = html.count('<script')
print('Script tags:', scripts)

# Check for common issues
print('ensureAuth call:', 'ensureAuth()' in html)
print('showLogin:', 'showLogin' in html)
print('LOGIN_HTML assignment:', 'innerHTML=LOGIN_HTML' in html)

# Check for errors in HTML
if 'SyntaxError' in html or 'ReferenceError' in html:
    print('JS Errors in HTML:', True)

# Print first 5000 chars
print('\n--- First 5000 chars ---')
print(html[:5000])