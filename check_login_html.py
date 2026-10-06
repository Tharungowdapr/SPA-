import urllib.request

resp = urllib.request.urlopen('http://localhost:8000/')
html = resp.read().decode('utf-8')

idx = html.find('const LOGIN_HTML')
if idx != -1:
    end = html.find('`;', idx) + 2
    print(html[idx:end])
else:
    print('LOGIN_HTML not found')