with open('web/sim.html', 'r', encoding='utf-8') as f:
    content = f.read()
idx = content.find('await api(')
if idx != -1:
    print('Found at:', idx)
    print(repr(content[idx:idx+200]))
else:
    print('Not found')