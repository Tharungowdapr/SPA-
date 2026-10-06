with open('web/sim.html', 'r', encoding='utf-8') as f:
    content = f.read()
idx = content.find('events ${fmt(s.events_per_sec,1)}')
if idx != -1:
    print(repr(content[idx-200:idx+300]))