const code = 'function navItem(v){return \'<a data-v="\'+v[0]+\'" tabindex="0" onclick="go(\'+JSON.stringify(v[0])+\")\" onkeydown=\\\"if(event.key===\'Enter\')go(\'+JSON.stringify(v[0])+\")\\\">\'+v[1]+\'<kbd>\'+v[2]+\'</kbd></a>\'};';
console.log('Testing...');
try { new Function(code); console.log('OK'); } catch(e) { console.log('ERROR:', e.message); }