const fs = require('fs');
const code = fs.readFileSync('extracted.js', 'utf8');

const idx = code.indexOf('function navItem(v){return ');
const endIdx = code.indexOf('const groupOrder=', idx);
const funcCode = code.substring(idx, endIdx);

console.log('Full function code:');
console.log(funcCode);
console.log('---');
console.log('Length:', funcCode.length);