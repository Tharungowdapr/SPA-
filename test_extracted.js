// Read the exact code from extracted.js
const fs = require('fs');
const code = fs.readFileSync('extracted.js', 'utf8');

// Extract just the navItem function
const idx = code.indexOf('function navItem(v){return ');
const endIdx = code.indexOf('const groupOrder=', idx);
const funcCode = code.substring(idx, endIdx).trim() + '};';

console.log('Code length:', funcCode.length);
console.log('First 200:', funcCode.substring(0, 200));

try {
    new Function(funcCode);
    console.log('OK');
} catch(e) {
    console.log('ERROR:', e.message);
    console.log('Stack:', e.stack);
}