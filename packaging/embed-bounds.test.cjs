const test = require('node:test');
const assert = require('node:assert/strict');
const {fitFields:f,codeBlock}=require('./domain.cjs');
test('embed limits hold for oversized names, values, field counts and tiny budgets',()=>{
 for(const budget of [0,1,20,100,5500]) {
  const out=f(Array.from({length:60},()=>({name:'n'.repeat(300),value:'v'.repeat(2000)})),budget);
  assert.ok(out.length<=25);
  assert.ok(out.reduce((n,x)=>n+x.name.length+x.value.length,0)<=budget);
  assert.ok(out.every(x=>x.name.length>0&&x.name.length<=256&&x.value.length>0&&x.value.length<=1024));
 }
 assert.ok(codeBlock(['a'.repeat(998)+'😀😀']).isWellFormed());
});

test('shortened record blocks retain their closing fence',()=>{
 const out=f([{name:'TXT',value:codeBlock(['a'.repeat(1000)])}],100);
 assert.ok(out[0].value.startsWith('```\n'));
 assert.ok(out[0].value.endsWith('\n```'));
 assert.ok(out[0].value.length+out[0].name.length<=100);
});
