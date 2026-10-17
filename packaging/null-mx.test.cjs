const test = require('node:test');
const assert = require('node:assert/strict');
const {formatMx:f}=require('./domain.cjs');
test('null MX is recognized only at priority zero',()=>{
 assert.deepEqual(f([{priority:10,exchange:'.'}]),['10 .']);
 assert.deepEqual(f([{priority:20,exchange:''}]),['20 ']);
 assert.match(f([{priority:0,exchange:'.'}])[0],/Null MX/);
});
