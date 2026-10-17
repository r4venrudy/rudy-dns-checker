const test = require('node:test');
const assert = require('node:assert/strict');
const {formatDate:f,daysUntil:d}=require('./whois-summary.cjs');
test('WHOIS dates reject calendar rollover and trailing garbage',()=>{
 const now=new Date('2026-01-01T00:00:00Z');
 for(const v of ['2026-02-31','2025-02-29','2026-13-01','2026-01-01garbage']) {
  assert.equal(d(v,now),null,v); assert.equal(f(v),v);
 }
 assert.equal(d('2028-02-29',new Date('2028-02-28T00:00:00Z')),1);
 assert.equal(f('2026-10-09T18:20:50+03:00'),'2026-10-09');
});
