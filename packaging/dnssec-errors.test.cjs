const test = require('node:test');
const assert = require('node:assert/strict');
const {dnssecNote:n}=require('./domain.cjs');
test('resolver failures are unknown rather than proof of missing DNSSEC',()=>{
 for(const Status of [1,2,5,NaN,Infinity]) assert.match(n({Status}),/kontrol edilemedi/);
 assert.match(n({Status:0,Answer:[]}),/DNSSEC yok/);
 assert.match(n({Status:0,Answer:[{type:43,data:'x'}]}),/DS kaydı/);
});
