const test = require('node:test');
const assert = require('node:assert/strict');
const {mailTransportNotes:n}=require('./domain.cjs');
test('mail transport record versions must match complete tags',()=>{
 const notes=n([['v=STSv10; id=a']],[['v=TLSRPTv10; rua=x']],[['v=BIMI10; l=x']]);
 assert.ok(!notes.some(x=>x.startsWith('✅')));
 assert.ok(n([['v=STSv1 ; id=a']],[])[0].startsWith('✅'));
});
