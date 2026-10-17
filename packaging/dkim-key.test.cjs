const test = require('node:test');
const assert = require('node:assert/strict');
const {summarizeDkim:s}=require('./domain.cjs');
test('DKIM requires a public-key tag and an exact supported version',()=>{
 for(const txt of ['v=DKIM1; k=rsa','v=DKIM10; p=AAAA','v=DKIM1; p=AAAA; p=BBBB'])
  assert.match(s([{selector:'s1',txt:[[txt]]}]),/bulunamadı/);
 assert.match(s([{selector:'s1',txt:[['p=AAAA']]}]),/bulundu/);
 assert.match(s([{selector:'s1',txt:[['v=DKIM1; p=']]}]),/İptal/);
});
