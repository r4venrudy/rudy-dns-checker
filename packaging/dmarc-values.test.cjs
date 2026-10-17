const test = require('node:test');
const assert = require('node:assert/strict');
const {gradeEmailSecurity:g}=require('./domain.cjs');
test('DMARC rejects duplicate and malformed policies and invalid percentages',()=>{
 for(const tail of ['p=reject-junk','p=reject; p=none','p=reject; pct=101','p=reject; pct=20oops','p=reject; pct=-1','p=reject; sp=none-junk']) {
  const notes=g([], [['v=DMARC1; '+tail]]).notes;
  assert.ok(notes.some(n=>n.includes('geçersiz')),tail);
  assert.ok(!notes.some(n=>n==='✅ DMARC p=reject'),tail);
 }
 assert.ok(g([], [['v=DMARC1; p = reject; pct = 0']]).notes.includes('✅ DMARC p=reject'));
});
