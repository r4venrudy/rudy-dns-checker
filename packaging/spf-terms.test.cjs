const test = require('node:test');
const assert = require('node:assert/strict');
const {gradeEmailSecurity:g}=require('./domain.cjs');
test('only whole SPF all mechanisms determine the grade',()=>{
 for(const term of ['-all:bad','~all.foo','include:-all','+all/24','?all:bad'])
  assert.match(g([['v=spf1 '+term]],[]).notes[0],/bitmiyor/);
 assert.match(g([['v=spf1 -all']],[]).notes[0],/sıkı/);
 assert.match(g([['v=spf1 ~all']],[]).notes[0],/softfail/);
});
