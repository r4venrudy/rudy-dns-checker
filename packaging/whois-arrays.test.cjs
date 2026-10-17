const test = require('node:test');
const assert = require('node:assert/strict');
const {whoisSummary:s}=require('./whois-summary.cjs');
test('WHOIS picks a nonempty value after blank array entries',()=>{
 assert.equal(s({a:{Registrar:['',null,'  Actual Registrar  ']},b:{Registrar:'Other'}}).registrar,'Actual Registrar');
 assert.equal(s({a:{'Expiry Date':[null,'','2027-01-01']}}).expires,'2027-01-01');
});
