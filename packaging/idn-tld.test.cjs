const test = require('node:test');
const assert = require('node:assert/strict');
const {normalizeDomain}=require('./domain.cjs');
test('internationalized TLDs normalize to validated ASCII labels',()=>{
 assert.equal(normalizeDomain('пример.рф'),'xn--e1afmkfd.xn--p1ai');
 assert.equal(normalizeDomain('xn--e1afmkfd.xn--p1ai'),'xn--e1afmkfd.xn--p1ai');
 for(const value of ['example.123','example.xn--','example.xn--bogus-']) assert.equal(normalizeDomain(value),null);
});
