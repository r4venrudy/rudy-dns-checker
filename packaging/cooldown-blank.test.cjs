const test = require('node:test');
const assert = require('node:assert/strict');
const {secondsFromEnv:s}=require('./cooldown.cjs');
test('whitespace-only cooldown values retain the default',()=>{
 for(const v of [' ','\t','\n']) assert.equal(s(v,30),30);
 assert.equal(s('0',30),0); assert.equal(s(' 2.5 ',30),2.5);
});
