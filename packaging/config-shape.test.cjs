const test = require('node:test');
const assert = require('node:assert/strict');
const {loadConfig}=require('./config.cjs');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
test('configuration supports UTF-8 BOM and rejects non-object roots clearly',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'rudy-config-')); const filename=path.join(dir,'config.json');
 try {
  fs.writeFileSync(filename,'\ufeff{"token":"abc"}');
  assert.equal(loadConfig({token:'TOKEN'},{env:{},filename}).token,'abc');
  for(const value of ['null','[]','"secret"']) {
   fs.writeFileSync(filename,value);
   assert.throws(()=>loadConfig({token:'TOKEN'},{env:{},filename}),/configuration must be a JSON object/i);
  }
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
