const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadConfig } = require('./config.cjs');
const spec = { token: 'DISCORD_TOKEN', clientId: 'CLIENT_ID' };
test('missing credentials fail with names only', () => {
  assert.throws(() => loadConfig(spec, {env: {}, filename: '/does-not-exist-rudy'}), /Missing configuration: DISCORD_TOKEN, CLIENT_ID/);
});
test('environment overrides a local file without changing it', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rudy-config-'));
  const filename = path.join(dir, 'config.json');
  const original = JSON.stringify({ token: 'old-dummy', clientId: '12345678901234567' });
  try {
    fs.writeFileSync(filename, original);
    const config = loadConfig(spec, {env: { DISCORD_TOKEN: 'new-dummy' }, filename});
    assert.equal(config.token, 'new-dummy');
    assert.equal(config.clientId, '12345678901234567');
    assert.equal(fs.readFileSync(filename, 'utf8'), original);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('invalid application IDs and placeholder credentials fail', () => {
  assert.throws(() => loadConfig(spec, {env: { DISCORD_TOKEN:'private-dummy', CLIENT_ID:'invalid' }, filename:'/does-not-exist-rudy'}), error => !error.message.includes('private-dummy') && /CLIENT_ID/.test(error.message));
  assert.throws(() => loadConfig(spec, {env: { DISCORD_TOKEN:'YOUR_DISCORD_TOKEN', CLIENT_ID:'12345678901234567' }, filename:'/does-not-exist-rudy'}), /Missing configuration/);
});
