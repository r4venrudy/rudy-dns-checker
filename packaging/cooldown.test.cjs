const test = require('node:test');
const assert = require('node:assert');
const { createCooldown, secondsFromEnv } = require('./cooldown.cjs');

test('a user waits out the cooldown, other users are not affected', () => {
  let t = 1000;
  const cd = createCooldown(10000, () => t);
  assert.strictEqual(cd.take('a'), 0);
  assert.strictEqual(cd.take('b'), 0);
  t += 4000;
  assert.strictEqual(cd.take('a'), 6000);
  t += 6000;
  assert.strictEqual(cd.take('a'), 0);
});

test('secondsFromEnv falls back on missing or invalid values', () => {
  assert.strictEqual(secondsFromEnv('30', 10), 30);
  assert.strictEqual(secondsFromEnv('0', 10), 0);
  assert.strictEqual(secondsFromEnv(undefined, 10), 10);
  assert.strictEqual(secondsFromEnv('', 10), 10);
  assert.strictEqual(secondsFromEnv('abc', 10), 10);
  assert.strictEqual(secondsFromEnv('-1', 10), 10);
});
