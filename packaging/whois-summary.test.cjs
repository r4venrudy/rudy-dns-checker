const test = require('node:test');
const assert = require('node:assert');
const { whoisSummary } = require('./whois-summary.cjs');

test('takes the first non-empty value across WHOIS servers', () => {
  const results = {
    'whois.verisign-grs.com': { 'Registrar': 'MarkMonitor Inc.', 'Created Date': '2007-10-09T18:20:50Z', 'Expiry Date': '' },
    'whois.markmonitor.com': { 'Registrar': 'MarkMonitor, Inc.', 'Expiry Date': ['2026-10-09T18:20:50Z'] }
  };
  assert.deepStrictEqual(whoisSummary(results), {
    registrar: 'MarkMonitor Inc.',
    created: '2007-10-09T18:20:50Z',
    expires: '2026-10-09T18:20:50Z'
  });
});

test('missing results give nulls', () => {
  assert.deepStrictEqual(whoisSummary(null), { registrar: null, created: null, expires: null });
});

const { formatDate, daysUntil } = require('./whois-summary.cjs');

test('formatDate shortens ISO timestamps and keeps unknown formats', () => {
  assert.strictEqual(formatDate('2026-10-09T18:20:50Z'), '2026-10-09');
  assert.strictEqual(formatDate('before Aug-1996'), 'before Aug-1996');
  assert.strictEqual(formatDate(null), null);
});

test('daysUntil counts whole days and handles bad input', () => {
  const now = new Date('2026-10-01T00:00:00Z');
  assert.strictEqual(daysUntil('2026-10-11T00:00:00Z', now), 10);
  assert.strictEqual(daysUntil('2026-09-30T00:00:00Z', now), -1);
  assert.strictEqual(daysUntil('garbage', now), null);
});

const { expiryText } = require('./whois-summary.cjs');

test('expiryText warns before expiry and reports an expired domain', () => {
  const now = new Date('2026-10-14T00:00:00Z');
  assert.strictEqual(expiryText('2027-05-01T00:00:00Z', now), '2027-05-01');
  assert.strictEqual(expiryText('2026-10-24T00:00:00Z', now), '2026-10-24 ⚠️ 10 gün kaldı');
  assert.strictEqual(expiryText('2026-10-09T00:00:00Z', now), '2026-10-09 ❌ süresi 5 gün önce dolmuş');
  assert.strictEqual(expiryText('before Aug-1996', now), 'before Aug-1996');
  assert.strictEqual(expiryText(null, now), null);
});
