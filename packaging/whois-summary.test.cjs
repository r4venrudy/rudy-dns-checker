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
