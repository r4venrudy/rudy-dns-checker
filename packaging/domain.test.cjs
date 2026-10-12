const test = require('node:test')
const assert = require('node:assert')
const { normalizeDomain, gradeEmailSecurity } = require('./domain.cjs')

test('normalizeDomain strips scheme, path, port and trailing dot', () => {
  assert.strictEqual(normalizeDomain('https://Example.com/path?q=1'), 'example.com')
  assert.strictEqual(normalizeDomain('itemsatis.com.'), 'itemsatis.com')
  assert.strictEqual(normalizeDomain('sub.domain.co.uk:443'), 'sub.domain.co.uk')
})

test('normalizeDomain rejects non-hostnames', () => {
  for (const bad of ['not a domain', 'localhost', '-bad.com', '', null]) assert.strictEqual(normalizeDomain(bad), null)
})

test('strict SPF and DMARC reject', () => {
  const r = gradeEmailSecurity([['v=spf1 include:_spf.google.com -all']], [['v=DMARC1; p=reject']])
  assert.deepStrictEqual(r.notes, ['✅ SPF sıkı (-all)', '✅ DMARC p=reject'])
})

test('missing and permissive records are flagged', () => {
  assert.deepStrictEqual(gradeEmailSecurity([], []).notes, ['❌ SPF kaydı yok', '❌ DMARC kaydı yok'])
  assert.match(gradeEmailSecurity([['v=spf1 +all']], []).notes[0], /gevşek/)
  assert.match(gradeEmailSecurity([['v=spf1 -all'], ['v=spf1 ~all']], []).notes[0], /Birden fazla/)
})

test('SPF split across TXT strings is joined', () => {
  const r = gradeEmailSecurity([['v=spf1 include:a.example ', '-all']], [])
  assert.strictEqual(r.spf, 'v=spf1 include:a.example -all')
})
