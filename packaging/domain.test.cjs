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
  const r = gradeEmailSecurity([['v=spf1 include:_spf.google.com -all']], [['v=DMARC1; p=reject; rua=mailto:d@example.com']])
  assert.deepStrictEqual(r.notes, ['✅ SPF sıkı (-all)', '✅ DMARC p=reject'])
})

test('missing and permissive records are flagged', () => {
  assert.deepStrictEqual(gradeEmailSecurity([], []).notes, ['❌ SPF kaydı yok', '❌ DMARC kaydı yok'])
  assert.match(gradeEmailSecurity([['v=spf1 +all']], []).notes[0], /gevşek/)
  assert.match(gradeEmailSecurity([['v=spf1 mx all']], []).notes[0], /gevşek/)
  assert.match(gradeEmailSecurity([['v=spf1 -all'], ['v=spf1 ~all']], []).notes[0], /Birden fazla/)
})

test('SPF split across TXT strings is joined', () => {
  const r = gradeEmailSecurity([['v=spf1 include:a.example ', '-all']], [])
  assert.strictEqual(r.spf, 'v=spf1 include:a.example -all')
})

test('SPF redirect is not reported as missing an all mechanism', () => {
  assert.strictEqual(gradeEmailSecurity([['v=spf1 redirect=_spf.example.net']], []).notes[0], '↪️ SPF _spf.example.net adresine yönlendiriliyor')
})

test('DMARC partial pct and missing rua are reported', () => {
  const notes = gradeEmailSecurity([['v=spf1 -all']], [['v=DMARC1; p=quarantine; pct=25']]).notes
  assert.deepStrictEqual(notes.slice(1), ["🟡 DMARC p=quarantine", "🟡 DMARC politikası e-postaların sadece %25'ine uygulanıyor", 'ℹ️ DMARC rapor adresi (rua) yok'])
})

const { codeBlock } = require('./domain.cjs')

test('codeBlock wraps records and stays under the field limit', () => {
  assert.strictEqual(codeBlock([]), 'Yok')
  assert.strictEqual(codeBlock(['1.2.3.4', '5.6.7.8']), '```\n1.2.3.4\n5.6.7.8\n```')
  const big = codeBlock(Array.from({ length: 200 }, (_, i) => `v=verify-${i}-${'x'.repeat(20)}`))
  assert.ok(big.length <= 1024)
  assert.ok(big.includes('…'))
})

test('DMARC without a valid p= tag is reported as invalid', () => {
  assert.match(gradeEmailSecurity([], [['v=DMARC1; rua=mailto:d@example.com']]).notes[1], /geçersiz/)
  assert.match(gradeEmailSecurity([], [['v=DMARC1; p=none; rua=mailto:d@example.com']]).notes[1], /p=none/)
})
