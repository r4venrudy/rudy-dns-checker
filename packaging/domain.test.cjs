const test = require('node:test')
const assert = require('node:assert')
const { normalizeDomain, gradeEmailSecurity, codeBlock, fitFields, formatMx, formatSoa, dnssecNote, mailTransportNotes, summarizeDkim } = require('./domain.cjs')

test('normalizeDomain strips scheme, path, port and trailing dot', () => {
  assert.strictEqual(normalizeDomain('https://Example.com/path?q=1'), 'example.com')
  assert.strictEqual(normalizeDomain('itemsatis.com.'), 'itemsatis.com')
  assert.strictEqual(normalizeDomain('sub.domain.co.uk:443'), 'sub.domain.co.uk')
})

test('normalizeDomain converts internationalized names to punycode', () => {
  assert.strictEqual(normalizeDomain('Örnek.com.tr'), 'xn--rnek-4qa.com.tr')
  assert.strictEqual(normalizeDomain('https://şirket.com/'), 'xn--irket-idb.com')
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

test('fitFields keeps the whole embed under the budget', () => {
  const big = codeBlock(['x'.repeat(2000)])
  const fields = Array.from({ length: 8 }, (_, i) => ({ name: `F${i}`, value: big }))
  const fitted = fitFields(fields)
  const total = fitted.reduce((n, f) => n + f.name.length + f.value.length, 0)
  // fields past the budget still carry a short placeholder; title, description and footer need the rest of the 6000
  assert.ok(total <= 5600, `total ${total}`)
  assert.strictEqual(fitted[0].value, big)
  assert.ok(fitted.every(f => f.value.length > 0 && f.value.length <= 1024))
})

test('fitFields leaves small embeds untouched', () => {
  const fields = [{ name: 'A', value: '`1.2.3.4`' }, { name: 'B', value: 'Yok' }]
  assert.deepStrictEqual(fitFields(fields), fields)
})

test('formatMx sorts by priority and recognises a null MX', () => {
  assert.deepStrictEqual(formatMx([{ priority: 20, exchange: 'b.mx' }, { priority: 10, exchange: 'a.mx' }]), ['10 a.mx', '20 b.mx'])
  assert.match(formatMx([{ priority: 0, exchange: '' }])[0], /Null MX/)
  assert.deepStrictEqual(formatMx([]), [])
})

test('summarizeDkim lists selectors that publish a key', () => {
  const note = summarizeDkim([
    { selector: 'google', txt: [['v=DKIM1; k=rsa; ', 'p=MIGf']] },
    { selector: 'selector1', txt: [] },
    { selector: 'default', txt: [['some unrelated text']] },
  ])
  assert.strictEqual(note, '✅ DKIM anahtarı bulundu: google')
  assert.match(summarizeDkim([{ selector: 'google', txt: [] }]), /bulunamadı/)
})

test('formatSoa shows the primary NS, admin address and serial', () => {
  assert.deepStrictEqual(formatSoa({ nsname: 'ns1.example.com', hostmaster: 'hostmaster.example.com', serial: 2026101301 }),
    ['Birincil NS: ns1.example.com', 'Yönetici: hostmaster@example.com', 'Seri: 2026101301'])
  assert.deepStrictEqual(formatSoa([]), [])
})

test('dnssecNote reads a DNS-over-HTTPS DS answer', () => {
  assert.match(dnssecNote({ Status: 0, AD: true, Answer: [{ name: 'cloudflare.com.', type: 43, data: '2371 13 2 32996839a6d8' }] }), /etkin \(1 DS/)
  assert.match(dnssecNote({ Status: 0, Answer: [] }), /DNSSEC yok/)
  assert.match(dnssecNote({ Status: 3 }), /DNSSEC yok/)
  assert.match(dnssecNote(null), /kontrol edilemedi/)
})

test('mailTransportNotes reports MTA-STS and TLS-RPT', () => {
  assert.deepStrictEqual(mailTransportNotes([['v=STSv1; id=20240101']], [['v=TLSRPTv1; rua=mailto:tls@example.com']]),
    ['✅ MTA-STS kaydı var', '✅ TLS-RPT raporlaması açık'])
  assert.deepStrictEqual(mailTransportNotes([], [['unrelated']]), ['ℹ️ MTA-STS yok (TLS zorunlu değil)', 'ℹ️ TLS-RPT yok'])
})

test('code formatting survives backticks in record values', () => {
  const { codeBlock, inlineCode } = require('./domain.cjs');
  const block = codeBlock(['v=spf1 ```oops```']);
  assert.equal(block.match(/```/g).length, 2);
  assert.equal(inlineCode('Reg`istrar'), '`Regˋistrar`');
});

test('two DMARC records are reported as invalid', () => {
  const r = gradeEmailSecurity([['v=spf1 -all']], [['v=DMARC1; p=reject'], ['v=DMARC1; p=none']])
  assert.deepStrictEqual(r.notes, ['✅ SPF sıkı (-all)', "⚠️ Birden fazla DMARC kaydı var (alıcılar DMARC'ı yok sayar)"])
})

test('SPF over the 10 lookup limit is flagged', () => {
  const includes = Array.from({ length: 11 }, (_, i) => `include:s${i}.example.com`).join(' ')
  const r = gradeEmailSecurity([[`v=spf1 ${includes} -all`]], [['v=DMARC1; p=reject; rua=mailto:d@example.com']])
  assert.ok(r.notes.includes('⚠️ SPF en az 11 DNS sorgusu gerektiriyor (sınır 10, kayıt geçersiz sayılır)'))
  const ok = gradeEmailSecurity([['v=spf1 a mx ip4:192.0.2.1 include:_spf.google.com -all']], [])
  assert.ok(!ok.notes.some(n => n.includes('DNS sorgusu')))
})

test('a weaker DMARC subdomain policy is flagged', () => {
  const r = gradeEmailSecurity([['v=spf1 -all']], [['v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com']])
  assert.ok(r.notes.includes('⚠️ Alt alan adları için daha zayıf politika: sp=none'))
  const same = gradeEmailSecurity([['v=spf1 -all']], [['v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@example.com']])
  assert.ok(!same.notes.some(n => n.includes('sp=')))
})

test('formatSoa keeps an escaped dot in the admin mailbox', () => {
  assert.strictEqual(formatSoa({ nsname: 'ns1.example.com', hostmaster: 'john\\.doe.example.com', serial: 1 })[1], 'Yönetici: john.doe@example.com')
})

test('summarizeDkim separates revoked keys (empty p=)', () => {
  const note = summarizeDkim([
    { selector: 'google', txt: [['v=DKIM1; k=rsa; p=MIGf']] },
    { selector: 's1', txt: [['v=DKIM1; p=']] },
  ])
  assert.strictEqual(note, '✅ DKIM anahtarı bulundu: google\nℹ️ İptal edilmiş DKIM anahtarı: s1')
})

test('mailTransportNotes mentions BIMI only when published', () => {
  assert.ok(mailTransportNotes([], [], [['v=BIMI1; l=https://example.com/logo.svg']]).includes('✅ BIMI logosu yayınlanmış'))
  assert.strictEqual(mailTransportNotes([], []).length, 2)
})

test('danglingCnameNote flags an unresolved CNAME to a hosting service', () => {
  const { danglingCnameNote } = require('./domain.cjs')
  assert.match(danglingCnameNote(['old-site.github.io.'], [], []), /ele geçirilebilir/)
  assert.strictEqual(danglingCnameNote(['old-site.github.io.'], ['185.199.108.153'], []), null)
  assert.strictEqual(danglingCnameNote(['cdn.example.net'], [], []), null)
  assert.strictEqual(danglingCnameNote([], [], []), null)
})

test('SPF ptr mechanism is flagged as deprecated', () => {
  const r = gradeEmailSecurity([['v=spf1 ptr:example.com -all']], [])
  assert.ok(r.notes.includes('⚠️ SPF kullanımdan kalkmış ptr mekanizmasını içeriyor'))
  assert.ok(!gradeEmailSecurity([['v=spf1 mx -all']], []).notes.some(n => n.includes('ptr')))
})
