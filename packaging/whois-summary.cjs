// whoiser returns one result object per WHOIS server it queried, e.g.
// { "whois.verisign-grs.com": {...}, "whois.markmonitor.com": {...} },
// with normalized keys such as "Registrar", "Created Date" and "Expiry Date".
function pick(results, key) {
  for (const server of Object.values(results || {})) {
    const value = server && server[key];
    const first = Array.isArray(value) ? value[0] : value;
    if (typeof first === 'string' && first.trim()) return first.trim();
  }
  return null;
}

// "2026-10-09T18:20:50Z" -> "2026-10-09"; leaves unparseable registry formats as they are
// Only ISO-style dates are parsed: V8's lenient Date() would turn values like
// "before Aug-1996" (used by some registries) into a made-up exact date.
const ISO_DATE = /^\d{4}-\d{2}-\d{2}/;

function formatDate(value) {
  if (!value) return null;
  return ISO_DATE.test(value) ? value.slice(0, 10) : value;
}

function daysUntil(value, now = new Date()) {
  if (!value || !ISO_DATE.test(value)) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : Math.floor((d - now) / 86400000);
}

// Expiry line for the embed: warns inside 30 days and says plainly when the date has passed
function expiryText(value, now = new Date()) {
  if (!value) return null;
  const left = daysUntil(value, now);
  const date = formatDate(value);
  if (left === null || left >= 30) return date;
  if (left < 0) return `${date} ❌ süresi ${-left} gün önce dolmuş`;
  return `${date} ⚠️ ${left} gün kaldı`;
}

// EPP status codes ("clientTransferProhibited https://icann.org/epp#...") from every server, deduplicated
function statuses(results) {
  const out = new Set();
  for (const server of Object.values(results || {})) {
    const value = server && server['Domain Status'];
    for (const v of Array.isArray(value) ? value : value ? [value] : []) {
      const code = String(v).trim().split(/\s+/)[0];
      if (code) out.add(code);
    }
  }
  return [...out];
}

function whoisSummary(results) {
  return {
    registrar: pick(results, 'Registrar'),
    created: pick(results, 'Created Date'),
    updated: pick(results, 'Updated Date'),
    expires: pick(results, 'Expiry Date'),
    statuses: statuses(results)
  };
}

// WHOIS only knows registered names, so "www.example.com" returns nothing. Walk up one label at a
// time (keeping at least two, since a public suffix like "com.tr" has no record either) until a
// lookup returns a registrar or creation date. Resolves to { name, results } or null.
async function lookupRegistered(domain, lookup) {
  const labels = domain.split('.');
  for (let i = 0; labels.length - i >= 2; i++) {
    const name = labels.slice(i).join('.');
    const results = await lookup(name).catch(() => null);
    const summary = whoisSummary(results);
    if (summary.registrar || summary.created) return { name, results };
    if (labels.length - i === 2) break;
  }
  return null;
}

module.exports = { whoisSummary, formatDate, daysUntil, expiryText, lookupRegistered };
