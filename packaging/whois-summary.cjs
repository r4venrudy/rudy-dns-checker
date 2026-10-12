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
function formatDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toISOString().slice(0, 10);
}

function daysUntil(value, now = new Date()) {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : Math.floor((d - now) / 86400000);
}

function whoisSummary(results) {
  return {
    registrar: pick(results, 'Registrar'),
    created: pick(results, 'Created Date'),
    expires: pick(results, 'Expiry Date')
  };
}

module.exports = { whoisSummary, formatDate, daysUntil };
