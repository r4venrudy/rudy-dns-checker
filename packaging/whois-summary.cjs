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

function whoisSummary(results) {
  return {
    registrar: pick(results, 'Registrar'),
    created: pick(results, 'Created Date'),
    expires: pick(results, 'Expiry Date')
  };
}

module.exports = { whoisSummary };
