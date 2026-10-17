// Per-user cooldown: every /domain runs about twenty DNS queries plus a WHOIS lookup.
function createCooldown(ms, now = () => Date.now()) {
  const last = new Map();
  return {
    // Returns 0 and records the use when allowed, otherwise the milliseconds left to wait
    take(userId) {
      const t = now();
      const left = (last.get(userId) ?? -Infinity) + ms - t;
      if (left > 0) return left;
      last.set(userId, t);
      // keep the map small: drop entries whose cooldown has long expired
      if (last.size > 1000) for (const [id, at] of last) if (t - at >= ms) last.delete(id);
      return 0;
    }
  };
}

// COOLDOWN_SECONDS: empty, negative or non-numeric values fall back to the default
// (Number('abc') is NaN, which silently disabled the cooldown)
function secondsFromEnv(value, fallback) {
  if (value === undefined || String(value).trim() === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

module.exports = { createCooldown, secondsFromEnv };
