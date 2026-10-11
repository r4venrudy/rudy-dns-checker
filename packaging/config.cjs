const fs = require('node:fs');
function loadConfig(spec, options = {}) {
  const env = options.env || process.env;
  const filename = options.filename || env.RUDY_CONFIG || 'config.json';
  const data = fs.existsSync(filename) ? JSON.parse(fs.readFileSync(filename, 'utf8')) : {};
  const result = {};
  for (const [key, variable] of Object.entries(spec)) result[key] = env[variable] || data[key] || '';
  const missing = Object.keys(result).filter(key => typeof result[key] !== 'string' || !result[key].trim() || /^(YOUR_|DISCORD TOKEN|YOUR CLIENT)/i.test(result[key]));
  if (missing.length) throw new Error('Missing configuration: ' + missing.map(key => spec[key]).join(', '));
  const clientId = result.clientId || result.CLIENT_ID;
  if (clientId && !/^\d{17,22}$/.test(clientId)) throw new Error('CLIENT_ID must be a Discord application ID');
  return result;
}
module.exports = { loadConfig };
