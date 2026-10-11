<p align="center"><img src="docs/banner.svg" alt="Rudy DNS Checker — Domain records and mail-policy signals in one command." width="100%"></p>

<p align="center">
  <img src="https://img.shields.io/badge/Runtime-Node.js%20/%20Discord-55e0b6?style=flat-square&labelColor=101b28" alt="Node.js / Discord">
  <img src="https://img.shields.io/badge/Docs-source_reviewed-55e0b6?style=flat-square&labelColor=101b28" alt="Documentation based on source review">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-55e0b6?style=flat-square&labelColor=101b28" alt="MIT license"></a>
</p>

<p align="center"><strong>Domain records and mail-policy signals in one command.</strong></p>

<p align="center"><a href="#overview">Overview</a> · <a href="#capabilities">Capabilities</a> · <a href="#quick-start">Quick start</a> · <a href="#implementation-notes">Implementation notes</a></p>

---

## Overview

A Discord `/domain` bot that resolves public DNS records, queries WHOIS and summarizes SPF/DMARC policy signals in an embed. DNS queries run concurrently and failed lookups are represented by empty results.

## Capabilities

| Layer | Implemented behavior |
| :--- | :--- |
| DNS | A, AAAA, NS, MX, TXT and CNAME lookups |
| Mail policy | SPF presence/multiplicity and common `all` qualifiers; DMARC policy summary |
| WHOIS | Registrar and date fields where the provider response matches the expected shape |
| Discord | Registers `/domain` globally and returns a structured embed |

## Quick start

Requires Node.js with ES-module and top-level-await support and a Discord application. Keep the bundled `raven.png`; startup verifies its PNG signature.

```bash
git clone https://github.com/r4venrudy/rudy-dns-checker.git
cd rudy-dns-checker
npm install
```

Create local `config.json`:

```json
{
  "token": "YOUR_DISCORD_BOT_TOKEN",
  "clientId": "YOUR_DISCORD_APPLICATION_ID"
}
```

```bash
node index.js
```

Invite the bot with `bot` and `applications.commands` scopes, then run `/domain example.com`.

## Implementation notes

- The actual slash command is `/domain`; this is a domain/DNS bot rather than an IP lookup bot.
- SPF and DMARC checks are lightweight string heuristics. They do not recursively evaluate SPF includes, check DKIM, verify DNSSEC or certify mail delivery.
- WHOIS response shape varies; registrar and date fields can be unavailable. Large DNS answers can exceed Discord embed limits.
- Run from the repository root because configuration and asset paths use the working directory. Replies are channel-visible; API availability and Discord setup require live validation.

## Project map

```text
index.js       DNS, WHOIS, mail-policy checks and Discord command
package.json   ES-module configuration and dependencies
config.json    Local Discord credentials
raven.png      Required startup asset
```

## License

[MIT](LICENSE). Preserve the attribution in the license file.

---

<p align="center">Part of the <a href="https://github.com/r4venrudy">r4venrudy</a> project collection.</p>
