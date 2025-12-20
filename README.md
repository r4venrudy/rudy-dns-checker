##################################################
#        Domain DNS & WHOIS Discord Bot          #
##################################################

Description:
-------------
This Discord bot provides DNS record lookups and WHOIS information for a given domain name.
It is designed for reconnaissance, cybersecurity research, and general domain intelligence.
The bot uses Discord slash commands and responds with a structured embed containing
all discovered DNS records and registration details.

The bot is lightweight, fast, and uses only official Node.js libraries and APIs.

--------------------------------------------------

Features:
---------
1. DNS Record Lookup
   - A (IPv4)
   - AAAA (IPv6)
   - NS (Name Servers)
   - MX (Mail Servers)
   - TXT records
   - CNAME records

2. WHOIS Information
   - Registrar
   - Creation date
   - Expiration date

3. Discord Slash Command
   - Uses /domain command
   - Clean embed-based output
   - Kali Linux–style terminal header aesthetic

4. Error Tolerant
   - DNS lookup failures do not crash the bot
   - Missing WHOIS fields are handled safely
   - Domains with partial data still return results

--------------------------------------------------

Requirements:
-------------
- Node.js v18 or newer
- Discord bot token
- Discord application Client ID
- Internet access

Required NPM packages:
----------------------
- discord.js
- @discordjs/rest
- dns (built-in)
- whoiser
- fs (built-in)

--------------------------------------------------

Installation:
-------------
1. Clone or download the bot files.

2. Install dependencies:
   npm install discord.js @discordjs/rest whoiser

3. Create a file named `config.json` in the root directory:

   {
       "token": "YOUR_DISCORD_BOT_TOKEN",
       "clientId": "YOUR_DISCORD_APPLICATION_ID"
   }

4. Start the bot:
   node index.js

--------------------------------------------------

Usage:
------
1. Invite the bot to your Discord server with the appropriate permissions.

2. Use the slash command:
/domain domain:example.com

3. The bot will respond with:
   - IPv4 and IPv6 addresses
   - Name servers
   - Mail servers
   - TXT records
   - CNAME records
   - Domain registrar
   - Creation date
   - Expiration date

4. If a DNS record does not exist, it will be displayed as:
   "Yok" (None)

--------------------------------------------------

Output Format:
--------------
- Results are displayed in a Discord embed.
- DNS records are shown inside code blocks for readability.
- WHOIS dates and registrar are formatted inline.
- The embed title mimics a Kali Linux terminal prompt.
- Footer indicates the lookup type (DNS / WHOIS).

--------------------------------------------------

Error Handling:
---------------
- DNS resolution errors are caught and ignored per record type.
- WHOIS lookup failures return "Bilinmiyor" (Unknown).
- The bot will never crash due to a single failed lookup.

--------------------------------------------------

Security Notes:
---------------
- This bot performs passive lookups only.
- No scanning, brute forcing, or intrusive actions are performed.
- Use responsibly and comply with local laws and API terms.

--------------------------------------------------

Customization:
--------------
You can easily extend this bot by:
- Adding more DNS record types (SRV, SOA, etc.)
- Adding IP reputation APIs
- Logging queries to a database
- Adding cooldowns or permission checks

--------------------------------------------------

Author:
-------
Created for domain intelligence, DNS inspection, and cybersecurity research.

--------------------------------------------------

License:
--------
Provided as-is.
Use responsibly.
Not intended for malicious activity.
