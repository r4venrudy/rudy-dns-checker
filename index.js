import {
    Client,
    GatewayIntentBits,
    Routes,
    SlashCommandBuilder,
    EmbedBuilder
} from "discord.js"

import { REST } from "@discordjs/rest"
import dns from "dns/promises"
import whoiser from "whoiser"
import fs from "fs"

const config = JSON.parse(fs.readFileSync("./config.json", "utf8"))

const client = new Client({
    intents: [GatewayIntentBits.Guilds]
})

const commands = [
    new SlashCommandBuilder()
        .setName("domain")
        .setDescription("Bir domain için DNS ve WHOIS bilgilerini getirir")
        .addStringOption(o =>
            o.setName("domain")
             .setDescription("Örnek: itemsatis.com")
             .setRequired(true)
        )
        .toJSON()
]

const rest = new REST({ version: "10" }).setToken(config.token)

await rest.put(
    Routes.applicationCommands(config.clientId),
    { body: commands }
)

client.once("ready", () => {
    console.log(`Bot aktif: ${client.user.tag}`)
})

async function safeResolve(domain, type) {
    try {
        return await dns.resolve(domain, type)
    } catch {
        return []
    }
}

client.on("interactionCreate", async interaction => {
    if (!interaction.isChatInputCommand()) return
    if (interaction.commandName !== "domain") return

    const domain = interaction.options.getString("domain")
    await interaction.deferReply()

    const [
        A,
        AAAA,
        NS,
        MX,
        TXT,
        CNAME
    ] = await Promise.all([
        safeResolve(domain, "A"),
        safeResolve(domain, "AAAA"),
        safeResolve(domain, "NS"),
        safeResolve(domain, "MX"),
        safeResolve(domain, "TXT"),
        safeResolve(domain, "CNAME")
    ])

    let whoisData = null
    try {
        whoisData = await whoiser(domain)
    } catch {
        whoisData = null
    }

    const registrar = whoisData?.registrar || "Bilinmiyor"
    const created = whoisData?.creationDate || "Bilinmiyor"
    const expires = whoisData?.expirationDate || "Bilinmiyor"

    const embed = new EmbedBuilder()
        .setColor(0x00ffea)
        .setTitle(`┌──(root㉿kali)-[~]\n└─$ domain ${domain}`)
        .setDescription(
            "Aşağıda hedef domain için bulunan açık DNS ve WHOIS verileri yer almaktadır."
        )
        .addFields(
            {
                name: "IPv4",
                value: A.length ? `\`\`\`\n${A.join("\n")}\n\`\`\`` : "Yok"
            },
            {
                name: "IPv6",
                value: AAAA.length ? `\`\`\`\n${AAAA.join("\n")}\n\`\`\`` : "Yok"
            },
            {
                name: "NS",
                value: NS.length ? `\`\`\`\n${NS.join("\n")}\n\`\`\`` : "Yok"
            },
            {
                name: "MX",
                value: MX.length
                    ? `\`\`\`\n${MX.map(x => x.exchange).join("\n")}\n\`\`\``
                    : "Yok"
            },
            {
                name: "TXT",
                value: TXT.length
                    ? `\`\`\`\n${TXT.map(t => Array.isArray(t) ? t.join(" ") : t).join("\n")}\n\`\`\``
                    : "Yok"
            },
            {
                name: "CNAME",
                value: CNAME.length ? `\`\`\`\n${CNAME.join("\n")}\n\`\`\`` : "Yok"
            },
            {
                name: "Registrar",
                value: `\`${registrar}\``
            },
            {
                name: "Oluşturulma",
                value: `\`${created}\``,
                inline: true
            },
            {
                name: "Bitiş",
                value: `\`${expires}\``,
                inline: true
            }
        )
        .setFooter({
            text: "Kali Linux | DNS / WHOIS Lookup"
        })

    await interaction.editReply({ embeds: [embed] })
})

client.login(config.token)
