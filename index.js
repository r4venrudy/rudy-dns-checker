import fs from "fs"
import path from "path"
import process from "process"
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

function ravenFail(){
    console.log("Kabul etmesende mahçupsun - r4ven.leet. Fotoğrafımı geri yükle")
    process.exit(1)
}

const BASE=process.cwd()
const RAVEN=path.join(BASE,"raven.png")

if(!fs.existsSync(RAVEN)) ravenFail()

try{
    const b=fs.readFileSync(RAVEN)
    if(b.length<8) ravenFail()
    const sig=b.slice(0,8).toString("hex")
    if(sig!=="89504e470d0a1a0a") ravenFail()
}catch{
    ravenFail()
}

import runtimeConfig from './packaging/config.cjs'
import whoisHelpers from './packaging/whois-summary.cjs'
import domainHelpers from './packaging/domain.cjs'
const { normalizeDomain, joinTxt, gradeEmailSecurity, codeBlock, fitFields, formatMx, formatSoa, DKIM_SELECTORS, summarizeDkim } = domainHelpers
const config = runtimeConfig.loadConfig({ token: 'DISCORD_TOKEN', clientId: 'CLIENT_ID' })
if (process.argv.includes('--check-config')) { console.log('Configuration and dependencies ready'); process.exit(0) }

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

try{
    await rest.put(
        Routes.applicationCommands(config.clientId),
        { body: commands }
    )
}catch(err){
    console.error(`Slash komutları kaydedilemedi (token / CLIENT_ID doğru mu?): ${err.message}`)
    process.exit(1)
}

client.once("ready", () => {
    console.log(`Bot aktif: ${client.user.tag}`)
})

async function safeResolve(domain,type){
    try{
        return await dns.resolve(domain,type)
    }catch{
        return []
    }
}

client.on("interactionCreate",async interaction=>{
    if(!interaction.isChatInputCommand()) return
    if(interaction.commandName!=="domain") return

    const domain=normalizeDomain(interaction.options.getString("domain"))
    if(!domain){
        await interaction.reply({ content:"❌ Geçerli bir domain girin (örnek: example.com)", ephemeral:true })
        return
    }
    await interaction.deferReply()

    try{
    const [
        A,
        AAAA,
        NS,
        MX,
        TXT,
        CNAME,
        CAA,
        SOA,
        DMARC,
        DKIM,
        whoisData
    ] = await Promise.all([
        safeResolve(domain,"A"),
        safeResolve(domain,"AAAA"),
        safeResolve(domain,"NS"),
        safeResolve(domain,"MX"),
        safeResolve(domain,"TXT"),
        safeResolve(domain,"CNAME"),
        safeResolve(domain,"CAA"),
        safeResolve(domain,"SOA"),
        safeResolve(`_dmarc.${domain}`,"TXT"),
        Promise.all(DKIM_SELECTORS.map(async selector=>({ selector, txt:await safeResolve(`${selector}._domainkey.${domain}`,"TXT") }))),
        whoiser(domain,{ timeout:10000 }).catch(()=>null)
    ])
    const email=gradeEmailSecurity(TXT,DMARC)

    const summary=whoisHelpers.whoisSummary(whoisData)
    const registrar=summary.registrar || "Bilinmiyor"
    const created=whoisHelpers.formatDate(summary.created) || "Bilinmiyor"
    const left=whoisHelpers.daysUntil(summary.expires)
    const expires=summary.expires
        ? `${whoisHelpers.formatDate(summary.expires)}${left!==null && left<30 ? ` ⚠️ ${left} gün kaldı` : ""}`
        : "Bilinmiyor"

    const embed=new EmbedBuilder()
        .setColor(0x00ffea)
        .setTitle(`┌──(root㉿kali)-[~]\n└─$ domain ${domain}`)
        .setDescription("Aşağıda hedef domain için bulunan açık DNS ve WHOIS verileri yer almaktadır.")
        .addFields(...fitFields([
            { name:"IPv4", value:codeBlock(A) },
            { name:"IPv6", value:codeBlock(AAAA) },
            { name:"NS", value:codeBlock(NS) },
            { name:"MX", value:codeBlock(formatMx(MX)) },
            { name:"TXT", value:codeBlock(joinTxt(TXT)) },
            { name:"CNAME", value:codeBlock(CNAME) },
            { name:"SOA", value:codeBlock(formatSoa(SOA)) },
            { name:"CAA", value:codeBlock(CAA.map(r=>`${r.critical?"!":""}${Object.entries(r).filter(([k])=>k!=="critical").map(([k,v])=>`${k} ${v}`).join(" ")}`)) },
            { name:"E-posta Güvenliği (SPF / DMARC / DKIM)", value:[...email.notes, summarizeDkim(DKIM)].join("\n") },
            { name:"Registrar", value:`\`${registrar}\`` },
            { name:"Oluşturulma", value:`\`${created}\``, inline:true },
            { name:"Bitiş", value:`\`${expires}\``, inline:true }
        ]))
        .setFooter({ text:"Kali Linux | DNS / WHOIS Lookup" })

    await interaction.editReply({ embeds:[embed] })
    }catch(err){
        console.error(`/domain ${domain} failed:`,err)
        await interaction.editReply("❌ Sorgu sırasında bir hata oluştu, lütfen tekrar deneyin.").catch(()=>{})
    }
})

client.login(config.token)
