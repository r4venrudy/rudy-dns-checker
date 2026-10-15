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
import { domainToUnicode } from "url"
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
import cooldownHelpers from './packaging/cooldown.cjs'
const { danglingCnameNote, inlineCode, normalizeDomain, joinTxt, gradeEmailSecurity, codeBlock, fitFields, formatMx, formatSoa, dnssecNote, mailTransportNotes, DKIM_SELECTORS, summarizeDkim } = domainHelpers
const config = runtimeConfig.loadConfig({ token: 'DISCORD_TOKEN', clientId: 'CLIENT_ID' })
if (process.argv.includes('--check-config')) { console.log('Configuration and dependencies ready'); process.exit(0) }

const cooldown=cooldownHelpers.createCooldown(cooldownHelpers.secondsFromEnv(process.env.COOLDOWN_SECONDS,10)*1000)

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
             // longest valid hostname is 253 characters; leave room for a pasted https:// prefix and path
             .setMaxLength(300)
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

// discord.js emits 'error' for gateway and network failures; with no listener Node treats it as
// an uncaught exception and the bot exits
client.on("error", err => console.error("Discord client error:", err))

client.once("ready", () => {
    console.log(`Bot aktif: ${client.user.tag}`)
})

// DS records via Cloudflare's DNS-over-HTTPS JSON API; null when it can't be reached
async function fetchDs(domain){
    try{
        const url=`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DS`
        const res=await fetch(url,{ headers:{ accept:"application/dns-json" }, signal:AbortSignal.timeout(8000) })
        return res.ok ? await res.json() : null
    }catch{
        return null
    }
}

async function safeResolve(domain,type){
    try{
        return await dns.resolve(domain,type)
    }catch{
        return []
    }
}

async function handleDomain(interaction){
    if(!interaction.isChatInputCommand()) return
    if(interaction.commandName!=="domain") return

    const domain=normalizeDomain(interaction.options.getString("domain"))
    // show "xn--rnek-4qa.com.tr (örnek.com.tr)" so a punycode name is still recognisable
    const unicodeName=domain ? domainToUnicode(domain) : null
    if(!domain){
        await interaction.reply({ content:"❌ Geçerli bir domain girin (örnek: example.com)", ephemeral:true })
        return
    }
    const wait=cooldown.take(interaction.user.id)
    if(wait>0){
        await interaction.reply({ content:`⏳ Bir sonraki sorgu için ${Math.ceil(wait/1000)} sn bekleyin.`, ephemeral:true })
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
        MTASTS,
        TLSRPT,
        BIMI,
        DS,
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
        safeResolve(`_mta-sts.${domain}`,"TXT"),
        safeResolve(`_smtp._tls.${domain}`,"TXT"),
        safeResolve(`default._bimi.${domain}`,"TXT"),
        fetchDs(domain),
        whoisHelpers.lookupRegistered(domain,name=>whoiser(name,{ timeout:10000 }))
    ])
    const email=gradeEmailSecurity(TXT,DMARC)
    // a single "0 ." MX (RFC 7505 null MX) means the domain takes no mail, so MTA-STS doesn't apply
    const receivesMail=MX.length>0 && !(MX.length===1 && (MX[0].exchange===""||MX[0].exchange==="."))
    // reverse DNS for the first few addresses often names the hosting provider (e.g. ec2-...amazonaws.com)
    const ipv4=await Promise.all(A.map((ip,i)=>i<5
        ? dns.reverse(ip).then(names=>names[0] ? `${ip}  →  ${names[0]}` : ip,()=>ip)
        : ip))

    const summary=whoisHelpers.whoisSummary(whoisData?.results)
    const registrar=summary.registrar || "Bilinmiyor"
    const created=whoisHelpers.formatDate(summary.created) || "Bilinmiyor"
    const expires=whoisHelpers.expiryText(summary.expires) || "Bilinmiyor"

    const embed=new EmbedBuilder()
        .setColor(0x00ffea)
        // Discord rejects titles over 256 characters, which a long name plus its Unicode form can reach
        .setTitle(`┌──(root㉿kali)-[~]\n└─$ domain ${domain}${unicodeName && unicodeName!==domain ? ` (${unicodeName})` : ""}`.slice(0,256))
        .setDescription("Aşağıda hedef domain için bulunan açık DNS ve WHOIS verileri yer almaktadır.")
        .addFields(...fitFields([
            { name:"IPv4 (PTR)", value:codeBlock(ipv4) },
            { name:"IPv6", value:codeBlock(AAAA) },
            { name:"NS", value:codeBlock(NS) },
            { name:"MX", value:codeBlock(formatMx(MX)) },
            { name:"TXT", value:codeBlock(joinTxt(TXT)) },
            { name:"CNAME", value:[codeBlock(CNAME), danglingCnameNote(CNAME,A,AAAA)].filter(Boolean).join("\n") },
            { name:"SOA", value:codeBlock(formatSoa(SOA)) },
            { name:"DNSSEC", value:dnssecNote(DS) },
            { name:"CAA", value:codeBlock(CAA.map(r=>`${r.critical?"!":""}${Object.entries(r).filter(([k])=>k!=="critical").map(([k,v])=>`${k} ${v}`).join(" ")}`)) },
            { name:"E-posta Güvenliği (SPF / DMARC / DKIM / MTA-STS)", value:[...email.notes, summarizeDkim(DKIM), ...(receivesMail ? mailTransportNotes(MTASTS,TLSRPT,BIMI) : [])].join("\n") },
            // for a subdomain the WHOIS data belongs to the registered name it sits under
            { name:whoisData && whoisData.name!==domain ? `Registrar (${whoisData.name})` : "Registrar", value:inlineCode(registrar) },
            { name:"Oluşturulma", value:inlineCode(created), inline:true },
            { name:"Bitiş", value:inlineCode(expires), inline:true },
            { name:"Güncelleme", value:inlineCode(whoisHelpers.formatDate(summary.updated) || "Bilinmiyor"), inline:true },
            // transfer/delete locks show whether the domain is protected against hijacking
            { name:"Durum (EPP)", value:summary.statuses.length ? codeBlock(summary.statuses) : "Bilinmiyor" }
        ]))
        .setFooter({ text:"Kali Linux | DNS / WHOIS Lookup" })

    await interaction.editReply({ embeds:[embed] })
    }catch(err){
        console.error(`/domain ${domain} failed:`,err)
        await interaction.editReply("❌ Sorgu sırasında bir hata oluştu, lütfen tekrar deneyin.").catch(()=>{})
    }
}

// reply/deferReply fail when Discord expires the interaction (the bot answered after 3 s); outside a
// catch that rejection is unhandled, and Node 15+ exits on unhandled rejections
client.on("interactionCreate",interaction=>{
    handleDomain(interaction).catch(err=>console.error("/domain could not reply:",err))
})

client.login(config.token)
