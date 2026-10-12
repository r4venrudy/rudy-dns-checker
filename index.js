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

await rest.put(
    Routes.applicationCommands(config.clientId),
    { body: commands }
)

client.once("ready", () => {
    console.log(`Bot aktif: ${client.user.tag}`)
})

// "https://Example.com/path" -> "example.com"; returns null for anything that isn't a hostname
function normalizeDomain(input){
    const d=String(input||"").trim().toLowerCase()
        .replace(/^[a-z]+:\/\//,"").split(/[/?#]/)[0].replace(/:\d+$/,"").replace(/\.$/,"")
    return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d) ? d : null
}

// Discord rejects embed field values over 1024 characters (long TXT/SPF records hit this)
function codeBlock(lines){
    if(!lines.length) return "Yok"
    let body=lines.join("\n")
    if(body.length>1000) body=body.slice(0,999)+"…"
    return `\`\`\`\n${body}\n\`\`\``
}

async function safeResolve(domain,type){
    try{
        return await dns.resolve(domain,type)
    }catch{
        return []
    }
}

function joinTxt(records){
    return records.map(t=>Array.isArray(t)?t.join(""):t)
}

// SPF ve DMARC kayıtlarını değerlendirir (e-posta sahteciliğine karşı koruma)
function gradeEmailSecurity(rootTxt,dmarcTxt){
    const notes=[]
    const spf=joinTxt(rootTxt).filter(t=>t.toLowerCase().startsWith("v=spf1"))
    if(spf.length===0) notes.push("❌ SPF kaydı yok")
    else if(spf.length>1) notes.push("⚠️ Birden fazla SPF kaydı var (geçersiz)")
    else if(/[+?]all\b/i.test(spf[0])) notes.push("⚠️ SPF çok gevşek (+all / ?all)")
    else if(/~all\b/i.test(spf[0])) notes.push("🟡 SPF softfail (~all)")
    else if(/-all\b/i.test(spf[0])) notes.push("✅ SPF sıkı (-all)")
    else notes.push("⚠️ SPF bir all mekanizmasıyla bitmiyor")

    const dmarc=joinTxt(dmarcTxt).find(t=>t.toLowerCase().startsWith("v=dmarc1"))
    if(!dmarc) notes.push("❌ DMARC kaydı yok")
    else{
        const policy=(dmarc.match(/;\s*p=(\w+)/i)||[])[1]?.toLowerCase()
        if(policy==="reject") notes.push("✅ DMARC p=reject")
        else if(policy==="quarantine") notes.push("🟡 DMARC p=quarantine")
        else notes.push("⚠️ DMARC p=none (sadece izleme)")
    }
    return { spf:spf[0]||null, dmarc:dmarc||null, notes }
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

    const [
        A,
        AAAA,
        NS,
        MX,
        TXT,
        CNAME
    ] = await Promise.all([
        safeResolve(domain,"A"),
        safeResolve(domain,"AAAA"),
        safeResolve(domain,"NS"),
        safeResolve(domain,"MX"),
        safeResolve(domain,"TXT"),
        safeResolve(domain,"CNAME")
    ])
    const DMARC=await safeResolve(`_dmarc.${domain}`,"TXT")
    const email=gradeEmailSecurity(TXT,DMARC)

    let whoisData=null
    try{
        whoisData=await whoiser(domain)
    }catch{
        whoisData=null
    }

    const summary=whoisHelpers.whoisSummary(whoisData)
    const registrar=summary.registrar || "Bilinmiyor"
    const created=summary.created || "Bilinmiyor"
    const expires=summary.expires || "Bilinmiyor"

    const embed=new EmbedBuilder()
        .setColor(0x00ffea)
        .setTitle(`┌──(root㉿kali)-[~]\n└─$ domain ${domain}`)
        .setDescription("Aşağıda hedef domain için bulunan açık DNS ve WHOIS verileri yer almaktadır.")
        .addFields(
            { name:"IPv4", value:codeBlock(A) },
            { name:"IPv6", value:codeBlock(AAAA) },
            { name:"NS", value:codeBlock(NS) },
            { name:"MX", value:codeBlock(MX.map(x=>x.exchange)) },
            { name:"TXT", value:codeBlock(joinTxt(TXT)) },
            { name:"CNAME", value:codeBlock(CNAME) },
            { name:"E-posta Güvenliği (SPF / DMARC)", value:email.notes.join("\n") },
            { name:"Registrar", value:`\`${registrar}\`` },
            { name:"Oluşturulma", value:`\`${created}\``, inline:true },
            { name:"Bitiş", value:`\`${expires}\``, inline:true }
        )
        .setFooter({ text:"Kali Linux | DNS / WHOIS Lookup" })

    await interaction.editReply({ embeds:[embed] })
})

client.login(config.token)
