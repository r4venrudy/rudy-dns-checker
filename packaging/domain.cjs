const { domainToASCII } = require('node:url')
// Pure helpers for /domain: input normalization and SPF/DMARC grading (no Discord or network access).
// "https://Example.com/path" -> "example.com"; returns null for anything that isn't a hostname
// Internationalized names ("örnek.com.tr") are converted to punycode ("xn--rnek-zoa.com.tr") first.
function normalizeDomain(input){
    const raw=String(input||"").trim().toLowerCase()
        .replace(/^[a-z]+:\/\//,"").split(/[/?#]/)[0].replace(/:\d+$/,"").replace(/\.$/,"")
    const d=/[^\x00-\x7f]/.test(raw) ? domainToASCII(raw) : raw
    return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d) ? d : null
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
    // A bare "all" has the default "+" qualifier, so it is as permissive as +all
    else if(/(?:^|\s)[+?]?all\b/i.test(spf[0])) notes.push("⚠️ SPF çok gevşek (+all / ?all)")
    else if(/~all\b/i.test(spf[0])) notes.push("🟡 SPF softfail (~all)")
    else if(/-all\b/i.test(spf[0])) notes.push("✅ SPF sıkı (-all)")
    else if(/\bredirect=\S+/i.test(spf[0])) notes.push(`↪️ SPF ${spf[0].match(/redirect=(\S+)/i)[1]} adresine yönlendiriliyor`)
    else notes.push("⚠️ SPF bir all mekanizmasıyla bitmiyor")

    const dmarcRecords=joinTxt(dmarcTxt).filter(t=>t.toLowerCase().startsWith("v=dmarc1"))
    const dmarc=dmarcRecords[0]
    if(!dmarc) notes.push("❌ DMARC kaydı yok")
    // RFC 7489: with more than one DMARC record receivers ignore DMARC for the domain entirely
    else if(dmarcRecords.length>1) notes.push("⚠️ Birden fazla DMARC kaydı var (alıcılar DMARC'ı yok sayar)")
    else{
        const policy=(dmarc.match(/;\s*p=(\w+)/i)||[])[1]?.toLowerCase()
        if(policy==="reject") notes.push("✅ DMARC p=reject")
        else if(policy==="quarantine") notes.push("🟡 DMARC p=quarantine")
        else if(policy==="none") notes.push("⚠️ DMARC p=none (sadece izleme)")
        else notes.push("⚠️ DMARC kaydında geçerli bir p= etiketi yok (kayıt geçersiz)")
        const pct=(dmarc.match(/;\s*pct=(\d+)/i)||[])[1]
        if(pct && Number(pct)<100) notes.push(`🟡 DMARC politikası e-postaların sadece %${pct}'ine uygulanıyor`)
        if(!/;\s*rua=/i.test(dmarc)) notes.push("ℹ️ DMARC rapor adresi (rua) yok")
    }
    return { spf:spf[0]||null, dmarc:dmarc||null, notes }
}


// Discord rejects embed field values over 1024 characters (long TXT/SPF records hit this)
function codeBlock(lines){
    if(!lines.length) return "Yok"
    // TXT and CAA values are written by the domain owner; a "```" inside would close the block early
    let body=lines.join("\n").replace(/```/g,"`\u200b`\u200b`")
    if(body.length>1000) body=body.slice(0,999)+"…"
    return `\`\`\`\n${body}\n\`\`\``
}

// Inline code for WHOIS values; Discord has no escape for a backtick inside single-backtick code
function inlineCode(text){
    return `\`${String(text).replace(/`/g,"ˋ")}\``
}

// DKIM keys live at <selector>._domainkey.<domain> and selectors are not discoverable,
// so only the ones big providers use by default are probed.
const DKIM_SELECTORS=["google","selector1","selector2","default","k1","s1","s2","dkim","mail"]

// results: [{ selector, txt: [...] }] -> one note line
function summarizeDkim(results){
    const found=results.filter(r=>joinTxt(r.txt).some(t=>/(^|;)\s*(v=dkim1|p=)/i.test(t))).map(r=>r.selector)
    return found.length
        ? `✅ DKIM anahtarı bulundu: ${found.join(", ")}`
        : "ℹ️ Yaygın seçicilerde DKIM bulunamadı (özel seçici kullanılıyor olabilir)"
}

// dns.resolve(domain,"SOA") gives one object; show the primary NS, the admin mailbox as an address, and the serial
function formatSoa(soa){
    if(!soa || !soa.nsname) return []
    const admin=String(soa.hostmaster||"").replace(".","@")
    return [`Birincil NS: ${soa.nsname}`, `Yönetici: ${admin}`, `Seri: ${soa.serial}`]
}

// Node's resolver cannot ask for DS records, so DNSSEC is checked with a DNS-over-HTTPS JSON answer
// (Cloudflare / Google format). A DS record at the parent zone means the domain is signed.
function dnssecNote(doh){
    if(!doh || typeof doh.Status!=="number") return "ℹ️ DNSSEC kontrol edilemedi"
    const ds=(doh.Answer||[]).filter(a=>a.type===43)
    if(doh.Status===0 && ds.length) return `✅ DNSSEC etkin (${ds.length} DS kaydı)`
    return "⚠️ DNSSEC yok (DS kaydı bulunamadı)"
}

// MTA-STS (_mta-sts TXT, "v=STSv1") makes senders require TLS; TLS-RPT (_smtp._tls TXT, "v=TLSRPTv1")
// asks them to report TLS failures. Only worth checking when the domain receives mail.
function mailTransportNotes(mtaStsTxt, tlsRptTxt){
    const has=(txt,prefix)=>joinTxt(txt).some(t=>t.toLowerCase().startsWith(prefix))
    return [
        has(mtaStsTxt,"v=stsv1") ? "✅ MTA-STS kaydı var" : "ℹ️ MTA-STS yok (TLS zorunlu değil)",
        has(tlsRptTxt,"v=tlsrptv1") ? "✅ TLS-RPT raporlaması açık" : "ℹ️ TLS-RPT yok"
    ]
}

// MX records by priority; a single "0 ." record (RFC 7505 null MX) means the domain takes no mail
function formatMx(records){
    if(records.length===1 && (records[0].exchange===""||records[0].exchange===".")) return ["Null MX: bu domain e-posta kabul etmiyor"]
    return [...records].sort((a,b)=>a.priority-b.priority).map(x=>`${x.priority} ${x.exchange}`)
}

// Discord also rejects a whole embed over 6000 characters; several long record sets can pass that
// even when each field fits, so later fields are shortened once the budget is spent.
function fitFields(fields,budget=5500){
    let used=0
    return fields.map(f=>{
        const size=f.name.length+f.value.length
        if(used+size<=budget){ used+=size; return f }
        const room=budget-used-f.name.length-8
        const value=room>20 ? codeBlock([f.value.replace(/```\n?/g,"").slice(0,room)]) : "Kısaltıldı"
        used+=f.name.length+value.length
        return { ...f, value }
    })
}

module.exports = { inlineCode, normalizeDomain, joinTxt, gradeEmailSecurity, codeBlock, fitFields, formatMx, formatSoa, dnssecNote, mailTransportNotes, DKIM_SELECTORS, summarizeDkim }
