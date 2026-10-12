// Pure helpers for /domain: input normalization and SPF/DMARC grading (no Discord or network access).
// "https://Example.com/path" -> "example.com"; returns null for anything that isn't a hostname
function normalizeDomain(input){
    const d=String(input||"").trim().toLowerCase()
        .replace(/^[a-z]+:\/\//,"").split(/[/?#]/)[0].replace(/:\d+$/,"").replace(/\.$/,"")
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
    else if(/[+?]all\b/i.test(spf[0])) notes.push("⚠️ SPF çok gevşek (+all / ?all)")
    else if(/~all\b/i.test(spf[0])) notes.push("🟡 SPF softfail (~all)")
    else if(/-all\b/i.test(spf[0])) notes.push("✅ SPF sıkı (-all)")
    else if(/\bredirect=\S+/i.test(spf[0])) notes.push(`↪️ SPF ${spf[0].match(/redirect=(\S+)/i)[1]} adresine yönlendiriliyor`)
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

module.exports = { normalizeDomain, joinTxt, gradeEmailSecurity }
