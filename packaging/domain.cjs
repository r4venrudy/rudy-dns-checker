const { domainToASCII } = require('node:url')
// Pure helpers for /domain: input normalization and SPF/DMARC grading (no Discord or network access).
// "https://Example.com/path" -> "example.com"; returns null for anything that isn't a hostname
// Internationalized names ("örnek.com.tr") are converted to punycode ("xn--rnek-zoa.com.tr") first.
function normalizeDomain(input){
    const raw=String(input||"").trim()
    if(/[\\\s\x00-\x1f]/.test(raw)) return null
    let url
    try { url=new URL(raw.includes("://")?raw:`https://${raw}`) }
    catch { return null }
    if(!["http:","https:"].includes(url.protocol)||url.username||url.password) return null
    // URL rejects malformed and out-of-range ports; port zero is syntactically valid but unusable.
    if(url.port!==""&&Number(url.port)===0) return null
    const d=domainToASCII(url.hostname.replace(/\.$/,""))
    return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?)$/.test(d) ? d : null
}

function joinTxt(records){
    return records.map(t=>Array.isArray(t)?t.join(""):t)
}

// SPF ve DMARC kayıtlarını değerlendirir (e-posta sahteciliğine karşı koruma)
function gradeEmailSecurity(rootTxt,dmarcTxt){
    const notes=[]
    // RFC 7208 4.5: the version must be exactly "v=spf1" followed by a space or the end, so
    // "v=spf10" or "v=spf1x" are not SPF records
    const spf=joinTxt(rootTxt).filter(t=>/^v=spf1(?:\s|$)/i.test(t))
    if(spf.length===0) notes.push("❌ SPF kaydı yok")
    else if(spf.length>1) notes.push("⚠️ Birden fazla SPF kaydı var (geçersiz)")
    // A bare "all" has the default "+" qualifier, so it is as permissive as +all
    else if(/(?:^|\s)[+?]?all(?:\s|$)/i.test(spf[0])) notes.push("⚠️ SPF çok gevşek (+all / ?all)")
    else if(/(?:^|\s)~all(?:\s|$)/i.test(spf[0])) notes.push("🟡 SPF softfail (~all)")
    else if(/(?:^|\s)-all(?:\s|$)/i.test(spf[0])) notes.push("✅ SPF sıkı (-all)")
    else if(/\bredirect=\S+/i.test(spf[0])) notes.push(`↪️ SPF ${spf[0].match(/redirect=(\S+)/i)[1]} adresine yönlendiriliyor`)
    else notes.push("⚠️ SPF bir all mekanizmasıyla bitmiyor")
    if(spf.length===1){
        // RFC 7208 allows 10 DNS-querying terms; past that receivers return permerror. Only the top
        // record is counted here (includes can add more), so this is a lower bound.
        const lookups=(spf[0].match(/(?:^|\s)[+\-~?]?(?:include:|a\b|mx\b|ptr\b|exists:|redirect=)/gi)||[]).length
        // RFC 7208 5.5: "ptr" is slow, unreliable and SHOULD NOT be used; many receivers ignore it
        if(/(?:^|\s)[+\-~?]?ptr\b/i.test(spf[0])) notes.push("⚠️ SPF kullanımdan kalkmış ptr mekanizmasını içeriyor")
        if(lookups>10) notes.push(`⚠️ SPF en az ${lookups} DNS sorgusu gerektiriyor (sınır 10, kayıt geçersiz sayılır)`)
    }

    const dmarcRecords=joinTxt(dmarcTxt).filter(t=>/^v=dmarc1\s*(?:;|$)/i.test(t))
    const dmarc=dmarcRecords[0]
    if(!dmarc) notes.push("❌ DMARC kaydı yok")
    // RFC 7489: with more than one DMARC record receivers ignore DMARC for the domain entirely
    else if(dmarcRecords.length>1) notes.push("⚠️ Birden fazla DMARC kaydı var (alıcılar DMARC'ı yok sayar)")
    else{
        // RFC 7489 section 6.4: parse complete tag values, reject duplicates.
        const tags=new Map()
        let invalid=false
        for(const part of dmarc.split(';').slice(1)){
            if(!part.trim()) continue
            const match=part.match(/^\s*([a-z][a-z0-9]*)\s*=\s*(.*?)\s*$/i)
            if(!match){ invalid=true; continue }
            const key=match[1].toLowerCase()
            if(tags.has(key)) invalid=true
            tags.set(key,match[2])
        }
        const policy=tags.get('p')?.toLowerCase()
        const pct=tags.get('pct')
        const sp=tags.get('sp')?.toLowerCase()
        if(pct!==undefined && (!/^\d{1,3}$/.test(pct) || Number(pct)>100)) invalid=true
        if(sp!==undefined && !['none','quarantine','reject'].includes(sp)) invalid=true
        if(invalid){
            notes.push("⚠️ DMARC etiketleri geçersiz (yinelenen etiket veya bozuk değer)")
            return { spf:spf[0]||null, dmarc, notes }
        }
        if(policy==="reject") notes.push("✅ DMARC p=reject")
        else if(policy==="quarantine") notes.push("🟡 DMARC p=quarantine")
        else if(policy==="none") notes.push("⚠️ DMARC p=none (sadece izleme)")
        else notes.push("⚠️ DMARC kaydında geçerli bir p= etiketi yok (kayıt geçersiz)")
        // pct has already been validated above.
        if(pct && Number(pct)<100) notes.push(`🟡 DMARC politikası e-postaların sadece %${pct}'ine uygulanıyor`)
        // sp= overrides p= for subdomains; "p=reject; sp=none" leaves every subdomain spoofable
        // sp has already been validated above.
        const rank={ none:0, quarantine:1, reject:2 }
        if(sp in rank && policy in rank && rank[sp]<rank[policy]) notes.push(`⚠️ Alt alan adları için daha zayıf politika: sp=${sp}`)
        if(!tags.get('rua')) notes.push("ℹ️ DMARC rapor adresi (rua) yok")
    }
    return { spf:spf[0]||null, dmarc:dmarc||null, notes }
}


// Discord rejects embed field values over 1024 characters (long TXT/SPF records hit this)
function codeBlock(lines){
    if(!lines.length) return "Yok"
    // TXT and CAA values are written by the domain owner; a "```" inside would close the block early
    let body=lines.join("\n").replace(/```/g,"`\u200b`\u200b`")
    if(body.length>1000) body=truncateText(body,999)+"…"
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
    const keys=results.map(r=>({ selector:r.selector, txt:joinTxt(r.txt).find(t=>{
        const tags=t.split(';').map(part=>part.trim()).filter(Boolean)
        const p=tags.filter(part=>/^p\s*=/i.test(part))
        const versions=tags.filter(part=>/^v\s*=/i.test(part))
        return p.length===1 && (versions.length===0 || (versions.length===1 && /^v\s*=\s*DKIM1$/i.test(versions[0])))
    }) })).filter(r=>r.txt)
    // an empty p= means the key was revoked (RFC 6376 3.6.1); mail signed with it fails DKIM
    const revoked=keys.filter(k=>/(^|;)\s*p\s*=\s*(;|$)/i.test(k.txt)).map(k=>k.selector)
    const active=keys.map(k=>k.selector).filter(s=>!revoked.includes(s))
    const notes=[]
    if(active.length) notes.push(`✅ DKIM anahtarı bulundu: ${active.join(", ")}`)
    if(revoked.length) notes.push(`ℹ️ İptal edilmiş DKIM anahtarı: ${revoked.join(", ")}`)
    return notes.length ? notes.join("\n") : "ℹ️ Yaygın seçicilerde DKIM bulunamadı (özel seçici kullanılıyor olabilir)"
}

// dns.resolve(domain,"SOA") gives one object; show the primary NS, the admin mailbox as an address, and the serial
function formatSoa(soa){
    if(!soa || !soa.nsname) return []
    // the first unescaped dot separates the mailbox; "john\\.doe.example.com" is john.doe@example.com
    const admin=String(soa.hostmaster||"").replace(/^((?:[^.\\]|\\.)*)\./,"$1@").replace(/\\\./g,".")
    return [`Birincil NS: ${soa.nsname}`, `Yönetici: ${admin}`, `Seri: ${soa.serial}`]
}

// Node's resolver cannot ask for DS records, so DNSSEC is checked with a DNS-over-HTTPS JSON answer
// (Cloudflare / Google format). A DS record at the parent zone means the domain is signed.
function dnssecNote(doh){
    if(!doh || ![0,3].includes(doh.Status)) return "ℹ️ DNSSEC kontrol edilemedi"
    if(doh.Status===3) return "ℹ️ DNS adı bulunamadı; DNSSEC durumu belirlenemedi"
    const ds=(doh.Answer||[]).filter(a=>a.type===43)
    if(ds.length) return `✅ DNSSEC etkin (${ds.length} DS kaydı)`
    return "⚠️ DNSSEC yok (DS kaydı bulunamadı)"
}

// MTA-STS (_mta-sts TXT, "v=STSv1") makes senders require TLS; TLS-RPT (_smtp._tls TXT, "v=TLSRPTv1")
// asks them to report TLS failures. Only worth checking when the domain receives mail.
// BIMI (default._bimi TXT, "v=BIMI1") shows the brand logo in Gmail/Yahoo; only listed when present
function mailTransportNotes(mtaStsTxt, tlsRptTxt, bimiTxt=[]){
    const has=(txt,prefix)=>joinTxt(txt).some(t=>new RegExp('^'+prefix+'(?:\\s*;|\\s*$)','i').test(t))
    const notes=[
        has(mtaStsTxt,"v=stsv1") ? "✅ MTA-STS kaydı var" : "ℹ️ MTA-STS yok (TLS zorunlu değil)",
        has(tlsRptTxt,"v=tlsrptv1") ? "✅ TLS-RPT raporlaması açık" : "ℹ️ TLS-RPT yok"
    ]
    if(has(bimiTxt,"v=bimi1")) notes.push("✅ BIMI logosu yayınlanmış")
    return notes
}

// CAA is looked up on the name and then each parent (RFC 8659 tree climbing): the closest set of
// records decides which CAs may issue. `lookup(name)` returns that name's CAA records.
async function effectiveCaa(domain,lookup){
    const labels=domain.split(".")
    // RFC 8659 tree-climbing includes the TLD and stops only before the DNS root.
    for(let i=0;i<labels.length;i++){
        const name=labels.slice(i).join(".")
        let records
        try{ records=await lookup(name) }
        catch{ return { name, records:[], lookupFailed:true } }
        if(records===null) return { name, records:[], lookupFailed:true }
        if(records.length) return { name, records }
    }
    return { name:null, records:[] }
}

function formatCaa(domain,caa){
    if(caa.lookupFailed) return `⚠️ ${caa.name} için CAA sorgusu başarısız oldu; geçerli politika belirlenemedi`
    if(!caa.records.length) return "ℹ️ CAA yok: herhangi bir sertifika otoritesi bu ad için sertifika verebilir"
    const lines=caa.records.map(r=>`${r.critical?"!":""}${Object.entries(r).filter(([k])=>k!=="critical").map(([k,v])=>`${k} ${v}`).join(" ")}`)
    return codeBlock(lines)+(caa.name!==domain ? `\n↳ ${caa.name} kayıtları geçerli` : "")
}

// A CNAME to a hosting service whose site was deleted leaves the name claimable by anyone
const TAKEOVER_SUFFIXES=[".github.io",".herokuapp.com",".herokudns.com",".s3.amazonaws.com",".cloudfront.net",".azurewebsites.net",".cloudapp.net",".trafficmanager.net",".blob.core.windows.net",".netlify.app",".surge.sh",".bitbucket.io",".ghost.io",".myshopify.com",".readthedocs.io"]

function danglingCnameNote(cname,a,aaaa){
    const target=String(cname[0]||"").replace(/\.$/,"").toLowerCase()
    if(!target || a.length || aaaa.length) return null
    return TAKEOVER_SUFFIXES.some(s=>target.endsWith(s))
        ? `⚠️ CNAME ${target} adresine gidiyor ama çözülmüyor: alt alan adı ele geçirilebilir`
        : null
}

// MX records by priority; a single "0 ." record (RFC 7505 null MX) means the domain takes no mail
function formatMx(records){
    if(records.length===1 && records[0].priority===0 && (records[0].exchange===""||records[0].exchange===".")) return ["Null MX: bu domain e-posta kabul etmiyor"]
    return [...records].sort((a,b)=>a.priority-b.priority).map(x=>`${x.priority} ${x.exchange}`)
}

// Discord also rejects a whole embed over 6000 characters; several long record sets can pass that
// even when each field fits, so later fields are shortened once the budget is spent.
function truncateText(text,limit){
    let result=text.slice(0,Math.max(0,limit))
    if(/[\uD800-\uDBFF]$/.test(result)) result=result.slice(0,-1)
    return result
}

function fitFields(fields,budget=5500){
    if(!Number.isFinite(budget)||budget<0) throw new RangeError('Invalid embed budget')
    let used=0
    const result=[]
    for(const field of fields.slice(0,25)){
        const room=Math.floor(budget)-used
        if(room<2) break
        const name=truncateText(String(field.name||'—'),Math.min(256,room-1))||'—'
        const available=Math.min(1024,room-name.length)
        if(available<1) break
        const raw=String(field.value||'—')
        let value=raw
        if(raw.length>available){
            if(raw.startsWith('```\n') && raw.endsWith('\n```') && available>=9){
                value='```\n'+truncateText(raw.slice(4,-4),available-9)+'…\n```'
            }else value=truncateText(raw,available-1)+'…'
        }
        result.push({...field,name,value})
        used+=name.length+value.length
    }
    return result
}

module.exports = { effectiveCaa, formatCaa, danglingCnameNote, inlineCode, normalizeDomain, joinTxt, gradeEmailSecurity, codeBlock, fitFields, formatMx, formatSoa, dnssecNote, mailTransportNotes, DKIM_SELECTORS, summarizeDkim }
