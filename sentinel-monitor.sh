#!/bin/bash
docker logs -f sentinel-ai-agents 2>&1 | awk '
BEGIN {
    rules["550"]    = "FIM: File added to monitored directory"
    rules["553"]    = "FIM: File deleted from monitored directory"
    rules["554"]    = "FIM: File modified in monitored directory"
    rules["592"]    = "SCAN: Suricata network scan"
    rules["5402"]   = "PRIVESC: sudo to root"
    rules["5715"]   = "SSH: Successful login"
    rules["31103"]  = "WEB: SQL injection attempt"
    rules["31106"]  = "WEB: SQL injection (sqlmap)"
    rules["31122"]  = "WEB: Web attack"
    rules["31152"]  = "WEB: PHP injection"
    rules["31171"]  = "WEB: Web scanner"
    rules["60122"]  = "WIN: Multiple failed logons"
    rules["86601"]  = "NET: Suricata pfSense alert"
    rules["87702"]  = "NET: Multiple pfSense blocks"
    rules["92057"]  = "WIN: PowerShell on DC"
    rules["100114"] = "FALCO: Sensitive file read by web process"
    rules["100115"] = "FALCO: File opened by non-privileged process"
    rules["100130"] = "NET: Suricata ET SCAN/POLICY"
    rules["100150"] = "WEB: Webshell activity"
    rules["100600"] = "TLS: nginx TLS access logged"
    rules["100601"] = "TLS: Weak cipher on nginx (no PFS)"
    rules["100602"] = "TLS: Repeated weak cipher"
    rules["100611"] = "SQL: Query on infra_credentials"
    rules["100612"] = "SQL: Repeated credential theft"
    rules["100620"] = "LATERAL: External NTLM logon to DC"
    rules["100700"] = "KERBEROS: AS-REP Roast attempt"
    rules["100701"] = "KERBEROS: AS-REP Roast campaign"
    rules["100710"] = "KERBEROS: Kerberoast SPN request"
    rules["100711"] = "KERBEROS: Kerberoast bulk requests"
    rules["100720"] = "LATERAL: SSH from attacker VLAN"
    rules["100730"] = "EXFIL: Raw TCP to attacker"
    rules["100731"] = "EXFIL: Data staging"
    rules["100740"] = "RANSOM: Ransom note dropped"
    rules["100750"] = "DOH: DNS-over-HTTPS exfiltration"
    rules["100751"] = "DOH: DoH exfil campaign"
    rules["31101"]   = "WEB: HTTP 400 Bad Request (scanner noise)"
    rules["31120"]  = "WEB: HTTP 500 Server Error"
    rules["31122"]  = "WEB: Web attack returned 200"
    rules["31171"]  = "WEB: Web scanner activity"
    rules["60702"]  = "WIN: VSS service timeout"
    rules["61109"]  = "WIN: DNS resolution timeout"
    rules["92201"]  = "WIN: PowerShell script block logged"
    rules["92652"]  = "WIN: Successful NTLM remote logon"
    rules["100112"] = "FALCO: SSH key search command detected"
    rules["100171"] = "FALCO: Possible reverse shell from Apache"
    rules["100413"] = "DOH: External client hit DoH endpoint (Falco)"
    rules["100422"] = "DOH: Suricata+Falco cross-source DoH confirmation"
    rules["100534"] = "ADCS: ESC1 certificate requested"
    rules["100536"] = "ADCS: ESC1 certificate ISSUED"
}

function extract(line, key,    pos, rest, val, q) {
    pos = index(line, " " key "=")
    if (pos == 0) pos = index(line, "\t" key "=")
    if (pos == 0) return ""
    rest = substr(line, pos + length(key) + 2)
    if (substr(rest,1,1) == "'"'"'") {
        rest = substr(rest, 2)
        q = index(rest, "'"'"'")
        return (q > 0) ? substr(rest, 1, q-1) : rest
    }
    n = split(rest, a, " ")
    return a[1]
}

function ctx_label(ctx,    lbl) {
    if (ctx == "" || ctx == "None" || ctx == "True" || ctx == "False") return ""
    if (ctx ~ /^dispatched/) return ""
    if (ctx ~ /^severity/) return ""
    if (index(ctx, "/") > 0 || index(ctx, "\\") > 0)
        return sprintf("  \033[0;37mfile=%s\033[0m", ctx)
    if (ctx ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)
        return sprintf("  \033[0;37msrc=%s\033[0m", ctx)
    return ""
}

/ansible\.playbook\.executed/ {
    pb = extract($0, "playbook")
    rc = extract($0, "rc")
    ch = extract($0, "changed")
    if (rc+0 == 0) {
        printf "\033[1;32m┌─ PLAYBOOK: %-38s ✓ SUCCESS  changed=%s\033[0m\n", pb, ch
    } else {
        printf "\033[1;31m┌─ PLAYBOOK: %-38s ✗ FAILED   changed=%s\033[0m\n", pb, ch
    }
    fflush()
}

/playbook\.task\.changed/ {
    h  = extract($0, "host")
    oc = extract($0, "outcome")
    printf "\033[0;36m│  ├─ [%-20s] %s\033[0m\n", h, oc
    fflush()
}

/playbook\.outcome_summary/ {
    pb = extract($0, "playbook")
    printf "\033[0;36m└─ DONE: %s\033[0m\n", pb
    fflush()
}

/playbook\.task\.failed/ {
    h = extract($0, "host")
    t = extract($0, "task")
    pos = index($0, "error='"'"'")
    err = ""
    if (pos > 0) {
        err = substr($0, pos+7, 90)
        q = index(err, "'"'"'")
        if (q > 0) err = substr(err, 1, q-1)
    }
    printf "\033[1;31m│  ✗ FAILED  [%-18s] %s\033[0m\n", h, err
    fflush()
}

/alert_dispatcher\.processed.*dispatched=True/ {
    rid  = extract($0, "rule_id")
    desc = (rid in rules) ? rules[rid] : extract($0, "rule_desc")
    ctx  = extract($0, "context")
    cl   = ctx_label(ctx)
    printf "\033[1;35m▶ DISPATCH  rule=%-8s %s%s\033[0m\n", rid, desc, cl
    fflush()
}

/alert_dispatcher\.processed.*dispatched=False/ {
    rid  = extract($0, "rule_id")
    desc = (rid in rules) ? rules[rid] : extract($0, "rule_desc")
    ctx  = extract($0, "context")
    cl   = ctx_label(ctx)
    printf "\033[0;33m○ SKIPPED   rule=%-8s %s%s\033[0m\n", rid, desc, cl
    fflush()
}

/orchestrator\.processing/ {
    rid  = extract($0, "rule_id")
    desc = (rid in rules) ? rules[rid] : "unknown rule"
    printf "\033[0;34m⚡ ALERT     rule=%-8s %s\033[0m\n", rid, desc
    fflush()
}
'
