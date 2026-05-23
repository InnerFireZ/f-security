#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "REPORT GENERATOR" "compile scan results into an HTML pentest report"

require_tool python3 "apt install python3"

# ── Session selection ─────────────────────────────────────────────────────────
mapfile -t SESSIONS < <(ls -1dt results/*/ 2>/dev/null || true)

if [[ ${#SESSIONS[@]} -eq 0 ]]; then
  printf '  %s[!] No scan sessions found in results/.%s\n\n' "${RED}" "${RESET}"
  exit 0
fi

printf '  %s[+]%s Available sessions:\n\n' "${GREEN}" "${RESET}"
printf '  %s  %-4s  %-26s  %s%s\n' "${DIM}" "ID" "SESSION" "FILES" "${RESET}"
printf '  %s  ──── ────────────────────────── ─────%s\n' "${DIM}" "${RESET}"
for i in "${!SESSIONS[@]}"; do
  _d="${SESSIONS[$i]}"
  _ts="${_d%/}"; _ts="${_ts##*/}"
  _fc=$(find "$_d" -maxdepth 1 -name "*.txt" -not -name ".*.txt" 2>/dev/null | wc -l)
  printf '  %s[%02d]%s  %-26s  %d file(s)\n' \
    "${CYAN}" "$(( i + 1 ))" "${RESET}" "$_ts" "$_fc"
done

printf '\n  %s>>%s Select session [1]: ' "${CYAN}" "${RESET}"
read -r _pick </dev/tty || _pick="1"
_pick="${_pick:-1}"

if ! [[ "$_pick" =~ ^[0-9]+$ ]] || (( _pick < 1 || _pick > ${#SESSIONS[@]} )); then
  printf '  %s[!] Invalid selection.%s\n' "${RED}" "${RESET}"
  exit 1
fi

SESSION_DIR="${SESSIONS[$(( _pick - 1 ))]}"
SESSION_NAME="${SESSION_DIR%/}"; SESSION_NAME="${SESSION_NAME##*/}"
REPORT_FILE="${SESSION_DIR}report.html"

printf '\n  %s[SYS]%s Session : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$SESSION_NAME" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$REPORT_FILE" "${RESET}"

section "GENERATING REPORT"
printf '  %s[*]%s Parsing + correlating findings...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

# ── Delegate all parsing and HTML generation to Python ────────────────────────
python3 - "$SESSION_DIR" "$SESSION_NAME" "$REPORT_FILE" << 'PYEOF'
import sys, os, re, html, json
from pathlib import Path
from datetime import datetime

session_dir  = Path(sys.argv[1])
session_name = sys.argv[2]
out_file     = sys.argv[3]

# ── Data model ────────────────────────────────────────────────────────────────
hosts = {}

def get_host(ip):
    if ip not in hosts:
        hosts[ip] = dict(type='Unknown', ports=[], ssl=[], vulns=[],
                         creds=[], warnings=[], probes=[], sources=set())
    return hosts[ip]

IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
ANSI  = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\[[0-9;]*m|\[[\d;]+m')

def strip_ansi(s):
    return ANSI.sub('', s)

# ── Load all .txt files ───────────────────────────────────────────────────────
file_data = {}
for fp in sorted(session_dir.glob('*.txt')):
    try:
        file_data[fp.name] = fp.read_text(errors='replace')
    except Exception:
        pass

# ── Parser: iot_scada.txt ─────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'iot_scada' not in fname:
        continue
    content = strip_ansi(raw)
    # Split on device separator lines
    dev_blocks = re.split(r'-{20,}', content)
    for block in dev_blocks:
        ip_m    = re.search(r'IP Address\s*:\s*(\S+)', block)
        type_m  = re.search(r'Device Type\s*:\s*(.+)', block)
        if not ip_m:
            continue
        ip = ip_m.group(1).strip()
        h  = get_host(ip)
        h['sources'].add(fname)
        if type_m:
            h['type'] = type_m.group(1).strip()
        in_ports = False
        for line in block.splitlines():
            if 'Open TCP Ports' in line:
                in_ports = True; continue
            if in_ports:
                pm = re.match(r'\s+(\d+)\s+/tcp\s*(\S*)\s*([^\n]*)', line)
                if pm:
                    svc   = pm.group(2).strip()
                    ver   = pm.group(3).strip()
                    entry = f"{pm.group(1)}/tcp  {svc} {ver}".strip()
                    if entry not in h['ports']:
                        h['ports'].append(entry)
                elif not line.strip() or 'Protocol' in line or ':' in line:
                    in_ports = False
        # Protocol probe results
        for pm in re.finditer(r'\[([A-Z_\-]+)\]\s*\n((?:[ \t]+.+\n)*)', block):
            name = pm.group(1)
            data = pm.group(2).strip()
            if data:
                h['probes'].append(f"[{name}] {data[:120]}")
        # Fingerprinted vendor
        for vm in re.finditer(r'vendor:\s*(\S+)', block, re.IGNORECASE):
            h['probes'].append(f"[VENDOR] {vm.group(1)}")

# ── Parser: ssl.txt summary + individual ssl_*.txt ───────────────────────────
for fname, raw in file_data.items():
    if 'ssl' not in fname:
        continue
    content = strip_ansi(raw)
    # Each target block starts with === IP:PORT ===
    for bm in re.finditer(r'===\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+===(.*?)(?====|\Z)', content, re.DOTALL):
        ip   = bm.group(1)
        port = bm.group(2)
        blk  = bm.group(3)
        h = get_host(ip)
        h['sources'].add(fname)

        issues = []
        if re.search(r'TLS 1\.1.*offered.*deprecated', blk, re.I):
            issues.append('TLS 1.1 deprecated')
        if re.search(r'TLS 1\s+.*offered.*deprecated', blk, re.I):
            issues.append('TLS 1.0 deprecated')
        if re.search(r'Triple DES.*offered', blk, re.I) and 'not offered' not in blk[blk.lower().find('triple'):blk.lower().find('triple')+40]:
            issues.append('3DES offered')
        if re.search(r'self signed', blk, re.I):
            issues.append('self-signed cert')
        if re.search(r'>= 10 years is way too long', blk, re.I):
            issues.append('cert validity >10 years')
        if re.search(r'Strict Transport Security.*not offered', blk, re.I):
            issues.append('HSTS missing')
        if re.search(r'Chain of trust.*NOT ok', blk, re.I):
            issues.append('broken chain of trust')

        # CVE-level vulnerabilities
        for vm in re.finditer(r'(Heartbleed|POODLE|BEAST|CRIME|ROBOT|FREAK|LOGJAM|DROWN|SWEET32|CVE-\d+-\d+)\s+([^\n]+)', blk, re.I):
            name  = vm.group(1)
            state = vm.group(2)
            if 'VULNERABLE' in state.upper() and 'NOT VULNERABLE' not in state.upper():
                h['vulns'].append(f"SSL CVE — {name} on {ip}:{port}")

        if issues:
            h['warnings'].extend([f"{i} ({ip}:{port})" for i in issues])
        if port not in [s['port'] for s in h['ssl']]:
            h['ssl'].append({'port': port, 'issues': issues})

# ── Parser: nmap.txt ──────────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'nmap' not in fname:
        continue
    content = strip_ansi(raw)
    for bm in re.finditer(r'Nmap scan report for (\S+)\n(.*?)(?=Nmap scan report|\Z)', content, re.DOTALL):
        target = bm.group(1)
        blk    = bm.group(2)
        ipm    = IP_RE.search(target)
        if not ipm:
            continue
        ip = ipm.group(1)
        h  = get_host(ip)
        h['sources'].add(fname)
        for pm in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*?)$', blk, re.MULTILINE):
            entry = f"{pm.group(1)}/tcp  {pm.group(2)} {pm.group(3).strip()}".rstrip()
            if entry not in h['ports']:
                h['ports'].append(entry)

# ── Parser: nuclei.txt ────────────────────────────────────────────────────────
for fname, raw in file_data.items():
    if 'nuclei' not in fname:
        continue
    content = strip_ansi(raw)
    for line in content.splitlines():
        sm = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
        im = IP_RE.search(line)
        if sm and im:
            sev = sm.group(1).lower()
            ip  = im.group(1)
            h   = get_host(ip)
            h['sources'].add(fname)
            if sev in ('critical', 'high'):
                h['vulns'].append(line.strip())
            elif sev == 'medium':
                h['warnings'].append(line.strip())

# ── Parser: credential lines across all files ─────────────────────────────────
for fname, raw in file_data.items():
    content = strip_ansi(raw)
    for line in content.splitlines():
        ll = line.lower()
        im = IP_RE.search(line)
        if not im:
            continue
        ip = im.group(1)
        if ('login:' in ll and 'password:' in ll) or \
           ('[+]' in line and re.search(r'(pass|hash|auth)', ll) and re.search(r'(smb|ssh|ftp|rdp|http)', ll, re.I)):
            h = get_host(ip)
            h['sources'].add(fname)
            if line.strip() not in h['creds']:
                h['creds'].append(line.strip())

# ── Also mark IPs from alive_hosts ───────────────────────────────────────────
for fname, raw in file_data.items():
    if 'alive' not in fname and 'host' not in fname:
        continue
    content = strip_ansi(raw)
    for ip in IP_RE.findall(content):
        h = get_host(ip)
        h['sources'].add(fname)

# ── Stats ─────────────────────────────────────────────────────────────────────
total_hosts = len(hosts)
total_vulns = sum(len(h['vulns'])    for h in hosts.values())
total_creds = sum(len(h['creds'])    for h in hosts.values())
total_warns = sum(len(h['warnings']) for h in hosts.values())
total_ports = sum(len(h['ports'])    for h in hosts.values())
total_files = len(file_data)

def host_score(item):
    _, h = item
    return -(len(h['vulns'])*100 + len(h['creds'])*50 + len(h['warnings'])*10 + len(h['ports']))

sorted_hosts = sorted(hosts.items(), key=host_score)

# ── HTML helpers ──────────────────────────────────────────────────────────────
def e(s): return html.escape(str(s))

def colorize_block(text):
    text = strip_ansi(text)
    lines = []
    for ln in text.splitlines():
        esc  = e(ln)
        lo   = esc.lower()
        if ('vulnerable' in lo and 'not vulnerable' not in lo) or 'not ok' in lo:
            lines.append(f'<span class="crit">{esc}</span>')
        elif 'login:' in lo and 'password:' in lo:
            lines.append(f'<span class="crit">{esc}</span>')
        elif re.search(r'\b(critical|high)\b', lo):
            lines.append(f'<span class="crit">{esc}</span>')
        elif ('[+]' in esc or '✔' in esc or '(ok)' in lo or 'not offered (ok)' in lo):
            lines.append(f'<span class="ok">{esc}</span>')
        elif re.search(r'\bmedium\b', lo) or 'deprecated' in lo or 'self signed' in lo or '3des' in lo:
            lines.append(f'<span class="warn">{esc}</span>')
        elif '[~]' in esc or 'expired' in lo or ' weak ' in lo or '[!]' in esc:
            lines.append(f'<span class="warn">{esc}</span>')
        elif '[*]' in esc or '[sys]' in lo or '[info]' in lo or 'info' in lo:
            lines.append(f'<span class="info">{esc}</span>')
        else:
            lines.append(esc)
    return '\n'.join(lines)

def type_icon(t):
    tl = (t or '').lower()
    if 'camera' in tl or 'cctv' in tl: return '📷'
    if 'scada' in tl or 'ics'  in tl: return '⚡'
    if 'iot'   in tl:                  return '◈'
    if 'windows' in tl or 'smb' in tl: return '⊞'
    return '◉'

def risk_class(h):
    if h['vulns'] or h['creds']: return 'risk-c', 'CRITICAL'
    if h['warnings']:             return 'risk-w', 'WARN'
    return 'risk-i', 'INFO'

def port_tag(p):
    num = p.split('/')[0].strip()
    return f'<span class="ptag">{e(num)}</span>'

def source_tags(sources):
    tags = []
    for s in sorted(sources):
        name = s.replace('.txt','').replace('_',' ')
        tags.append(f'<span class="stag">{e(name)}</span>')
    return ' '.join(tags)

# ── Write HTML ────────────────────────────────────────────────────────────────
now = datetime.now().strftime('%Y-%m-%d %H:%M')

with open(out_file, 'w') as f:
    f.write(f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>F-Security Report — {e(session_name)}</title>
<style>
:root{{--bg:#0a0c0f;--bg2:#0f1318;--bg3:#131b24;--bd:#1a2535;--tx:#8899aa;
      --cy:#00ccff;--gn:#00cc66;--rd:#ff3333;--or:#ffaa00;--pu:#cc88ff;
      --dim:#3a4a5a}}
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--tx);font-family:'Courier New',Consolas,monospace;
     font-size:13px;line-height:1.5;padding:16px 20px;max-width:1500px;margin:0 auto}}

/* ── Header ── */
header{{border-bottom:1px solid var(--bd);padding-bottom:12px;margin-bottom:20px;
        display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:8px}}
.hdr-title{{color:var(--cy);font-size:1.1em;letter-spacing:3px;font-weight:bold}}
.hdr-meta{{font-size:0.78em;color:var(--dim)}}
.hdr-meta span{{color:var(--cy)}}

/* ── Stat cards ── */
.cards{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}}
.card{{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;
       padding:10px 16px;min-width:110px;text-align:center;flex:1}}
.card .n{{font-size:1.8em;font-weight:bold;line-height:1}}
.card .l{{font-size:0.7em;letter-spacing:1.5px;margin-top:4px;color:var(--dim)}}
.card.r{{border-color:var(--rd)}}.card.r .n{{color:var(--rd)}}
.card.g{{border-color:var(--gn)}}.card.g .n{{color:var(--gn)}}
.card.a{{border-color:var(--or)}}.card.a .n{{color:var(--or)}}
.card.b{{border-color:var(--cy)}}.card.b .n{{color:var(--cy)}}
.card.p{{border-color:var(--pu)}}.card.p .n{{color:var(--pu)}}

/* ── Toolbar ── */
.toolbar{{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}}
.toolbar input{{background:var(--bg2);border:1px solid var(--bd);color:var(--cy);
                padding:5px 10px;border-radius:3px;font-family:inherit;font-size:0.85em;
                width:220px;outline:none}}
.toolbar input::placeholder{{color:var(--dim)}}
.toolbar input:focus{{border-color:var(--cy)}}
button{{background:var(--bg2);color:var(--cy);border:1px solid var(--bd);
        padding:5px 12px;cursor:pointer;border-radius:3px;font-family:inherit;
        font-size:0.82em}}
button:hover{{border-color:var(--cy);color:#fff}}
.btn-warn{{color:var(--or);border-color:var(--or)}}
.btn-crit{{color:var(--rd);border-color:var(--rd)}}

/* ── Section wrapper ── */
.sec{{background:var(--bg2);border:1px solid var(--bd);border-left:3px solid var(--cy);
      border-radius:4px;margin-bottom:10px;overflow:hidden}}
.sec.warn-border{{border-left-color:var(--or)}}
.sec.crit-border{{border-left-color:var(--rd)}}
.sec h2{{background:var(--bg);color:var(--cy);padding:8px 14px;font-size:0.85em;
         letter-spacing:2px;border-bottom:1px solid var(--bd);
         cursor:pointer;user-select:none;display:flex;justify-content:space-between;align-items:center}}
.sec h2 .h2l{{display:flex;align-items:center;gap:8px}}
.sec h2::before{{content:"▶ "}}
.sec.col h2::before{{content:"▷ "}}
.sec-body{{padding:12px 14px}}
.sec.col .sec-body{{display:none}}
pre{{white-space:pre-wrap;word-break:break-all;font-size:11.5px;line-height:1.42}}

/* ── Host matrix table ── */
.matrix-wrap{{overflow-x:auto;margin-bottom:4px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:var(--bg);color:var(--cy);padding:6px 10px;text-align:left;
    border-bottom:2px solid var(--bd);font-size:0.78em;letter-spacing:1.5px;
    white-space:nowrap}}
td{{padding:5px 10px;border-bottom:1px solid var(--bd);vertical-align:top}}
tr:hover td{{background:var(--bg3)}}
tr.hide{{display:none}}

.ip-link{{color:var(--cy);text-decoration:none;font-weight:bold}}
.ip-link:hover{{color:#fff}}

/* ── Risk / type badges ── */
.risk-c{{color:var(--rd);font-weight:bold;font-size:0.78em}}
.risk-w{{color:var(--or);font-size:0.78em}}
.risk-i{{color:var(--dim);font-size:0.78em}}
.badge{{display:inline-block;font-size:0.75em;padding:1px 6px;border-radius:2px;
        border:1px solid;margin-right:3px;white-space:nowrap}}
.bc{{color:var(--or);border-color:var(--or)}}
.bs{{color:#ff6644;border-color:#ff6644}}
.bi{{color:var(--pu);border-color:var(--pu)}}
.bw{{color:#4499ff;border-color:#4499ff}}
.bu{{color:var(--dim);border-color:var(--dim)}}

.ptag{{display:inline-block;background:var(--bg);border:1px solid var(--bd);
       font-size:0.72em;padding:0 4px;border-radius:2px;color:var(--cy);
       margin:1px;white-space:nowrap}}
.stag{{display:inline-block;background:var(--bg);border:1px solid var(--bd);
       font-size:0.7em;padding:0 5px;border-radius:2px;color:var(--dim);margin:1px}}

/* ── Findings list ── */
.find-list{{list-style:none;padding:0}}
.find-list li{{padding:3px 0;border-bottom:1px solid #111;display:flex;gap:8px;align-items:flex-start}}
.find-list li:last-child{{border-bottom:none}}
.find-ip{{min-width:100px;color:var(--cy);font-weight:bold;flex-shrink:0;font-size:0.85em}}
.find-txt{{color:var(--tx)}}
.find-txt.crit{{color:var(--rd)}}
.find-txt.warn{{color:var(--or)}}
.find-txt.ok{{color:var(--gn)}}

/* ── Colorizer spans ── */
.ok{{color:var(--gn)}}
.crit{{color:var(--rd);font-weight:bold}}
.warn{{color:var(--or)}}
.info{{color:var(--cy)}}

/* ── Device detail card ── */
.host-card{{background:var(--bg3);border:1px solid var(--bd);border-radius:4px;
            padding:10px 14px;margin-bottom:8px}}
.host-card .hc-ip{{color:var(--cy);font-weight:bold;font-size:1em}}
.host-card .hc-type{{color:var(--dim);font-size:0.8em;margin-left:8px}}
.hc-row{{margin-top:4px;font-size:0.8em}}
.hc-label{{color:var(--dim);min-width:80px;display:inline-block}}

/* ── Footer ── */
footer{{margin-top:20px;padding-top:10px;border-top:1px solid var(--bd);
        color:var(--dim);font-size:0.76em;display:flex;justify-content:space-between}}
</style>
</head>
<body>

<header>
  <div>
    <div class="hdr-title">▓▒░  F-SECURITY PENTEST REPORT  ░▒▓</div>
    <div class="hdr-meta">Session: <span>{e(session_name)}</span>
      &nbsp;·&nbsp; Generated: <span>{now}</span>
      &nbsp;·&nbsp; {total_files} source file(s)</div>
  </div>
</header>

<div class="cards">
  <div class="card r"><div class="n">{total_vulns}</div><div class="l">VULNERABILITIES</div></div>
  <div class="card g"><div class="n">{total_creds}</div><div class="l">CREDENTIALS</div></div>
  <div class="card a"><div class="n">{total_warns}</div><div class="l">WARNINGS</div></div>
  <div class="card b"><div class="n">{total_ports}</div><div class="l">OPEN PORTS</div></div>
  <div class="card p"><div class="n">{total_hosts}</div><div class="l">HOSTS SEEN</div></div>
</div>

<div class="toolbar">
  <input type="text" id="ip-filter" placeholder="Filter by IP…" oninput="filterHosts(this.value)">
  <button onclick="filterRisk('crit')" class="btn-crit">● CRITICAL</button>
  <button onclick="filterRisk('warn')" class="btn-warn">◐ WARNINGS</button>
  <button onclick="filterRisk('')">ALL HOSTS</button>
  <button onclick="expandAll()">▶ Expand All</button>
  <button onclick="collapseAll()">▷ Collapse All</button>
</div>
''')

    # ── Section 1: Host Matrix ────────────────────────────────────────────────
    f.write('''
<div class="sec" id="sec-matrix">
<h2><span class="h2l">HOST INTELLIGENCE MATRIX</span>
    <span style="color:var(--dim);font-size:0.8em;font-weight:normal">''' + str(total_hosts) + ''' hosts</span></h2>
<div class="sec-body">
<div class="matrix-wrap">
<table id="host-table">
<thead><tr>
  <th>IP ADDRESS</th><th>TYPE</th><th>RISK</th><th>OPEN PORTS</th>
  <th>VULNS</th><th>CREDS</th><th>WARNINGS</th><th>SSL ISSUES</th><th>SOURCES</th>
</tr></thead>
<tbody>
''')

    for ip, h in sorted_hosts:
        rc, rl = risk_class(h)
        ssl_count = sum(len(s['issues']) for s in h['ssl'])
        ssl_ports = ', '.join(s['port'] for s in h['ssl']) if h['ssl'] else '—'
        port_tags = ' '.join(port_tag(p) for p in h['ports'][:12])
        if len(h['ports']) > 12:
            port_tags += f' <span style="color:var(--dim)">+{len(h["ports"])-12} more</span>'
        row_class = 'data-risk="crit"' if h['vulns'] or h['creds'] else \
                    'data-risk="warn"' if h['warnings'] else 'data-risk="info"'
        f.write(f'''<tr {row_class} data-ip="{e(ip)}">
  <td><a class="ip-link" href="#host-{e(ip.replace(".","_"))}">{e(ip)}</a></td>
  <td>{type_icon(h["type"])} {e(h["type"])}</td>
  <td><span class="{rc}">{rl}</span></td>
  <td style="max-width:320px">{port_tags if port_tags else "—"}</td>
  <td style="color:var(--rd)">{len(h["vulns"]) or "—"}</td>
  <td style="color:var(--gn)">{len(h["creds"]) or "—"}</td>
  <td style="color:var(--or)">{len(h["warnings"]) or "—"}</td>
  <td style="color:var(--or);font-size:0.8em">{ssl_count or "—"}</td>
  <td>{source_tags(h["sources"])}</td>
</tr>
''')

    f.write('</tbody></table></div></div></div>\n')

    # ── Section 2: Critical Findings (only if any) ────────────────────────────
    all_vulns = [(ip, v) for ip, h in sorted_hosts for v in h['vulns']]
    all_creds = [(ip, c) for ip, h in sorted_hosts for c in h['creds']]
    all_warns = [(ip, w) for ip, h in sorted_hosts for w in h['warnings']]

    if all_vulns or all_creds:
        f.write('''
<div class="sec crit-border" id="sec-critical">
<h2><span class="h2l">CRITICAL FINDINGS</span>
    <span style="color:var(--rd);font-size:0.8em;font-weight:normal">''' +
    str(len(all_vulns) + len(all_creds)) + ''' items</span></h2>
<div class="sec-body">
''')
        if all_vulns:
            f.write('<div style="margin-bottom:10px;color:var(--rd);font-size:0.8em;letter-spacing:1px">▸ VULNERABILITIES</div>\n')
            f.write('<ul class="find-list">\n')
            for ip, v in all_vulns:
                f.write(f'<li><span class="find-ip">{e(ip)}</span>'
                        f'<span class="find-txt crit">{e(strip_ansi(v))}</span></li>\n')
            f.write('</ul>\n')
        if all_creds:
            f.write('<div style="margin:10px 0 6px;color:var(--gn);font-size:0.8em;letter-spacing:1px">▸ CREDENTIALS</div>\n')
            f.write('<ul class="find-list">\n')
            for ip, c in all_creds:
                f.write(f'<li><span class="find-ip">{e(ip)}</span>'
                        f'<span class="find-txt ok">{e(strip_ansi(c))}</span></li>\n')
            f.write('</ul>\n')
        f.write('</div></div>\n')

    if all_warns:
        f.write('''
<div class="sec warn-border col" id="sec-warnings">
<h2><span class="h2l">WARNINGS &amp; ADVISORIES</span>
    <span style="color:var(--or);font-size:0.8em;font-weight:normal">''' +
    str(len(all_warns)) + ''' items</span></h2>
<div class="sec-body"><ul class="find-list">\n''')
        for ip, w in all_warns:
            f.write(f'<li><span class="find-ip">{e(ip)}</span>'
                    f'<span class="find-txt warn">{e(strip_ansi(w))}</span></li>\n')
        f.write('</ul></div></div>\n')

    # ── Section 3: Per-host detail cards ─────────────────────────────────────
    hosts_with_detail = [(ip, h) for ip, h in sorted_hosts
                         if h['ports'] or h['vulns'] or h['creds'] or h['ssl']]
    if hosts_with_detail:
        f.write(f'''
<div class="sec col" id="sec-hosts">
<h2><span class="h2l">HOST DETAILS</span>
    <span style="color:var(--dim);font-size:0.8em;font-weight:normal">{len(hosts_with_detail)} hosts with data</span></h2>
<div class="sec-body">
''')
        for ip, h in hosts_with_detail:
            anchor = f'host-{ip.replace(".","_")}'
            rc, rl = risk_class(h)
            f.write(f'<div class="host-card" id="{anchor}">\n')
            f.write(f'<span class="hc-ip">{e(ip)}</span>'
                    f'<span class="hc-type">{type_icon(h["type"])} {e(h["type"])}</span>'
                    f'&nbsp;&nbsp;<span class="{rc}">{rl}</span>\n')
            if h['ports']:
                f.write(f'<div class="hc-row"><span class="hc-label">PORTS</span>'
                        + ' '.join(port_tag(p) for p in h['ports']) + '</div>\n')
            if h['ssl']:
                for s in h['ssl']:
                    iss = ', '.join(s['issues']) if s['issues'] else 'OK'
                    col = 'var(--or)' if s['issues'] else 'var(--gn)'
                    f.write(f'<div class="hc-row"><span class="hc-label">SSL :{s["port"]}</span>'
                            f'<span style="color:{col};font-size:0.8em">{e(iss)}</span></div>\n')
            if h['probes']:
                f.write('<div class="hc-row"><span class="hc-label">PROBES</span>'
                        f'<span style="font-size:0.8em;color:var(--dim)">'
                        + ' &nbsp;|&nbsp; '.join(e(p) for p in h['probes'][:6])
                        + '</span></div>\n')
            if h['vulns']:
                for v in h['vulns']:
                    f.write(f'<div class="hc-row" style="color:var(--rd)">'
                            f'<span class="hc-label">VULN</span>{e(strip_ansi(v))}</div>\n')
            if h['creds']:
                for c in h['creds']:
                    f.write(f'<div class="hc-row" style="color:var(--gn)">'
                            f'<span class="hc-label">CRED</span>{e(strip_ansi(c))}</div>\n')
            f.write(f'<div class="hc-row" style="margin-top:4px">'
                    f'<span class="hc-label">SOURCES</span>{source_tags(h["sources"])}</div>\n')
            f.write('</div>\n')
        f.write('</div></div>\n')

    # ── Section 4: Raw module output ─────────────────────────────────────────
    f.write('''
<div class="sec col" id="sec-raw">
<h2><span class="h2l">RAW MODULE OUTPUT</span>
    <span style="color:var(--dim);font-size:0.8em;font-weight:normal">''' + str(len(file_data)) + ''' files</span></h2>
<div class="sec-body">
''')
    for fname, raw in sorted(file_data.items()):
        lines = raw.count('\n')
        # Find IPs mentioned in this file
        ips_in_file = sorted(set(IP_RE.findall(strip_ansi(raw))))[:8]
        ip_tags = ' '.join(f'<a class="stag" href="#host-{ip.replace(".","_")}" style="color:var(--cy)">{e(ip)}</a>'
                           for ip in ips_in_file)
        has_vuln = bool(re.search(r'vulnerable|NOT ok|CRITICAL|HIGH', raw, re.I))
        has_cred = bool(re.search(r'login:.*password:|password:.*login:', raw, re.I))
        border = ' crit-border' if (has_vuln or has_cred) else ''
        f.write(f'''<div class="sec col{border}" style="margin-bottom:8px">
<h2 style="font-size:0.8em">
  <span class="h2l"><span style="color:var(--cy)">{e(fname)}</span>
  &nbsp;<span style="color:var(--dim)">{lines} lines</span>
  &nbsp;{ip_tags}</span>
  {"<span style='color:var(--rd)'>⚠ findings</span>" if (has_vuln or has_cred) else ""}
</h2>
<div class="sec-body"><pre>{colorize_block(raw)}</pre></div>
</div>
''')
    f.write('</div></div>\n')

    # ── Footer + JS ───────────────────────────────────────────────────────────
    f.write(f'''
<footer>
  <span>F-Security Pentest Report &nbsp;·&nbsp; {e(session_name)}</span>
  <span>rootless Kali NetHunter &nbsp;·&nbsp; {now}</span>
</footer>

<script>
function expandAll()  {{ document.querySelectorAll('.sec').forEach(s=>s.classList.remove('col')); }}
function collapseAll(){{ document.querySelectorAll('.sec').forEach(s=>s.classList.add('col')); }}

document.querySelectorAll('.sec > h2').forEach(h=>{{
  h.addEventListener('click', ()=> h.parentElement.classList.toggle('col'));
}});

function filterHosts(q) {{
  q = q.trim().toLowerCase();
  document.querySelectorAll('#host-table tbody tr').forEach(r => {{
    const ip = (r.dataset.ip || '').toLowerCase();
    r.classList.toggle('hide', q !== '' && !ip.includes(q));
  }});
}}

function filterRisk(level) {{
  document.querySelectorAll('#host-table tbody tr').forEach(r => {{
    if (!level) {{ r.classList.remove('hide'); return; }}
    r.classList.toggle('hide', r.dataset.risk !== level);
  }});
  document.getElementById('ip-filter').value = '';
}}
</script>
</body></html>
''')

print(f"  [+] Report written: {out_file}")
print(f"  [+] Hosts parsed: {total_hosts}  Vulns: {total_vulns}  Creds: {total_creds}  Warns: {total_warns}")
PYEOF

_py_exit=$?
if [[ $_py_exit -ne 0 ]]; then
  printf '  %s[!] Report generation failed (exit %d).%s\n\n' "${RED}" "$_py_exit" "${RESET}"
  exit 1
fi

_sz=$(du -h "$REPORT_FILE" 2>/dev/null | cut -f1)
printf '\n  %s[✔]%s Report saved — %s%s%s  (%s)\n\n' \
  "${GREEN}" "${RESET}" "${DIM}" "$REPORT_FILE" "${RESET}" "$_sz"

# ── Serve ─────────────────────────────────────────────────────────────────────
printf '  %s>>%s Serve report in browser? [Y/n]: ' "${CYAN}" "${RESET}"
read -r _serve </dev/tty || _serve="n"
if [[ "${_serve,,}" != "n" ]]; then
  _port=8888
  _ip="$(get_ip)"
  printf '\n'
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  REPORT SERVER                                   │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s[SYS]%s URL  : %shttp://%s:%d/report.html%s\n' \
    "${CYAN}" "${RESET}" "${GREEN}" "$_ip" "$_port" "${RESET}"
  printf '  %s[SYS]%s Open this URL on any device on the same network.%s\n' \
    "${CYAN}" "${RESET}" "${RESET}"
  printf '  %s[*]%s Press Ctrl+C to stop the server.\n\n' "${DIM}" "${RESET}"
  cd "$SESSION_DIR" && python3 -m http.server "$_port" 2>/dev/null || true
fi
