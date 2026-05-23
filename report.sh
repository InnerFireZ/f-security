#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

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

# ── Count key findings ────────────────────────────────────────────────────────
section "ANALYSING FINDINGS"

CREDS=$( (grep -rh "login:"                 "${SESSION_DIR}" 2>/dev/null || true) | wc -l)
VULNS=$( (grep -rh "VULNERABLE\|NOT ok"     "${SESSION_DIR}" 2>/dev/null || true) | wc -l)
WARNS=$( (grep -rh "deprecated\|expired\|self signed\| weak " \
  "${SESSION_DIR}" 2>/dev/null || true) | wc -l)
PORTS=$( (grep -rh "/tcp.*open\|/udp.*open" \
  "${SESSION_DIR}/nmap.txt" 2>/dev/null || true) | wc -l)
FILES=$(find "${SESSION_DIR}" -maxdepth 1 -name "*.txt" \
  -not -name ".*.txt" 2>/dev/null | wc -l)

printf '  %s[!]%s Vulnerabilities : %s%d%s\n' "${RED}"    "${RESET}" "${RED}"    "$VULNS" "${RESET}"
printf '  %s[✔]%s Credentials     : %s%d%s\n' "${GREEN}"  "${RESET}" "${GREEN}"  "$CREDS" "${RESET}"
printf '  %s[~]%s Warnings        : %s%d%s\n' "${YELLOW}" "${RESET}" "${YELLOW}" "$WARNS" "${RESET}"
printf '  %s[*]%s Open ports      : %s%d%s\n' "${CYAN}"   "${RESET}" "${DIM}"    "$PORTS" "${RESET}"
printf '\n'

# ── Python line colorizer (reused for each file section) ─────────────────────
_PY_COL=$(cat <<'PYEOF'
import sys, html
for ln in sys.stdin:
    ln = ln.rstrip('\n')
    e = html.escape(ln)
    lo = e.lower()
    if 'vulnerable' in lo or 'not ok' in lo:
        print('<span class="crit">' + e + '</span>')
    elif 'login:' in lo and 'password:' in lo:
        print('<span class="crit">' + e + '</span>')
    elif '[+]' in e or '✔' in e:
        print('<span class="ok">' + e + '</span>')
    elif '[~]' in e or 'deprecated' in lo or 'expired' in lo or 'weak' in lo:
        print('<span class="warn">' + e + '</span>')
    elif '[*]' in e or '[sys]' in lo or '[info]' in lo:
        print('<span class="info">' + e + '</span>')
    elif '[!]' in e:
        print('<span class="warn">' + e + '</span>')
    else:
        print(e)
PYEOF
)

# ── Generate HTML report ──────────────────────────────────────────────────────
section "GENERATING REPORT"
printf '  %s[*]%s Building HTML...%s\n' "${CYAN}" "${RESET}" "${RESET}"

{
# ── HTML head + CSS ───────────────────────────────────────────────────────────
cat << HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Report — ${SESSION_NAME}</title>
<style>
:root{--bg:#0a0c0f;--bg2:#0f1318;--bd:#1e2d3d;--tx:#8899aa;
      --cy:#00ccff;--gn:#00cc66;--rd:#ff3333;--or:#ffaa00}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Courier New',Consolas,monospace;
     font-size:13px;line-height:1.5;padding:20px;max-width:1400px;margin:0 auto}
header{border-bottom:1px solid var(--bd);padding-bottom:14px;margin-bottom:22px}
header h1{color:var(--cy);font-size:1.25em;letter-spacing:3px}
header .meta{margin-top:5px;font-size:0.82em}
.actions{margin-bottom:18px}
button{background:var(--bg2);color:var(--cy);border:1px solid var(--bd);
       padding:5px 14px;cursor:pointer;border-radius:3px;font-family:inherit;
       font-size:0.85em;margin-right:8px}
button:hover{border-color:var(--cy)}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:24px}
.card{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;
      padding:12px 18px;min-width:120px;text-align:center}
.card .n{font-size:1.9em;font-weight:bold}
.card .l{font-size:0.75em;letter-spacing:1px;margin-top:3px;color:var(--tx)}
.card.r{border-color:var(--rd)}.card.r .n{color:var(--rd)}
.card.g{border-color:var(--gn)}.card.g .n{color:var(--gn)}
.card.a{border-color:var(--or)}.card.a .n{color:var(--or)}
.card.b{border-color:var(--cy)}.card.b .n{color:var(--cy)}
.sec{background:var(--bg2);border:1px solid var(--bd);border-left:3px solid var(--cy);
     border-radius:4px;margin-bottom:14px;overflow:hidden}
.sec h2{background:var(--bg);color:var(--cy);padding:8px 14px;font-size:0.88em;
        letter-spacing:2px;border-bottom:1px solid var(--bd);
        cursor:pointer;user-select:none}
.sec h2::before{content:"▶ "}
.sec.col h2::before{content:"▷ "}
.sec-body{padding:12px 14px}
.sec.col .sec-body{display:none}
pre{white-space:pre-wrap;word-break:break-all;font-size:11.5px;line-height:1.42}
.ok{color:var(--gn)}.crit{color:var(--rd);font-weight:bold}
.warn{color:var(--or)}.info{color:var(--cy)}
footer{margin-top:24px;padding-top:10px;border-top:1px solid var(--bd);
       color:#3a4a5a;font-size:0.78em}
</style>
</head>
<body>
<header>
  <h1>▓▒░ PENTEST REPORT ░▒▓</h1>
  <div class="meta">
    Session: <strong style="color:var(--cy)">${SESSION_NAME}</strong>
    &nbsp;·&nbsp; Generated: $(date '+%Y-%m-%d %H:%M:%S')
    &nbsp;·&nbsp; ${FILES} result file(s)
  </div>
</header>
<div class="actions">
  <button onclick="document.querySelectorAll('.sec').forEach(s=>s.classList.remove('col'))">▶ Expand All</button>
  <button onclick="document.querySelectorAll('.sec').forEach(s=>s.classList.add('col'))">▷ Collapse All</button>
</div>
<div class="cards">
  <div class="card r"><div class="n">${VULNS}</div><div class="l">VULNERABILITIES</div></div>
  <div class="card g"><div class="n">${CREDS}</div><div class="l">CREDENTIALS</div></div>
  <div class="card a"><div class="n">${WARNS}</div><div class="l">WARNINGS</div></div>
  <div class="card b"><div class="n">${PORTS}</div><div class="l">OPEN PORTS</div></div>
</div>
HTMLHEAD

# ── Per-file sections ─────────────────────────────────────────────────────────
find "${SESSION_DIR}" -maxdepth 1 -name "*.txt" -not -name ".*.txt" 2>/dev/null \
| sort | while IFS= read -r _f; do
  _fname=$(basename "$_f")
  _lines=$(wc -l < "$_f" 2>/dev/null || echo 0)
  _sz=$(du -h "$_f" 2>/dev/null | cut -f1)
  printf '<div class="sec col">\n'
  printf '<h2>%s &nbsp;<span style="color:#2a3a4a;font-size:0.82em">%d lines · %s</span></h2>\n' \
    "$_fname" "$_lines" "$_sz"
  printf '<div class="sec-body"><pre>'
  python3 -c "$_PY_COL" < "$_f" 2>/dev/null || true
  printf '</pre></div></div>\n'
done

# ── HTML foot ─────────────────────────────────────────────────────────────────
cat << HTMLFOOT
<footer>F-Security Pentest Report &nbsp;·&nbsp; $(date '+%Y-%m-%d') &nbsp;·&nbsp; rootless Kali NetHunter</footer>
<script>
document.querySelectorAll('.sec h2').forEach(h=>{
  h.addEventListener('click',()=>h.parentElement.classList.toggle('col'));
});
</script>
</body></html>
HTMLFOOT

} > "$REPORT_FILE"

_sz=$(du -h "$REPORT_FILE" 2>/dev/null | cut -f1)
printf '  %s[✔]%s Report saved — %s%s%s  (%s)\n\n' \
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
