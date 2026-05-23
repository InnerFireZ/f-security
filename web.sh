#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

WEB_PORTS="80,81,82,443,8000,8001,8008,8080,8081,8443,8888,9090,9443"
HTTPS_PORTS=(443 8443 9443)

banner "WEB RECON" "whatweb · nikto · gobuster · feroxbuster"

target=$(prompt_target)
outdir=$(make_outdir)

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir" "${RESET}"

# Phase 0: find live hosts with open web ports
_discover_web() {
  require_tool nmap
  printf '  %s[*]%s Scanning for live hosts with open web ports...%s\n' "${CYAN}" "${RESET}" "${RESET}"
  local out
  out=$(nmap -sT --unprivileged -Pn -n -p "$WEB_PORTS" --open -T4 "$target" 2>&1)
  if grep -qE "netlink|Permission denied" <<< "$out"; then
    printf '  %s[!] nmap error: %s%s\n' "${RED}" "$(grep -E 'netlink|Permission' <<< "$out" | head -1)" "${RESET}" >&2
    return 1
  fi
  local ip=""
  while IFS= read -r line; do
    if [[ "$line" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]] && [[ "$line" == *"scan report"* ]]; then
      ip="${BASH_REMATCH[1]}"
    elif [[ -n "$ip" && "$line" =~ ^([0-9]+)/tcp.*open ]]; then
      local port="${BASH_REMATCH[1]}"
      local scheme="http"
      for p in "${HTTPS_PORTS[@]}"; do [[ "$port" == "$p" ]] && scheme="https" && break; done
      echo "${scheme}://${ip}:${port}"
    fi
  done <<< "$out"
}

mapfile -t URLS < <(_discover_web 2>/dev/null)

if [[ ${#URLS[@]} -eq 0 ]]; then
  printf '  %s[!] No live hosts with open web ports found.%s\n' "${YELLOW}" "${RESET}"
  printf '  %s>>%s Enter URL manually (e.g. http://192.168.1.1:8080), or Enter to exit: ' "${CYAN}" "${RESET}"
  read -r _manual
  [[ -z "$_manual" ]] && exit 0
  URLS=("$_manual")
else
  printf '  %s[+]%s Found %d web target(s):%s\n' "${GREEN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  for u in "${URLS[@]}"; do printf '      %s%s%s\n' "${DIM}" "$u" "${RESET}"; done
  printf '\n'
fi

_safe() { echo "${1//[^a-zA-Z0-9._-]/_}"; }

_bar() {
  local cur=$1 tot=$2 width=20
  local pct=$(( cur * 100 / tot ))
  local filled=$(( cur * width / tot ))
  local bar=""
  for (( i=0; i<width; i++ )); do
    (( i < filled )) && bar+="█" || bar+="░"
  done
  printf '[%s] %3d%% [%d/%d]' "$bar" "$pct" "$cur" "$tot"
}

run_whatweb() {
  require_tool whatweb "apt install whatweb"
  printf '  %s[*]%s whatweb — %d target(s)%s\n' "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    whatweb -a 3 "$url" | tee -a "$outdir/whatweb.txt"
  done
}

run_nikto() {
  require_tool nikto "apt install nikto"
  printf '  %s[*]%s nikto — %d target(s)%s\n' "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    nikto -h "$url" | tee -a "$outdir/nikto.txt"
  done
}

run_gobuster() {
  require_tool gobuster "apt install gobuster"
  local wordlist="/usr/share/wordlists/dirb/common.txt"
  [[ ! -f "$wordlist" ]] && wordlist="/usr/share/dirb/wordlists/common.txt"
  if [[ ! -f "$wordlist" ]]; then
    printf '  %s>>%s Enter path to wordlist: ' "${CYAN}" "${RESET}"
    read -r wordlist
  fi
  printf '  %s[*]%s gobuster — %d target(s)%s\n' "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    gobuster dir -u "$url" -w "$wordlist" -t 20 | tee "$outdir/gobuster_$(_safe "$url").txt"
  done
}

run_feroxbuster() {
  require_tool feroxbuster "apt install feroxbuster"
  printf '  %s[*]%s feroxbuster — %d target(s)%s\n' "${CYAN}" "${RESET}" "${#URLS[@]}" "${RESET}"
  local _i=0
  for url in "${URLS[@]}"; do
    (( _i++ ))
    printf '  %s%s%s → %s\n' "${CYAN}" "$(_bar $_i ${#URLS[@]})" "${RESET}" "$url"
    feroxbuster -u "$url" -o "$outdir/ferox_$(_safe "$url").txt"
  done
}

web_menu() {
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  WEB RECON TOOLS                                 │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s[01]%s ▶  whatweb      Identify web technologies\n'        "${CYAN}" "${RESET}"
  printf '  %s[02]%s ▶  nikto        Web server vulnerability scanner\n' "${CYAN}" "${RESET}"
  printf '  %s[03]%s ▶  gobuster     Directory / file brute-force\n'     "${CYAN}" "${RESET}"
  printf '  %s[04]%s ▶  feroxbuster  Recursive content discovery\n'      "${CYAN}" "${RESET}"
  printf '  %s[05]%s ▶  Run all (1–4 in sequence)\n'                     "${GREEN}" "${RESET}"
  printf '  %s[00]%s ▶  Back\n'                                           "${RED}"  "${RESET}"
  printf '\n'
}

while true; do
  web_menu
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r choice
  case "$choice" in
    1) run_whatweb ;;
    2) run_nikto ;;
    3) run_gobuster ;;
    4) run_feroxbuster ;;
    5) run_whatweb; run_nikto; run_gobuster; run_feroxbuster ;;
    0) break ;;
    *) printf '  %s[!] Invalid option%s\n' "${RED}" "${RESET}" ;;
  esac
  printf '  %s▶%s Press Enter to continue...' "${DIM}" "${RESET}"
  read -r _
done
