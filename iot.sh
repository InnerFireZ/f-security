#!/usr/bin/env bash
# IoT / SCADA / Camera device discovery — wrapper for recon_iot_scada.py
source "$(dirname "$0")/lib.sh"

SCRIPT_DIR="$(dirname "$0")"
PYFILE="$SCRIPT_DIR/recon_iot_scada.py"
OUI_FILE="$SCRIPT_DIR/oui.txt"

require_tool python3 "pkg install python"
require_tool nmap    "pkg install nmap"

if ! python3 -c "import nmap" 2>/dev/null; then
  printf '  %s[!] python-nmap not installed. Run: pip install python-nmap%s\n' "${RED}" "${RESET}"
  exit 1
fi

banner "IoT / SCADA SCANNER" "camera · industrial · embedded device discovery"

target=$(prompt_target)
outdir=$(make_outdir)
outfile="$outdir/iot_scada.txt"

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
printf '\n'

# ── Scan options ──────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  SCAN OPTIONS                                    │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Quick   TCP only, no screenshots  %s(rootless-safe)%s\n'  "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[02]%s ▶  Full    TCP + UDP + screenshots   %s(needs root)%s\n'     "${YELLOW}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s ▶  Custom  enter flags manually\n'                            "${DIM}" "${RESET}"
printf '\n'

printf '  %s>>%s ' "${CYAN}" "${RESET}"
read -r _mode </dev/tty
_mode="${_mode:-1}"

case "$_mode" in
  1) extra_flags="--no-udp --no-screenshots" ;;
  2) extra_flags="" ;;
  3) printf '  %s>>%s Extra flags: ' "${CYAN}" "${RESET}"
     read -r extra_flags </dev/tty ;;
  *) extra_flags="--no-udp --no-screenshots" ;;
esac

# ── OUI hint ──────────────────────────────────────────────────────────────────
oui_flag=""
if [[ -f "$OUI_FILE" ]]; then
  oui_flag="--oui-file $OUI_FILE"
  printf '  %s[+]%s OUI database loaded: %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$OUI_FILE" "${RESET}"
fi

printf '\n  %s[*]%s Starting IoT/SCADA scan...%s\n\n' "${CYAN}" "${RESET}" "${RESET}"

# shellcheck disable=SC2086
python3 -u "$PYFILE" "$target" \
  --output "$outfile" \
  $oui_flag \
  $extra_flags \
  | tee -a "$outfile"

printf '\n  %s[+]%s Results saved to: %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
