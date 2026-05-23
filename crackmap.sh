#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
require_tool crackmapexec "pip install crackmapexec"

banner "CRACKMAPEXEC" "SMB / RDP / WinRM null-session enumeration"

ip=$(prompt_target)
outdir=$(make_outdir)
printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ip" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir/crackmap.txt" "${RESET}"
printf '\n'

crackmapexec smb "$ip" -u '' -p '' --shares | tee "$outdir/crackmap.txt"
