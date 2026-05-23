#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

banner "FSCAN" "fast internal network scanner"

ip=$(prompt_target)
outdir=$(make_outdir)
printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ip" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir/fscan.txt" "${RESET}"
printf '\n'

./fscan -h "$ip" | tee "$outdir/fscan.txt"
