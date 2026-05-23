#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
require_tool nmap

banner "NMAP — SERVICE SCANNER" "rootless TCP connect · -sT --unprivileged"

ip=$(prompt_target)
outdir=$(make_outdir)
printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ip" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$outdir/nmap.txt" "${RESET}"
printf '\n'

nmap -v -sT --unprivileged -sV -sC "$ip" | tee "$outdir/nmap.txt"
