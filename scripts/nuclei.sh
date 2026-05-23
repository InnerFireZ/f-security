#!/usr/bin/env bash
# nuclei.sh — Nuclei LAN/IoT vulnerability scanner (rootless Android optimised)
source "$(dirname "$0")/../lib.sh"
require_tool nuclei "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

set -u

banner "NUCLEI" "fast vulnerability scanner · LAN / IoT optimised"

# ── Target ────────────────────────────────────────────────────────────────────
target="$(prompt_target)"
outdir="$(make_outdir)"
outfile="$outdir/nuclei.txt"
hosts_file="$outdir/alive_hosts.txt"
scan_file="$outdir/scan_targets.txt"
: > "$hosts_file"
: > "$scan_file"

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

# ── Template update ───────────────────────────────────────────────────────────
printf '  %s>>%s Update nuclei templates? [y/N]: ' "${CYAN}" "${RESET}"
read -r _upd </dev/tty
if [[ "${_upd,,}" == "y" ]]; then
    printf '  %s[*]%s Updating templates...%s\n' "${CYAN}" "${RESET}" "${RESET}"
    nuclei -update-templates 2>&1 | tail -5
    printf '\n'
fi

# ── Live host discovery + port check ─────────────────────────────────────────
# Strategy:
#   nmap available  → one pass: -sT --unprivileged finds live hosts AND open ports
#   nmap absent     → bash parallel ping sweep → /dev/tcp port check fallback

COMMON_PORTS="21,22,23,25,53,80,443,445,554,1883,3389,8080,8443,8554,9100"
MAX_PING_JOBS=50
PING_TIMEOUT=1

if [[ "$target" == */* ]]; then
    # ── CIDR path ─────────────────────────────────────────────────────────────
    if check_tool nmap; then
        printf '  %s[*]%s nmap host+port discovery on %s...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"
        # -sT --unprivileged: TCP connect (works rootless)
        # --open: only report hosts with at least one open port
        nmap -sT --unprivileged -T4 \
             -p "$COMMON_PORTS" \
             --open \
             "$target" 2>/dev/null \
        | awk '/report for/{ip=$NF} /open/{print ip; ip=""}' \
        | sort -u > "$scan_file"
    else
        # Fallback: bash ping sweep
        network="${target%.*/*}"          # 192.168.1  from 192.168.1.0/24

        printf '  %s[*]%s Ping sweep on %s (up to %d parallel)...%s\n' "${CYAN}" "${RESET}" "$target" "$MAX_PING_JOBS" "${RESET}"
        lockfile="${hosts_file}.lock"
        touch "$lockfile"
        trap 'rm -f "$lockfile"' EXIT

        _ping_one() {
            local _ip="$1"
            if ping -c 1 -W "$PING_TIMEOUT" "$_ip" &>/dev/null; then
                { exec 9>"$lockfile"; flock -x 9
                  echo "$_ip" >> "$hosts_file"
                  flock -u 9; exec 9>&-; } 2>/dev/null
            fi
        }

        for i in $(seq 1 254); do
            _ping_one "${network}.${i}" &
            while (( $(jobs -r | wc -l) >= MAX_PING_JOBS )); do sleep 0.05; done
        done
        wait

        sort -t. -k4 -n "$hosts_file" -o "$hosts_file"
        alive=$(wc -l < "$hosts_file")
        printf '  %s[+]%s %d live host(s) found%s\n' "${GREEN}" "${RESET}" "$alive" "${RESET}"
        [[ "$alive" -eq 0 ]] && { printf '  %s[!] No live hosts.%s\n' "${RED}" "${RESET}"; exit 1; }

        # /dev/tcp port check on each alive host
        printf '  %s[*]%s Checking for open ports (/dev/tcp)...%s\n' "${CYAN}" "${RESET}" "${RESET}"
        IFS=',' read -ra _ports <<< "$COMMON_PORTS"
        while IFS= read -r _ip; do
            for _port in "${_ports[@]}"; do
                if timeout 1 bash -c "echo > /dev/tcp/$_ip/$_port" 2>/dev/null; then
                    printf '  %s[+]%s %s — port %s open\n' "${GREEN}" "${RESET}" "$_ip" "$_port"
                    echo "$_ip" >> "$scan_file"
                    break
                fi
            done
        done < "$hosts_file"
    fi

else
    # ── Single IP path ────────────────────────────────────────────────────────
    printf '  %s[*]%s Checking %s for open ports...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"

    if check_tool nmap; then
        open_count=$(nmap -sT --unprivileged -T4 \
                         -p "$COMMON_PORTS" --open \
                         "$target" 2>/dev/null | grep -c "/tcp")
    else
        open_count=0
        IFS=',' read -ra _ports <<< "$COMMON_PORTS"
        for _port in "${_ports[@]}"; do
            if timeout 1 bash -c "echo > /dev/tcp/$target/$_port" 2>/dev/null; then
                (( open_count++ ))
            fi
        done
    fi

    if [[ "$open_count" -eq 0 ]]; then
        printf '  %s[!] No open ports found on %s — skipping.%s\n' "${RED}" "$target" "${RESET}"
        exit 1
    fi
    printf '  %s[+]%s %d open port(s) on %s%s\n' "${GREEN}" "${RESET}" "$open_count" "$target" "${RESET}"
    echo "$target" > "$scan_file"
fi

# ── Validate we have something to scan ───────────────────────────────────────
scan_count=$(wc -l < "$scan_file")
if [[ "$scan_count" -eq 0 ]]; then
    printf '  %s[!] No live hosts with open ports found. Exiting.%s\n' "${RED}" "${RESET}"
    exit 1
fi
echo
printf '  %s[+]%s %d host(s) queued for nuclei%s\n' "${GREEN}" "${RESET}" "$scan_count" "${RESET}"
sed 's/^/      /' "$scan_file"
printf '\n'

# ── Scan mode ─────────────────────────────────────────────────────────────────
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  SCAN MODE                                       │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  Quick     critical+high severity, fast\n'                         "${CYAN}" "${RESET}"
printf '  %s[02]%s ▶  LAN/IoT   default-logins, exposure, misconfiguration %s(recommended)%s\n' "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[03]%s ▶  Full      all templates, reduced rate %s(slow on phone)%s\n'      "${YELLOW}" "${RESET}" "${DIM}" "${RESET}"
printf '  %s[04]%s ▶  Custom    enter flags manually\n'                                 "${DIM}" "${RESET}"
printf '\n'
printf '  %s>>%s ' "${CYAN}" "${RESET}"
read -r _mode </dev/tty
_mode="${_mode:-2}"
echo

RATE=50
BULK=10
TIMEOUT=5
RETRIES=1
EXTRA_FLAGS=""

case "$_mode" in
    1)  label="Quick (critical+high)"
        EXTRA_FLAGS="-severity critical,high"
        ;;
    2)  label="LAN / IoT"
        EXTRA_FLAGS="-tags network,default-logins,exposure,misconfiguration"
        ;;
    3)  label="Full (all templates)"
        RATE=25; BULK=5
        ;;
    4)  printf '  %s>>%s Extra nuclei flags: ' "${CYAN}" "${RESET}"
        read -r EXTRA_FLAGS </dev/tty
        label="Custom"
        ;;
    *)  label="LAN / IoT"
        EXTRA_FLAGS="-tags network,default-logins,exposure,misconfiguration"
        ;;
esac

printf '\n'
printf '  %s[SYS]%s Mode    : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$label" "${RESET}"
printf '  %s[SYS]%s Rate    : %s%d req/s  bulk=%d  timeout=%ds%s\n' "${CYAN}" "${RESET}" "${DIM}" "$RATE" "$BULK" "$TIMEOUT" "${RESET}"
[[ -n "$EXTRA_FLAGS" ]] && printf '  %s[SYS]%s Filters : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$EXTRA_FLAGS" "${RESET}"
printf '\n'

# ── Run nuclei ────────────────────────────────────────────────────────────────
# -ni : disable interactsh callbacks (requires internet; irrelevant for LAN)
# -l  : target list file (one host per line)
# -o  : direct file output — no tee, no ANSI codes saved to file
# shellcheck disable=SC2086
nuclei -l "$scan_file" \
    -rate-limit "$RATE" \
    -bulk-size  "$BULK" \
    -timeout    "$TIMEOUT" \
    -retries    "$RETRIES" \
    -ni \
    -stats \
    $EXTRA_FLAGS \
    -o "$outfile"

printf '\n'
if [[ -s "$outfile" ]]; then
    count=$(wc -l < "$outfile")
    printf '  %s[!] %d finding(s) — saved to: %s%s\n' "${RED}" "$count" "$outfile" "${RESET}"
else
    printf '  %s[+] No findings. Results: %s%s\n' "${GREEN}" "$outfile" "${RESET}"
fi
