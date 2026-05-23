#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "SSL / TLS AUDITOR" "certificate · protocol · vulnerability scanner"

# ── Tool detection ────────────────────────────────────────────────────────────
SCANNER=""
SCANNER_TYPE=""

for _c in testssl.sh testssl /usr/bin/testssl.sh /usr/local/bin/testssl.sh; do
  if command -v "$_c" &>/dev/null || [[ -x "$_c" ]]; then
    SCANNER="$_c"
    SCANNER_TYPE="testssl"
    break
  fi
done

if [[ -z "$SCANNER" ]]; then
  if command -v sslscan &>/dev/null; then
    SCANNER="sslscan"
    SCANNER_TYPE="sslscan"
  else
    printf '  %s[!] No TLS scanner found. Install one:%s\n\n' "${RED}" "${RESET}"
    printf '      apt install testssl.sh   %s(recommended — full CVE checks)%s\n' "${DIM}" "${RESET}"
    printf '      apt install sslscan      %s(already in apt, basic checks)%s\n\n'  "${DIM}" "${RESET}"
    exit 1
  fi
fi

printf '  %s[SYS]%s Scanner : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$SCANNER ($SCANNER_TYPE)" "${RESET}"

# ── Target & output ───────────────────────────────────────────────────────────
target="$(prompt_target)"

# ── Existing nmap.txt? ────────────────────────────────────────────────────────
_nmap_load="$(pick_nmap_file)"

HTTPS_PORTS="443,4443,8443,9443"

declare -a EP_HOST=()
declare -a EP_PORT=()

if [[ -n "$_nmap_load" ]]; then
  outdir="${_nmap_load%%|*}"
  _nmap_txt="${_nmap_load##*|}"
  outfile="$outdir/ssl.txt"
  : > "$outfile"

  section "ENDPOINT DISCOVERY  (from nmap.txt)"
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "$_cur" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
      _p="${BASH_REMATCH[1]}"
      if [[ ",$HTTPS_PORTS," == *",$_p,"* ]]; then
        EP_HOST+=("$_cur"); EP_PORT+=("$_p")
      fi
    fi
  done < "$_nmap_txt"
else
  outdir="$(make_outdir)"
  outfile="$outdir/ssl.txt"
  : > "$outfile"

  section "ENDPOINT DISCOVERY"
  printf '  %s[*]%s Scanning %s for TLS endpoints...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"

  start_spin "nmap scan running"
  mapfile -t _scan < <(
    nmap -sT --unprivileged -Pn -n -T4 \
         -p "$HTTPS_PORTS" --open \
         "$target" 2>/dev/null
  )
  stop_spin

  _cur=""
  for _line in "${_scan[@]}"; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "${_cur}" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
      EP_HOST+=("$_cur")
      EP_PORT+=("${BASH_REMATCH[1]}")
    fi
  done
fi

printf '  %s[SYS]%s Target  : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s[SYS]%s Output  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"

if [[ ${#EP_HOST[@]} -eq 0 ]]; then
  printf '\n  %s[!]%s No TLS ports found on %s.\n' "${YELLOW}" "${RESET}" "$target"
  printf '  %s>>%s Enter endpoint manually (host:port), or Enter to exit: ' "${CYAN}" "${RESET}"
  read -r _manual </dev/tty
  [[ -z "${_manual}" ]] && exit 0
  _mhost="${_manual%%:*}"
  _mport="${_manual##*:}"
  [[ "$_mport" == "$_mhost" ]] && _mport="443"
  EP_HOST+=("$_mhost")
  EP_PORT+=("$_mport")
fi

printf '\n  %s[+]%s %d endpoint(s) found:\n\n' "${GREEN}" "${RESET}" "${#EP_HOST[@]}"
printf '  %s  %-4s  %-16s  %-6s%s\n' "${DIM}" "ID" "HOST" "PORT" "${RESET}"
printf '  %s  ──── ──────────────── ──────%s\n' "${DIM}" "${RESET}"
for i in "${!EP_HOST[@]}"; do
  printf '  %s[%02d]%s  %-16s  %s\n' \
    "${CYAN}" "$(( i + 1 ))" "${RESET}" \
    "${EP_HOST[$i]}" "${EP_PORT[$i]}"
done
printf '\n'

# ── Scan mode (testssl only — sslscan has no modes) ───────────────────────────
SCAN_FLAGS=""
SCAN_LABEL="Standard"

if [[ "$SCANNER_TYPE" == "testssl" ]]; then
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  SCAN MODE                                       │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s[01]%s ▶  Quick   fast  %s(Heartbleed · POODLE · cert · protocols)%s\n' "${CYAN}"   "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[02]%s ▶  Full    complete audit  %s(all ciphers + all CVEs — slow)%s\n' "${CYAN}"  "${RESET}" "${DIM}" "${RESET}"
  printf '  %s[03]%s ▶  Certs   certificate + protocol info only\n'                    "${CYAN}"   "${RESET}"
  printf '\n'
  printf '  %s>>%s ' "${CYAN}" "${RESET}"
  read -r _mode </dev/tty
  echo

  case "${_mode:-1}" in
    2) SCAN_LABEL="Full"  ; SCAN_FLAGS="" ;;
    3) SCAN_LABEL="Certs" ; SCAN_FLAGS="--protocols" ;;
    *) SCAN_LABEL="Quick" ; SCAN_FLAGS="--fast" ;;
  esac

  printf '  %s[SYS]%s Mode    : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$SCAN_LABEL" "${RESET}"
fi

# ── Finding summariser ────────────────────────────────────────────────────────
_summarise() {
  local logfile="$1"
  [[ ! -f "$logfile" ]] && return
  local vulns=0 warnings=0

  while IFS= read -r _l; do
    local _s="${_l#"${_l%%[![:space:]]*}"}"
    [[ -z "$_s" ]] && continue

    if [[ "$_s" == *"VULNERABLE"* || "$_s" == *"NOT ok"* ]]; then
      printf '  %s[!]%s %s\n' "${RED}" "${RESET}" "$_s"
      vulns=$(( vulns + 1 ))
    elif [[ "$_s" == *"expired"*   || "$_s" == *"EXPIRED"*   ||
            "$_s" == *"self signed"* || "$_s" == *"deprecated"* ||
            "$_s" == *" weak"*     || "$_s" == *"WEAK"* ]]; then
      printf '  %s[~]%s %s\n' "${YELLOW}" "${RESET}" "$_s"
      warnings=$(( warnings + 1 ))
    fi
  done < "$logfile"

  printf '\n'
  if [[ $vulns -gt 0 ]]; then
    printf '  %s[!] %d critical finding(s)%s\n' "${RED}" "$vulns" "${RESET}"
  elif [[ $warnings -gt 0 ]]; then
    printf '  %s[~] %d warning(s)%s\n' "${YELLOW}" "$warnings" "${RESET}"
  else
    printf '  %s[+]%s No critical issues detected%s\n' "${GREEN}" "${RESET}" "${RESET}"
  fi
}

# ── Scanner runner — writes terminal output to stdout (captured per-job) ──────
_run_scan() {
  local host="$1" port="$2"
  local ep_log="$outdir/ssl_${host}_${port}.txt"

  printf '\n  %s▶%s  %s:%s\n' "${CYAN}${BOLD}" "${RESET}" "$host" "$port"
  printf '  %s──────────────────────────────────────────────%s\n\n' "${DIM}" "${RESET}"

  if [[ "$SCANNER_TYPE" == "testssl" ]]; then
    # --parallel: probe cipher groups concurrently within a single host scan
    # shellcheck disable=SC2086
    "$SCANNER" $SCAN_FLAGS --parallel --quiet --logfile "$ep_log" "${host}:${port}" 2>/dev/null || true
    printf '\n  %s▶ FINDINGS%s\n' "${CYAN}${BOLD}" "${RESET}"
    _summarise "$ep_log"
  else
    sslscan --no-colour "${host}:${port}" 2>/dev/null | tee "$ep_log" || true
    printf '\n  %s▶ FINDINGS%s\n' "${CYAN}${BOLD}" "${RESET}"
    _summarise "$ep_log"
  fi
}

# ── Execute — parallel host scanning, ordered output ─────────────────────────
section "SCANNING"
_ep_count="${#EP_HOST[@]}"

if [[ $_ep_count -gt 1 ]]; then
  printf '  %s[*]%s %d endpoint(s) — running in parallel (max 3 concurrent)%s\n\n' \
    "${CYAN}" "${RESET}" "$_ep_count" "${RESET}"
else
  printf '  %s[*]%s %d endpoint queued%s\n\n' "${CYAN}" "${RESET}" "$_ep_count" "${RESET}"
fi

_PARALLEL_MAX=3
_tmpout=()
_pids=()

for i in "${!EP_HOST[@]}"; do
  _tmp="$outdir/.ssl_out_${i}.tmp"
  _tmpout+=("$_tmp")
  # Each scan writes its terminal output to a temp file; ep_log is separate
  _run_scan "${EP_HOST[$i]}" "${EP_PORT[$i]}" > "$_tmp" 2>&1 &
  _pids+=($!)
  # Throttle: wait if at the concurrency cap before launching next
  while (( $(jobs -rp | wc -l) >= _PARALLEL_MAX )); do sleep 0.3; done
done

# Wait for each job in submission order and replay its output
for i in "${!_pids[@]}"; do
  wait "${_pids[$i]}" 2>/dev/null || true
  if [[ -f "${_tmpout[$i]}" ]]; then
    cat "${_tmpout[$i]}"
    rm -f "${_tmpout[$i]}"
  fi
done

# Merge per-host logs into summary file in order
for i in "${!EP_HOST[@]}"; do
  _ep_log="$outdir/ssl_${EP_HOST[$i]}_${EP_PORT[$i]}.txt"
  if [[ -f "$_ep_log" ]]; then
    printf '\n=== %s:%s ===\n' "${EP_HOST[$i]}" "${EP_PORT[$i]}" >> "$outfile"
    cat "$_ep_log" >> "$outfile"
  fi
done

# ── Final summary ─────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  AUDIT COMPLETE                                  │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'

total_vulns=0
[[ -s "$outfile" ]] && total_vulns=$(grep -c "VULNERABLE" "$outfile" 2>/dev/null || echo 0)

if [[ $total_vulns -gt 0 ]]; then
  printf '  %s[!] %d VULNERABLE finding(s) across all endpoints — review report%s\n' \
    "${RED}" "$total_vulns" "${RESET}"
else
  printf '  %s[+]%s No critical vulnerabilities found%s\n' "${GREEN}" "${RESET}" "${RESET}"
fi

printf '\n  %s[SYS]%s Report  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
