#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

set -uo pipefail

banner "DNS / ACTIVE DIRECTORY" "zone transfer · SRV discovery · domain enumeration"

require_tool dig  "apt install dnsutils"
require_tool nmap "apt install nmap"

# ── Inputs ────────────────────────────────────────────────────────────────────
target="$(prompt_target)"
outdir="$(make_outdir)"
outfile="$outdir/dns_ad.txt"
: > "$outfile"

# Auto-detect domain from resolv.conf, let user confirm or override
_auto_domain="$(grep -E "^(domain|search)" /etc/resolv.conf 2>/dev/null \
  | head -1 | awk '{print $2}' || true)"

printf '  %s[SYS]%s Network : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$target" "${RESET}"
printf '  %s>>%s Domain (e.g. corp.local)' "${CYAN}" "${RESET}"
[[ -n "${_auto_domain}" ]] && printf ' %s[detected: %s]%s' "${DIM}" "$_auto_domain" "${RESET}"
printf ': '
read -r DOMAIN </dev/tty
[[ -z "$DOMAIN" ]] && DOMAIN="${_auto_domain}"
printf '  %s[SYS]%s Domain  : %s%s%s\n\n' \
  "${CYAN}" "${RESET}" "${GREEN}" "${DOMAIN:-<not set>}" "${RESET}"

# ── Infrastructure scan ───────────────────────────────────────────────────────
section "INFRASTRUCTURE SCAN"
printf '  %s[*]%s Scanning %s for DNS / DC services...%s\n' "${CYAN}" "${RESET}" "$target" "${RESET}"

start_spin "nmap running"
mapfile -t _scan < <(
  nmap -sT --unprivileged -Pn -n -T4 \
       -p "53,88,389,445,636,3268,3269" --open \
       "$target" 2>/dev/null
)
stop_spin

declare -a DNS_SERVERS=()
declare -a DC_HOSTS=()
declare -A DC_PORTS=()

_cur=""
for _line in "${_scan[@]}"; do
  if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    _cur="${BASH_REMATCH[1]}"
  elif [[ -n "${_cur}" && "$_line" =~ ^([0-9]+)/tcp.*open ]]; then
    _p="${BASH_REMATCH[1]}"
    if [[ "$_p" == "53" ]]; then
      _seen=0
      for _h in "${DNS_SERVERS[@]}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
      [[ $_seen -eq 0 ]] && DNS_SERVERS+=("$_cur")
    else
      _seen=0
      for _h in "${DC_HOSTS[@]}"; do [[ "$_h" == "$_cur" ]] && _seen=1; done
      [[ $_seen -eq 0 ]] && DC_HOSTS+=("$_cur")
      DC_PORTS["$_cur"]+="${_p} "
    fi
  fi
done

printf '\n'
if [[ ${#DNS_SERVERS[@]} -gt 0 ]]; then
  printf '  %s[+]%s DNS server(s) : %s%s%s\n' \
    "${GREEN}" "${RESET}" "${CYAN}" "${DNS_SERVERS[*]}" "${RESET}"
else
  printf '  %s[~]%s No DNS servers found on target range%s\n' "${DIM}" "${RESET}" "${RESET}"
fi

if [[ ${#DC_HOSTS[@]} -gt 0 ]]; then
  printf '  %s[+]%s DC candidate(s):\n' "${GREEN}" "${RESET}"
  for _h in "${DC_HOSTS[@]}"; do
    printf '      %s%s%s  %s[ports: %s]%s\n' \
      "${CYAN}" "$_h" "${RESET}" "${DIM}" "${DC_PORTS[$_h]:-}" "${RESET}"
  done
else
  printf '  %s[~]%s No Domain Controller ports (88/389/636/3268) found%s\n' \
    "${DIM}" "${RESET}" "${RESET}"
fi

{ printf '=== DISCOVERY ===\nDNS: %s\nDCs: %s\n\n' \
    "${DNS_SERVERS[*]:-none}" "${DC_HOSTS[*]:-none}"; } >> "$outfile"

# ── Mode selection ────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RECON MODE                                      │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[01]%s ▶  DNS        zone transfer · SRV records · PTR sweep\n' "${CYAN}" "${RESET}"
printf '  %s[02]%s ▶  AD / LDAP  domain enum · users · shares\n'             "${CYAN}" "${RESET}"
printf '  %s[03]%s ▶  Full       both in sequence\n'                          "${GREEN}" "${RESET}"
printf '\n'
printf '  %s>>%s ' "${CYAN}" "${RESET}"
read -r _mode </dev/tty
echo

RUN_DNS=0 RUN_AD=0
case "${_mode:-3}" in
  1) RUN_DNS=1 ;;
  2) RUN_AD=1 ;;
  *) RUN_DNS=1; RUN_AD=1 ;;
esac

# ── DNS recon ─────────────────────────────────────────────────────────────────
if [[ $RUN_DNS -eq 1 ]]; then
  section "DNS RECON"
  _ns="${DNS_SERVERS[0]:-}"

  _dig() {
    local -a _cmd=(dig +short +time=3 +tries=1)
    [[ -n "$_ns" ]] && _cmd+=("@${_ns}")
    "${_cmd[@]}" "$@" 2>/dev/null || true
  }

  # Zone transfer
  if [[ -n "${DOMAIN}" && ${#DNS_SERVERS[@]} -gt 0 ]]; then
    printf '  %s[*]%s Zone transfer — %s\n' "${CYAN}" "${RESET}" "$DOMAIN"
    printf '=== ZONE TRANSFERS ===\n' >> "$outfile"
    for _ns_t in "${DNS_SERVERS[@]}"; do
      printf '      @%s → ' "$_ns_t"
      _axfr=$(dig AXFR "$DOMAIN" @"$_ns_t" +time=8 2>/dev/null || true)
      if echo "$_axfr" | grep -qE "Transfer failed|REFUSED|SERVFAIL|timed out|reset" \
         || [[ -z "$_axfr" ]]; then
        printf '%s[✘] blocked%s\n' "${DIM}" "${RESET}"
        printf 'AXFR @%s: blocked\n' "$_ns_t" >> "$outfile"
      else
        printf '%s[✔] SUCCESS — full zone received!%s\n' "${GREEN}" "${RESET}"
        printf '%s\n' "$_axfr" | tee -a "$outfile"
      fi
    done
    printf '\n'
  fi

  # SRV records — AD service pointers
  if [[ -n "${DOMAIN}" ]]; then
    printf '  %s[*]%s SRV records  %s(AD service discovery)%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "${RESET}"
    printf '=== SRV ===\n' >> "$outfile"
    for _srv in \
      "_ldap._tcp"               \
      "_kerberos._tcp"           \
      "_gc._tcp"                 \
      "_kpasswd._tcp"            \
      "_ldap._tcp.dc._msdcs"     \
      "_kerberos._tcp.dc._msdcs"; do
      _r=$(_dig SRV "${_srv}.${DOMAIN}")
      if [[ -n "$_r" ]]; then
        printf '  %s[+]%s %-38s %s%s%s\n' \
          "${GREEN}" "${RESET}" "${_srv}" "${CYAN}" "$_r" "${RESET}"
        printf '%s.%s  %s\n' "$_srv" "$DOMAIN" "$_r" >> "$outfile"
      else
        printf '  %s[~]%s %-38s no record%s\n' "${DIM}" "${RESET}" "${_srv}" "${RESET}"
      fi
    done
    printf '\n'
  fi

  # NS / SOA / MX
  if [[ -n "${DOMAIN}" ]]; then
    printf '  %s[*]%s NS / SOA / MX\n' "${CYAN}" "${RESET}"
    printf '=== NS/SOA/MX ===\n' >> "$outfile"
    for _type in NS SOA MX; do
      _r=$(_dig "$_type" "$DOMAIN")
      if [[ -n "$_r" ]]; then
        printf '  %s[+]%s %-5s %s%s%s\n' "${GREEN}" "${RESET}" "$_type" "${DIM}" "$_r" "${RESET}"
        printf '%s: %s\n' "$_type" "$_r" >> "$outfile"
      fi
    done
    printf '\n'
  fi

  # Reverse PTR sweep — parallel
  if [[ "$target" == */* ]]; then
    IFS='.' read -r _a _b _c _ <<< "${target%%/*}"
    _pfx="${_a}.${_b}.${_c}"
    printf '  %s[*]%s PTR reverse sweep — %s.1-254  %s(parallel)%s\n' \
      "${CYAN}" "${RESET}" "$_pfx" "${DIM}" "${RESET}"
    printf '=== PTR SWEEP ===\n' >> "$outfile"
    _ptrtmp="$outdir/.ptr_tmp"
    : > "$_ptrtmp"
    for i in $(seq 1 254); do
      {
        _r=$(dig +short +time=1 +tries=1 -x "${_pfx}.${i}" \
             ${_ns:+@"$_ns"} 2>/dev/null || true)
        if [[ -n "$_r" ]]; then
          printf '  %s[+]%s %-16s → %s\n' "${GREEN}" "${RESET}" "${_pfx}.${i}" "$_r"
          printf '%s.%d  →  %s\n' "$_pfx" "$i" "$_r" >> "$_ptrtmp"
        fi
      } &
      while (( $(jobs -rp | wc -l) >= 30 )); do sleep 0.05; done
    done
    wait
    cat "$_ptrtmp" >> "$outfile" 2>/dev/null || true
    rm -f "$_ptrtmp"
    printf '\n'
  fi

  # dnsrecon
  if check_tool dnsrecon && [[ -n "${DOMAIN}" ]]; then
    printf '  %s[*]%s dnsrecon std + axfr enumeration\n' "${CYAN}" "${RESET}"
    printf '=== DNSRECON ===\n' >> "$outfile"
    dnsrecon -d "$DOMAIN" -t std,axfr ${_ns:+-n "$_ns"} 2>/dev/null \
      | tee -a "$outfile" || true
    printf '\n'
  fi
fi

# ── AD / LDAP enumeration ─────────────────────────────────────────────────────
if [[ $RUN_AD -eq 1 ]]; then
  if [[ ${#DC_HOSTS[@]} -eq 0 ]]; then
    printf '\n  %s[!]%s No DCs found — enter one manually (or Enter to skip):\n' \
      "${YELLOW}" "${RESET}"
    printf '  %s>>%s DC IP: ' "${CYAN}" "${RESET}"
    read -r _manual_dc </dev/tty
    [[ -n "${_manual_dc}" ]] && DC_HOSTS+=("$_manual_dc")
  fi

  for _dc in "${DC_HOSTS[@]}"; do
    section "AD ENUM — $_dc"
    printf '=== AD: %s ===\n' "$_dc" >> "$outfile"

    # Anonymous LDAP bind + user dump
    if check_tool ldapsearch; then
      printf '  %s[*]%s Anonymous LDAP bind...%s\n' "${CYAN}" "${RESET}" "${RESET}"
      _ldap=$(ldapsearch -x -H "ldap://${_dc}" -b "" -s base namingContexts 2>/dev/null || true)
      if [[ -n "$_ldap" ]]; then
        printf '  %s[✔] Anon LDAP succeeded!%s\n' "${GREEN}" "${RESET}"
        printf '%s\n' "$_ldap" >> "$outfile"
        _base=$(echo "$_ldap" | grep -i "DC=" | awk '{print $2}' | head -1)
        if [[ -n "$_base" ]]; then
          printf '  %s[*]%s Dumping accounts from %s...%s\n' \
            "${CYAN}" "${RESET}" "$_base" "${RESET}"
          ldapsearch -x -H "ldap://${_dc}" -b "$_base" \
            "(objectClass=user)" sAMAccountName 2>/dev/null \
            | grep "^sAMAccountName:" | tee -a "$outfile" | head -40 || true
        fi
      else
        printf '  %s[~]%s Anonymous LDAP rejected%s\n' "${DIM}" "${RESET}" "${RESET}"
      fi
    fi

    # enum4linux-ng (preferred) or enum4linux fallback
    if check_tool enum4linux-ng; then
      printf '\n  %s[*]%s enum4linux-ng -A %s\n' "${CYAN}" "${RESET}" "$_dc"
      enum4linux-ng -A "$_dc" 2>/dev/null | tee -a "$outfile" || true
    elif check_tool enum4linux; then
      printf '\n  %s[*]%s enum4linux -a %s\n' "${CYAN}" "${RESET}" "$_dc"
      enum4linux -a "$_dc" 2>/dev/null | tee -a "$outfile" || true
    fi

    # Password policy via crackmapexec
    if check_tool crackmapexec; then
      printf '\n  %s[*]%s Password policy (crackmapexec)...%s\n' "${CYAN}" "${RESET}" "${RESET}"
      crackmapexec smb "$_dc" -u '' -p '' --pass-pol 2>/dev/null \
        | tee -a "$outfile" || true
    fi
  done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n'
printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
printf '  %s│  RESULTS                                         │%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
printf '\n'
printf '  %s[SYS]%s DNS servers : %s%d%s\n' "${CYAN}" "${RESET}" "${DIM}" "${#DNS_SERVERS[@]}" "${RESET}"
printf '  %s[SYS]%s DCs found   : %s%d%s\n' "${CYAN}" "${RESET}" "${DIM}" "${#DC_HOSTS[@]}"    "${RESET}"

_axfr_ok=$(grep -c "\[✔\].*zone" "$outfile" 2>/dev/null || echo 0)
[[ "$_axfr_ok" -gt 0 ]] && \
  printf '  %s[✔] Zone transfer succeeded — full DNS zone captured!%s\n' "${GREEN}" "${RESET}"

_ldap_ok=$(grep -c "Anon LDAP succeeded" "$outfile" 2>/dev/null || echo 0)
[[ "$_ldap_ok" -gt 0 ]] && \
  printf '  %s[✔] Anonymous LDAP — accounts enumerated!%s\n' "${GREEN}" "${RESET}"

printf '\n  %s[SYS]%s Report  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$outfile" "${RESET}"
