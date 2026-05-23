#!/usr/bin/env bash
# Shared helpers — source this file, do not execute directly.

# Colors
if tput setaf 1 >/dev/null 2>&1; then
  RED="$(tput setaf 1)$(tput bold)"
  GREEN="$(tput setaf 2)$(tput bold)"
  YELLOW="$(tput setaf 3)$(tput bold)"
  CYAN="$(tput setaf 6)$(tput bold)"
  BOLD="$(tput bold)"
  DIM="$(tput dim 2>/dev/null || printf '\033[2m')"
  RESET="$(tput sgr0)"
else
  RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' RESET=''
fi

# ── Watch Dogs / ctOS visual helpers ─────────────────────────────────────────

# banner <TITLE> [subtitle]  — ctOS style tool header box
banner() {
  local title="$1" sub="${2:-}"
  printf '\n'
  printf '  %s╔══════════════════════════════════════════════╗%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s║  ▶ %s%s\n' "${CYAN}${BOLD}" "${title}" "${RESET}"
  [[ -n "$sub" ]] && printf '  %s║    %s%s%s\n' "${CYAN}" "${DIM}" "${sub}" "${RESET}"
  printf '  %s╚══════════════════════════════════════════════╝%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '\n'
}

# section <title>  — styled section marker
section() {
  printf '\n  %s▶ %s%s\n' "${CYAN}${BOLD}" "$*" "${RESET}"
  printf '  %s──────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
}

# Spinner — wrap slow operations: start_spin <msg> … stop_spin
_spin_pid=""
start_spin() {
  local msg="$1"
  ( local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while true; do
      printf "\r  \033[1;36m%s\033[0m %s" "${frames[$i]}" "$msg"
      sleep 0.12
      i=$(( (i + 1) % 10 ))
    done ) &
  _spin_pid=$!
}
stop_spin() {
  [[ -z "${_spin_pid:-}" ]] && return 0
  kill "$_spin_pid" 2>/dev/null || true
  wait "$_spin_pid" 2>/dev/null || true
  printf '\r\033[K'
  _spin_pid=""
}

# _ip_to_network <ip> <prefix>
# Pure-bash: compute network address from host IP + prefix length.
# e.g. _ip_to_network 192.168.68.92 22  ->  192.168.68.0/22
_ip_to_network() {
  local ip="$1" prefix="$2"
  local -i a b c d
  IFS=. read -r a b c d <<< "$ip"
  local -i full=$(( (a<<24) | (b<<16) | (c<<8) | d ))
  local -i mask=$(( prefix > 0 ? (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF : 0 ))
  local -i net=$(( full & mask ))
  printf "%d.%d.%d.%d/%d\n" \
    $(( (net>>24)&0xFF )) $(( (net>>16)&0xFF )) \
    $(( (net>>8)&0xFF  )) $(( net&0xFF )) \
    "$prefix"
}

# _ip_usable: returns 0 only if 'ip' exists AND can actually query addresses
# (on Android rootless, 'ip' exists but fails with "Cannot bind netlink socket")
_ip_usable() {
  command -v ip &>/dev/null && ip -o -4 addr show 2>/dev/null | grep -q .
}

# list_ifaces
# Prints tab-separated "iface <TAB> network/prefix" for every non-loopback IPv4 interface.
list_ifaces() {
  if _ip_usable; then
    # ip -o -4 addr show gives lines like:
    #   2: wlan0    inet 192.168.68.92/22 brd ...
    ip -o -4 addr show 2>/dev/null | while IFS= read -r line; do
      local iface host_cidr
      iface=$(echo "$line" | awk '{print $2}')
      host_cidr=$(echo "$line" | awk '{print $4}')
      [[ "$iface" == "lo" || -z "$host_cidr" ]] && continue
      local host prefix
      host="${host_cidr%%/*}"
      prefix="${host_cidr##*/}"
      [[ -z "$prefix" || "$prefix" == "$host" ]] && prefix=24
      local net
      net=$(_ip_to_network "$host" "$prefix")
      printf "%s\t%s\n" "$iface" "$net"
    done
  else
    # ifconfig fallback — Android/busybox format
    local cur_iface=""
    ifconfig 2>/dev/null | while IFS= read -r line; do
      # Interface line: "wlan0: flags=..."  or  "wlan0  Link encap:..."
      if echo "$line" | grep -qE '^[a-zA-Z][a-zA-Z0-9_.-]+'; then
        cur_iface=$(echo "$line" | awk -F'[ :]' '{print $1}')
      fi
      # inet line: "  inet 192.168.1.5  netmask 255.255.255.0 ..."
      if echo "$line" | grep -q 'inet ' && [[ "$cur_iface" != "lo" ]]; then
        local host mask
        host=$(echo "$line" | grep -oE 'inet [0-9.]+' | awk '{print $2}')
        mask=$(echo "$line" | grep -oE 'netmask [0-9.]+' | awk '{print $2}')
        if [[ -n "$host" ]]; then
          local prefix=24
          if [[ -n "$mask" ]]; then
            # Convert dotted netmask to prefix length
            local IFS=.
            read -r m1 m2 m3 m4 <<< "$mask"
            local -i bits=0
            for oct in $m1 $m2 $m3 $m4; do
              local x=$oct
              while (( x > 0 )); do
                (( bits += x & 1 ))
                (( x >>= 1 ))
              done
            done
            prefix=$bits
          fi
          local net
          net=$(_ip_to_network "$host" "$prefix")
          printf "%s\t%s\n" "$cur_iface" "$net"
        fi
      fi
    done
  fi
}

# _get_addr <iface>
# Returns the IPv4 address for the given interface using whichever tool works.
# On Android rootless, ifconfig <iface> fails — parse full ifconfig output instead.
_get_addr() {
  local _iface="$1"
  if _ip_usable; then
    ip -o -4 addr show "$_iface" 2>/dev/null \
      | awk '{print $4}' | cut -d/ -f1 | head -1
  else
    ifconfig 2>/dev/null | awk -v iface="$_iface" '
      /^[a-zA-Z]/ { cur = $1; gsub(/:/, "", cur) }
      cur == iface && /inet / {
        for (i=1; i<=NF; i++) if ($i == "inet") { print $(i+1); exit }
      }
    '
  fi
}

# get_ip [interface]
# Returns the IPv4 address (no prefix) for the given interface, or the first
# active non-loopback interface if no argument is given.
get_ip() {
  local iface="${1:-}"
  local addr=""

  if [[ -n "$iface" ]]; then
    addr=$(_get_addr "$iface")
    [[ -n "$addr" ]] && echo "$addr" && return
  fi

  # Try common NetHunter / mobile interfaces in order
  for candidate in wlan0 wlan1 eth0 eth1 usb0 usb1 rndis0 tun0; do
    addr=$(_get_addr "$candidate")
    if [[ -n "$addr" ]]; then
      echo "$addr"
      return
    fi
  done

  # Last resort: any non-loopback interface
  if _ip_usable; then
    addr=$(ip -o -4 addr show 2>/dev/null \
      | awk '$2 != "lo" {print $4}' | cut -d/ -f1 | head -1)
  else
    addr=$(ifconfig 2>/dev/null | awk '
      /^[a-zA-Z]/ { cur = $1; gsub(/:/, "", cur) }
      cur != "lo" && /inet / {
        for (i=1; i<=NF; i++) if ($i == "inet") { print $(i+1); exit }
      }
    ')
  fi
  echo "${addr:-N/A}"
}

# require_tool <tool> [install-hint]
# Exits with an error if the tool is not found in PATH.
require_tool() {
  local tool="$1"
  local hint="${2:-apt install $tool}"
  if ! command -v "$tool" &>/dev/null; then
    echo "${RED}[!] '$tool' not found. Install it with: $hint${RESET}" >&2
    exit 1
  fi
}

# check_tool <tool>
# Returns 0 if found, 1 if not (non-fatal — lets callers decide).
check_tool() {
  command -v "$1" &>/dev/null
}

# make_outdir
# Creates and prints a timestamped results directory under ./results/.
make_outdir() {
  local dir="results/$(date '+%Y-%m-%d_%H-%M-%S')"
  mkdir -p "$dir"
  echo "$dir"
}

# prompt_target
# Prints the chosen target network CIDR or IP.
# Reads TARGET env var if already set, otherwise shows active interfaces.
prompt_target() {
  if [[ -n "${TARGET:-}" ]]; then
    echo "$TARGET"
    return
  fi

  echo "${YELLOW}[?] Target selection:${RESET}" >&2

  # Build list of active interfaces
  local -a iface_arr=()
  local -a net_arr=()
  local idx=1

  while IFS=$'\t' read -r _iface _net; do
    [[ -z "$_iface" || -z "$_net" ]] && continue
    iface_arr+=("$_iface")
    net_arr+=("$_net")
    local _host
    _host=$(get_ip "$_iface")
    echo "    ${idx}) ${_iface} — ${_host} → ${_net}" >&2
    (( idx++ ))
  done < <(list_ifaces 2>/dev/null)

  echo "    ${idx}) Enter manually" >&2
  read -rp "    Choice [1]: " _choice </dev/tty
  _choice="${_choice:-1}"

  if [[ "$_choice" == "$idx" ]] || [[ "$_choice" == "m" ]]; then
    read -rp "    Enter IP or CIDR (e.g. 192.168.1.0/24 or 10.0.0.5): " _manual </dev/tty
    echo "$_manual"
  elif [[ "$_choice" =~ ^[0-9]+$ ]] && (( _choice >= 1 && _choice < idx )); then
    echo "${net_arr[$((_choice - 1))]}"
  else
    # Fallback: first detected network, or manual
    if [[ ${#net_arr[@]} -gt 0 ]]; then
      echo "${net_arr[0]}"
    else
      read -rp "    No interfaces detected. Enter target manually: " _manual </dev/tty
      echo "$_manual"
    fi
  fi
}
