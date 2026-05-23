#!/usr/bin/env bash
set -uo pipefail

# ── Colours — $'...' so escape codes are real bytes, not literal backslashes ──
RED=$'\033[1;31m';  GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[1;36m'; BOLD=$'\033[1m';     DIM=$'\033[2m';    RESET=$'\033[0m'

# ── Banner — first thing printed, before anything can fail ────────────────────
printf '\n'
printf '  %s╔════════════════════════════════════════════════════╗%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s║   ▓▒░  F - S E C U R I T Y  ░▒▓                 ║%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s║   DEPENDENCY INSTALLER                            ║%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s║   · · · · · · · · · · · · · · · · · · · · · ·   ║%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s║   Safe to re-run — installed tools are skipped   ║%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s╚════════════════════════════════════════════════════╝%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '\n'

# ── Counters ──────────────────────────────────────────────────────────────────
_ok=0; _skip=0; _fail=0; _warn=0
FAILED_ITEMS=()

# ── Output helpers ────────────────────────────────────────────────────────────
ok()   { printf "  ${GREEN}[✔]${RESET} %s\n" "$*"; _ok=$(( _ok + 1 )); }
skip() { printf "  ${YELLOW}[~]${RESET} %s\n" "$*"; _skip=$(( _skip + 1 )); }
fail() { printf "  ${RED}[✘]${RESET} %s\n"   "$*"; _fail=$(( _fail + 1 )); FAILED_ITEMS+=("$*"); }
warn() { printf "  ${YELLOW}[!]${RESET} %s\n" "$*"; _warn=$(( _warn + 1 )); }
info() { printf "  ${CYAN}[*]${RESET} %s\n"   "$*"; }
has()  { command -v "$1" &>/dev/null; }

# ── Spinner ───────────────────────────────────────────────────────────────────
_spin_pid=""
start_spin() {
    local msg="$1"
    ( frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
      i=0
      while true; do
          printf "\r  ${CYAN}%s${RESET} %s" "${frames[$i]}" "$msg"
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

# ── Signal handling ───────────────────────────────────────────────────────────
_on_interrupt() {
    stop_spin 2>/dev/null || true
    printf '\n\n  %s[!] Interrupted — setup did not complete.%s\n\n' "${RED}" "${RESET}"
    exit 130
}
trap '_on_interrupt' INT TERM
trap 'stop_spin 2>/dev/null || true' EXIT

# ── Section header ────────────────────────────────────────────────────────────
section() {
    printf '\n  %s▶  %s%s\n' "${CYAN}${BOLD}" "$*" "${RESET}"
    printf '  %s────────────────────────────────────────────────%s\n' "${DIM}" "${RESET}"
}

# Install one or more apt packages, skipping already-installed ones.
apt_install() {
    local pkgs=()
    for pkg in "$@"; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            skip "$pkg (already installed)"
        else
            pkgs+=("$pkg")
        fi
    done
    [[ ${#pkgs[@]} -eq 0 ]] && return 0
    info "apt install ${pkgs[*]} ..."
    if apt-get install -y "${pkgs[@]}" &>/dev/null 2>&1; then
        for pkg in "${pkgs[@]}"; do ok "$pkg"; done
    else
        # Try one by one so one bad package doesn't block the rest
        for pkg in "${pkgs[@]}"; do
            if apt-get install -y "$pkg" &>/dev/null 2>&1; then
                ok "$pkg"
            else
                fail "$pkg (apt install failed)"
            fi
        done
    fi
}

# Install a pip package, skipping if already importable/installed.
pip_install() {
    local pkg="$1"           # pip package name   e.g. python-nmap
    local import="${2:-}"    # python import name  e.g. nmap   (optional)
    local extra="${3:-}"     # extra pip args      e.g. --break-system-packages

    # Check if already installed via pip show first, then try import
    if pip show "$pkg" &>/dev/null 2>&1; then
        skip "$pkg (pip — already installed)"
        return 0
    fi
    if [[ -n "$import" ]] && python3 -c "import $import" &>/dev/null 2>&1; then
        skip "$pkg (importable as '$import')"
        return 0
    fi

    info "pip install $pkg ..."
    local pip_args=("install" "--quiet" "$pkg")
    [[ -n "$extra" ]] && pip_args+=($extra)

    if pip "${pip_args[@]}" &>/dev/null 2>&1; then
        ok "$pkg"
    else
        # Retry with --break-system-packages for PEP-668 environments (Kali 2024+)
        if pip install --quiet --break-system-packages "$pkg" &>/dev/null 2>&1; then
            ok "$pkg (--break-system-packages)"
        else
            fail "$pkg (pip install failed)"
        fi
    fi
}

# ── Detect package manager ────────────────────────────────────────────────────
detect_env() {
    if has apt-get; then
        PKG_MGR="apt"
    elif has pkg; then
        PKG_MGR="pkg"
    else
        printf '  %s[!] No supported package manager found (apt / pkg).%s\n' "${RED}" "${RESET}"
        exit 1
    fi

    OS_PRETTY=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "Unknown")
    ARCH=$(uname -m)

    printf '  %s[SYS]%s OS   : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "${OS_PRETTY}" "${RESET}"
    printf '  %s[SYS]%s Arch : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "${ARCH}"      "${RESET}"
    printf '  %s[SYS]%s Pkg  : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "${PKG_MGR}"   "${RESET}"
    printf '  %s[SYS]%s User : %s%s%s\n' "${CYAN}" "${RESET}" "${DIM}" "$(whoami)"    "${RESET}"
    printf '\n'
}

# ── Main ──────────────────────────────────────────────────────────────────────

detect_env

# ── 1. System package update ──────────────────────────────────────────────────
section "Updating package lists"
if [[ "$PKG_MGR" == "apt" ]]; then
    start_spin "Synchronising package index..."
    if apt-get update -qq &>/dev/null 2>&1; then
        stop_spin; ok "Package lists refreshed"
    else
        stop_spin; warn "apt-get update had errors (continuing anyway)"
    fi
fi

# ── 2. Core system tools ──────────────────────────────────────────────────────
section "Core tools (nmap, python3, curl, git)"

if [[ "$PKG_MGR" == "apt" ]]; then
    apt_install nmap python3 python3-pip curl wget git
else
    for tool in nmap python python-pip curl wget git; do
        if has "$tool"; then skip "$tool (already installed)"
        else
            pkg install -y "$tool" &>/dev/null 2>&1 && ok "$tool" || fail "$tool"
        fi
    done
fi

# ── 3. Nuclei ─────────────────────────────────────────────────────────────────
section "Nuclei — fast vulnerability scanner"

if has nuclei; then
    _ver=$(nuclei -version 2>&1 | grep -oP 'v[\d.]+' | head -1)
    skip "nuclei ${_ver} (already installed)"
else
    if [[ "$PKG_MGR" == "apt" ]]; then
        apt_install nuclei
    else
        warn "nuclei not in pkg — install manually: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    fi
fi

# Update templates (non-fatal)
if has nuclei; then
    start_spin "Fetching latest nuclei templates..."
    _nupd=$(nuclei -update-templates 2>&1)
    stop_spin
    if echo "$_nupd" | grep -qiE "Successfully updated|No new updates|already up|GoodLuck"; then
        ok "nuclei templates up to date"
    else
        warn "nuclei template update may have failed — run: nuclei -update-templates"
    fi
fi

# ── 4. Crackmapexec / NetExec ─────────────────────────────────────────────────
section "CrackMapExec (SMB/RDP/WinRM enumeration)"

if has crackmapexec || has cme || has netexec || has nxc; then
    skip "crackmapexec / netexec (already installed)"
else
    # Kali 2024+ ships netexec (the maintained fork of cme)
    if [[ "$PKG_MGR" == "apt" ]]; then
        if apt-get install -y crackmapexec &>/dev/null 2>&1; then
            ok "crackmapexec"
        elif apt-get install -y netexec &>/dev/null 2>&1; then
            ok "netexec (crackmapexec fork)"
        else
            # Fallback: pip
            pip_install crackmapexec "" "--break-system-packages"
        fi
    else
        pip_install crackmapexec
    fi
fi

# ── 5. Web recon tools ────────────────────────────────────────────────────────
section "Web recon — whatweb, nikto, gobuster, feroxbuster"

if [[ "$PKG_MGR" == "apt" ]]; then
    apt_install whatweb nikto gobuster feroxbuster
else
    for tool in whatweb nikto gobuster feroxbuster; do
        has "$tool" && skip "$tool (already installed)" || warn "$tool — install manually via pkg or GitHub"
    done
fi

# ── 6. SNMP tools ─────────────────────────────────────────────────────────────
section "SNMP tools (snmpwalk, snmp-check)"

if [[ "$PKG_MGR" == "apt" ]]; then
    apt_install snmp snmp-mibs-downloader
    # snmp-check is a Perl script — check for it separately
    if has snmp-check || has snmpcheck; then
        skip "snmp-check (already installed)"
    else
        if apt-get install -y snmpcheck &>/dev/null 2>&1; then
            ok "snmpcheck"
        else
            warn "snmpcheck not found in apt — install from: https://www.nothink.org/codes/snmpcheck/snmpcheck-1.9.rb"
        fi
    fi
    # Perl dep required by snmp-check
    apt_install libterm-readkey-perl
else
    warn "SNMP tools — install manually: pkg install net-snmp"
fi

# ── 7. Metasploit ─────────────────────────────────────────────────────────────
section "Metasploit Framework (msfconsole)"

if has msfconsole; then
    skip "metasploit-framework (already installed)"
else
    if [[ "$PKG_MGR" == "apt" ]]; then
        start_spin "Installing metasploit-framework (may take several minutes)..."
        if apt-get install -y metasploit-framework &>/dev/null 2>&1; then
            stop_spin; ok "metasploit-framework"
        else
            stop_spin; warn "metasploit-framework failed — try: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"
        fi
    else
        warn "Metasploit — not available via pkg on Termux"
    fi
fi

# ── 8. mpv (RTSP stream viewer) ───────────────────────────────────────────────
section "mpv (RTSP live stream viewer)"

if has mpv; then
    skip "mpv (already installed)"
else
    if [[ "$PKG_MGR" == "apt" ]]; then
        apt_install mpv
    else
        pkg install -y mpv &>/dev/null 2>&1 && ok "mpv" || warn "mpv not found in pkg — install manually"
    fi
fi

# ── 9. AutoRecon ──────────────────────────────────────────────────────────────
section "AutoRecon (automated multi-tool recon)"

if has autorecon; then
    skip "autorecon (already installed)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install autorecon
else
    warn "autorecon not in pkg — install manually: pip install git+https://github.com/Tib3rius/AutoRecon.git"
fi

# ── 10. Hydra (credential brute-force — module 10) ───────────────────────────
section "Hydra — credential brute-force (brute.sh)"

if has hydra; then
    _ver=$(hydra -V 2>&1 | grep -oP 'v[\d.]+' | head -1 || echo "")
    skip "hydra ${_ver} (already installed)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install hydra
else
    warn "hydra — install manually: pkg install hydra"
fi

# ── 11. TLS/SSL scanners (ssl.sh) ─────────────────────────────────────────────
section "TLS/SSL scanners — testssl.sh + sslscan (ssl.sh)"

if has testssl.sh || has testssl; then
    skip "testssl.sh (already installed)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install testssl.sh
else
    warn "testssl.sh not in pkg — download: https://testssl.sh"
fi

if has sslscan; then
    skip "sslscan (already installed)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install sslscan
else
    warn "sslscan — install manually: pkg install sslscan"
fi

# ── 12. DNS / Active Directory tools (dns_ad.sh) ─────────────────────────────
section "DNS + AD tools — dig, dnsrecon, ldapsearch, enum4linux-ng (dns_ad.sh)"

if [[ "$PKG_MGR" == "apt" ]]; then
    apt_install dnsutils dnsrecon ldap-utils
else
    for tool in dig dnsrecon ldapsearch; do
        has "$tool" && skip "$tool (already installed)" \
            || warn "$tool — install manually"
    done
fi

if has enum4linux-ng; then
    skip "enum4linux-ng (already installed)"
elif has enum4linux; then
    skip "enum4linux (already installed, enum4linux-ng preferred)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    if apt-get install -y enum4linux-ng &>/dev/null 2>&1; then
        ok "enum4linux-ng"
    elif apt-get install -y enum4linux &>/dev/null 2>&1; then
        ok "enum4linux (fallback — enum4linux-ng not in apt)"
    else
        warn "enum4linux-ng/enum4linux not found in apt — install manually"
    fi
else
    warn "enum4linux-ng — install manually"
fi

# ── 13. MQTT client (post.sh MQTT actions) ────────────────────────────────────
section "MQTT client — mosquitto_sub (post.sh)"

if has mosquitto_sub; then
    skip "mosquitto-clients (already installed)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install mosquitto-clients
else
    pkg install -y mosquitto &>/dev/null 2>&1 && ok "mosquitto-clients" \
        || warn "mosquitto-clients — install manually: pkg install mosquitto"
fi

# ── 14. Ingram — webcam auto-exploit (module 04) ─────────────────────────────
section "Ingram — webcam snapshot + credential exploit (auto_ingramv2.sh)"

# Ingram is a GitHub project, not a pip package.
# We clone it into Ingram/tool/ and run via: python3 run_ingram.py -i <targets> -o <outdir>
INGRAM_TOOL_DIR="$SCRIPT_DIR/Ingram/tool"
INGRAM_SCRIPT="$INGRAM_TOOL_DIR/run_ingram.py"

if [[ -f "$INGRAM_SCRIPT" ]]; then
    skip "Ingram already cloned at $INGRAM_TOOL_DIR"
else
    if has git; then
        start_spin "Cloning Ingram from GitHub..."
        if git clone --quiet --depth 1 https://github.com/jorhelp/Ingram "$INGRAM_TOOL_DIR" 2>/dev/null; then
            stop_spin; ok "Ingram cloned → $INGRAM_TOOL_DIR"
        else
            stop_spin; warn "Ingram clone failed — check internet connection"
            INGRAM_TOOL_DIR=""
        fi
    else
        warn "git not found — cannot clone Ingram"
        INGRAM_TOOL_DIR=""
    fi
fi

# Install Ingram's Python requirements
if [[ -n "${INGRAM_TOOL_DIR:-}" && -f "$INGRAM_TOOL_DIR/requirements.txt" ]]; then
    start_spin "Installing Ingram Python requirements..."
    if pip install --quiet --break-system-packages -r "$INGRAM_TOOL_DIR/requirements.txt" &>/dev/null 2>&1 \
       || pip install --quiet -r "$INGRAM_TOOL_DIR/requirements.txt" &>/dev/null 2>&1; then
        stop_spin; ok "Ingram requirements installed"
    else
        stop_spin; warn "Some Ingram requirements failed — run: pip install -r $INGRAM_TOOL_DIR/requirements.txt"
    fi
fi

# ── 15. socat + netcat (c2.sh listener) ──────────────────────────────────────
section "socat + netcat — reverse shell listener (c2.sh)"

if has socat; then
    skip "socat (already installed)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install socat
else
    pkg install -y socat &>/dev/null 2>&1 && ok "socat" \
        || warn "socat — install manually: pkg install socat"
fi

# netcat-traditional (has -e flag) preferred; nc is acceptable fallback
if has nc; then
    _nc_path=$(command -v nc)
    # Check if this nc supports -e (traditional/openbsd differ)
    if nc --help 2>&1 | grep -q "\-e"; then
        skip "netcat (already installed, has -e)"
    else
        skip "netcat (already installed — no -e flag; mkfifo payload still works)"
    fi
elif [[ "$PKG_MGR" == "apt" ]]; then
    if apt-get install -y netcat-traditional &>/dev/null 2>&1; then
        ok "netcat-traditional (supports -e)"
    elif apt-get install -y netcat &>/dev/null 2>&1; then
        ok "netcat"
    else
        warn "netcat not found — apt install netcat-traditional"
    fi
else
    pkg install -y netcat &>/dev/null 2>&1 && ok "netcat" \
        || warn "netcat — install manually: pkg install netcat"
fi

# ── 16. ExploitDB / searchsploit (exploit.sh) ────────────────────────────────
section "ExploitDB — searchsploit (exploit.sh)"

if has searchsploit; then
    skip "exploitdb / searchsploit (already installed)"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install exploitdb
else
    warn "exploitdb not in pkg — install manually or clone: https://github.com/offensive-security/exploitdb"
fi

# ── 17. Python dependencies (requirements.txt) ────────────────────────────────
section "Python dependencies (requirements.txt)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ="$SCRIPT_DIR/requirements.txt"

if [[ -f "$REQ" ]]; then
    info "Installing from $REQ ..."
    if pip install --quiet -r "$REQ" &>/dev/null 2>&1 \
       || pip install --quiet --break-system-packages -r "$REQ" &>/dev/null 2>&1; then
        ok "requirements.txt packages installed"
    else
        warn "Some requirements may have failed — run: pip install -r requirements.txt"
    fi
else
    warn "requirements.txt not found — skipping"
fi

# Install individually to report per-package status
pip_install python-nmap   nmap
pip_install scapy         scapy
pip_install netifaces     netifaces

# ── 18. fscan binary ──────────────────────────────────────────────────────────
section "fscan (fast internal network scanner binary)"

FSCAN="$SCRIPT_DIR/fscan"
if [[ -x "$FSCAN" ]]; then
    skip "fscan binary already present at $FSCAN"
else
    # Resolve arch: aarch64 → arm64, x86_64 → x64, armv7l → armv7
    case "$(uname -m)" in
        aarch64)        _farch="arm64" ;;
        x86_64)         _farch="x64"   ;;
        armv7l|armv7)   _farch="armv7" ;;
        armv6l)         _farch="armv6" ;;
        armv5*)         _farch="armv5" ;;
        i*86)           _farch="x32"   ;;
        *)              _farch=""      ;;
    esac

    if [[ -z "$_farch" ]]; then
        warn "fscan — unsupported arch $(uname -m), download manually: https://github.com/shadow1ng/fscan/releases"
    else
        # Get latest release tag via GitHub redirect (no API token needed)
        _ftag=$(curl -sI "https://github.com/shadow1ng/fscan/releases/latest" \
                | grep -i '^location:' | grep -oP 'v[\d.]+' | head -1)
        _fver="${_ftag#v}"   # strip leading 'v' for filename

        if [[ -z "$_fver" ]]; then
            warn "fscan — could not resolve latest version (no internet?). Download manually: https://github.com/shadow1ng/fscan/releases"
        else
            _furl="https://github.com/shadow1ng/fscan/releases/download/${_ftag}/fscan_${_fver}_linux_${_farch}"
            start_spin "Downloading fscan ${_ftag} (linux/${_farch})..."
            if curl -sL --connect-timeout 15 --retry 2 -o "$FSCAN" "$_furl" \
               && [[ -s "$FSCAN" ]]; then
                stop_spin
                chmod +x "$FSCAN"
                ok "fscan ${_ftag} → $FSCAN"
            else
                stop_spin
                rm -f "$FSCAN"
                fail "fscan download failed — get it manually: $_furl"
            fi
        fi
    fi
fi

# ── 19. Wordlists ─────────────────────────────────────────────────────────────
section "Wordlists (for gobuster / feroxbuster)"

if [[ -f /usr/share/wordlists/dirb/common.txt ]]; then
    skip "dirb wordlists already present"
elif [[ "$PKG_MGR" == "apt" ]]; then
    apt_install wordlists dirb
    # Decompress rockyou if needed
    if [[ -f /usr/share/wordlists/rockyou.txt.gz && ! -f /usr/share/wordlists/rockyou.txt ]]; then
        info "Decompressing rockyou.txt ..."
        gunzip /usr/share/wordlists/rockyou.txt.gz && ok "rockyou.txt ready" || warn "gunzip rockyou failed"
    fi
else
    warn "Wordlists — install manually or place in /usr/share/wordlists/"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n'
printf '  %s╔════════════════════════════════════════════════════╗%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s║   INFILTRATION STATUS REPORT                      ║%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '  %s╚════════════════════════════════════════════════════╝%s\n' "${CYAN}${BOLD}" "${RESET}"
printf '\n'
printf '  %s[✔] DEPLOYED%s    : %s%d%s\n'  "${GREEN}"  "${RESET}" "${BOLD}" "${_ok}"   "${RESET}"
printf '  %s[~] CACHED%s      : %s%d%s\n'  "${YELLOW}" "${RESET}" "${BOLD}" "${_skip}" "${RESET}"
printf '  %s[!] WARNINGS%s    : %s%d%s\n'  "${YELLOW}" "${RESET}" "${BOLD}" "${_warn}" "${RESET}"
printf '  %s[✘] FAILED%s      : %s%d%s\n'  "${RED}"    "${RESET}" "${BOLD}" "${_fail}" "${RESET}"
printf '\n'

if [[ ${#FAILED_ITEMS[@]} -gt 0 ]]; then
    printf '  %s[✘] Failed items:%s\n' "${RED}" "${RESET}"
    for item in "${FAILED_ITEMS[@]}"; do
        printf '      %s•%s %s\n' "${RED}" "${RESET}" "$item"
    done
    printf '\n'
fi

if [[ $_fail -eq 0 ]]; then
    printf '  %s[✔] All modules online — run: bash start.sh%s\n\n' "${GREEN}${BOLD}" "${RESET}"
else
    printf '  %s[!] Setup complete with failures — check warnings above.%s\n\n' "${YELLOW}${BOLD}" "${RESET}"
fi
