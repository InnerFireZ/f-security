```
╔══════════════════════════════════════════════════════════╗
║   ▓▒░  F - S E C U R I T Y  ░▒▓                       ║
║   NETWORK INFILTRATION SUITE  ·  16 MODULES             ║
║   Rootless Kali NetHunter  ·  Android / Linux           ║
╚══════════════════════════════════════════════════════════╝
```

**Portable LAN pentest suite — rootless Android first.**  
No root required. TCP connect scans throughout (`-sT --unprivileged`). No raw sockets.

---

## DEPLOY

```bash
bash setup-tools.sh   # install all dependencies
bash start.sh         # launch the suite
```

Results saved to `results/YYYY-MM-DD_HH-MM-SS/` automatically.

---

## MODULES

| `[ID]` | Script | What it does |
|--------|--------|--------------|
| `[01]` | `crackmap.sh` | SMB / RDP / WinRM null-session enumeration |
| `[02]` | `fscan.sh` | Fast internal LAN scanner (binary) |
| `[03]` | `nmap.sh` | Service + version scan — rootless `-sT` |
| `[04]` | `auto_ingram.sh` | Webcam auto-exploit via Ingram |
| `[05]` | `rtsp_brute_open.sh` | RTSP stream brute-force + live view (mpv) |
| `[06]` | `nuclei.sh` | Vulnerability templates scan — IoT / LAN optimised |
| `[07]` | `autorecon.sh` | Ping sweep + AutoRecon (TCP only, rootless) |
| `[08]` | `web.sh` | Web recon — whatweb / nikto / gobuster / feroxbuster |
| `[09]` | `iot.sh` | IoT / SCADA / Camera discovery + exploit menus |
| `[10]` | `brute.sh` | Credential brute-force — SSH / FTP / HTTP / Telnet / SMB / RDP |
| `[11]` | `ssl.sh` | TLS/SSL cert + CVE audit (testssl.sh / sslscan) |
| `[12]` | `dns_ad.sh` | DNS zone transfer + Active Directory / LDAP enumeration |
| `[13]` | `report.sh` | Compile results → dark-themed HTML pentest report |
| `[14]` | `post.sh` | Per-host exploit menus from any scan session |
| `[15]` | `c2.sh` | Reverse shell listener — 13 payload types |
| `[16]` | `exploit.sh` | CVE quick-strike — port match + MSF launcher |

---

## IoT / SCADA ENGINE — `iot.sh`

```
[SYS] Interface picker
  ▶  Triage pre-scan       12 ports — fast preview
  ▶  Full nmap             all IoT/SCADA/camera ports  -sT
  ▶  Parallel probes       25+ protocol fingerprints
  ▶  Device classification 2-tier scoring engine
  ▶  RTSP brute-force      cameras only
  ▶  Action submenus       per device type / protocol
```

### Protocol Probes

| Protocol | Port | Detection |
|----------|------|-----------|
| Modbus/TCP | 502 | Device ID (FC43), registers, coils — unauthenticated |
| Siemens S7 | 102 | COTP + S7 comms setup |
| EtherNet/IP | 44818 | CIP List Identity |
| IEC 60870-5-104 | 2404 | STARTDT handshake |
| DNP3 | 20000 | Link-layer frame |
| BACnet/IP | 47808 | Who-Is broadcast |
| OPC-UA | 4840 | Hello message |
| Niagara Fox | 1911/4911 | Tridium building automation — station name, version, hostname |
| MQTT | 1883/8883 | CONNECT + open broker check + 10 s live capture |
| RTSP | 554/8554 | DESCRIBE — anonymous + credential brute-force |
| ONVIF | 80/8080 | GetDeviceInformation |
| HTTP fingerprint | 80/443/8080 | Hikvision, Dahua, Axis, Siemens, Schneider |
| SMB | 445 | SMB2/3 negotiate + signing mode |
| SSH | 22 | Banner + key exchange |
| SNMP | 161/UDP | sysDescr / sysName / sysLocation |
| FTP | 21 | Anonymous login |
| Telnet | 23 | Credential pairs + no-auth check |
| UPnP/SSDP | 1900/UDP | Device description |
| CoAP | 5683/UDP | GET `/.well-known/core` |
| WS-Discovery | 3702/UDP | ONVIF camera self-announcement — model, scopes, service URLs |
| Hikvision SADP | 37020/UDP | Firmware version, serial, SDK port — no credentials |
| IPMI/RMCP | 623/UDP | BMC auth caps — cipher-0 flag (CVE-2013-4786) |
| NFS | 2049 | `showmount -e` — enumerate exports, flag `*` world-mountable shares |
| Redis | 6379 | PING probe — no-auth detection, default password list, version, writable dir (RCE path) |
| PostgreSQL | 5432 | StartupMessage → trust auth check + default credential pairs (postgres/postgres etc.) |
| Ghostcat / Tomcat AJP | 8009 | CVE-2020-1938 — AJP13 handshake; open connector = unauthenticated file read from any webapp |
| Oracle WebLogic | 7001 | CVE-2019-2725 — T3 handshake; confirmed response = pre-auth RCE (CVSS 9.8) |
| Docker API | 2375 | Unauthenticated daemon — instant host root via `docker run -v /:/host` |
| MikroTik Winbox | 8291/8728 | RouterOS detection — CVE-2018-14847 credential DB read (≤ 6.42) |
| Cisco Smart Install | 4786 | CVE-2018-0171 — unauthenticated config r/w + firmware replace |
| **Telnet no-auth + CVE-2026-24061** | **23** | **No-cred shell (Mirai) + inetutils telnetd auth bypass via `NEW_ENVIRON USER=-f root` → root shell** |

### Action Submenus

Sections appear only when the corresponding type or protocol was detected.

**`[Camera/CCTV]`**
1. RTSP credential brute-force
2. Print open ports + probe details
3. Dump Hikvision / Dahua / Axis device info via HTTP
4. HTTP Basic auth default credential check
5. Ingram auto-exploit — snapshot + credential attack

**`[SCADA/ICS]`**
1. Re-run all protocol probes live
2. Print full probe results
3. SNMP walk — public / private / admin communities

**`[IoT]`**
1. MQTT broker check + 10 s live message capture
2. UPnP / SSDP device info
3. Print full probe results
4. FTP anonymous + Telnet credential check

**`[Windows/SMB]`**
1. Null session — share list
2. Null session — full enum (users / groups / RID brute)
3. MS17-010 check — SMBv1 hosts
4. EternalBlue exploit — bind shell via Metasploit

**`[RDP/BlueKeep]`**
1. BlueKeep check — CVE-2019-0708 via Metasploit
2. BlueKeep exploit — unauthenticated RCE bind shell
3. RDP security scan — NLA / encryption level

**`[IPMI/BMC]`**
1. Auth types + cipher-0 vulnerability status
2. Metasploit `ipmi_dumphashes` — CVE-2013-4786 hash extraction
3. Metasploit `ipmi_login` — default credential check

**`[Docker API]`**
1. Show `/version` + `/info` — engine, OS, containers
2. `docker ps -a` via remote daemon
3. Privileged container root escape — mounts host `/` inside container

**`[Niagara Fox]`**
1. Station name, version, hostname, address
2. `nmap --script fox-info,fox-brute`
3. Metasploit `fox_login`

**`[Telnet Exploit]`**
1. Show raw banner — what prompt appears without credentials
2. Open interactive `telnet IP 23` session
3. Dump `/etc/passwd` — send command, capture output
4. **CVE-2026-24061** — inject `NEW_ENVIRON USER=-f root` IAC payload → instant root shell (inetutils telnetd 1.9.3–2.7)

**`[MikroTik]`**
1. Winbox version + CVE-2018-14847 flag
2. Metasploit `mikrotik_winbox_disclosure` — extract credentials unauthenticated
3. `nmap --script mikrotik-routeros-brute`
4. SSH default credential check

**`[NFS Shares]`**
1. Show all exports — path + access control per host
2. Mount share interactively — browse filesystem
3. Metasploit `nfsmount` scanner
4. `nmap --script nfs-showmount,nfs-ls,nfs-statfs`

**`[Cisco SMI]`**
1. Response data — IOS version if extracted
2. Metasploit `cisco_smart_install` — CVE-2018-0171
3. CVE-2023-20198 check — probe `/webui/logoutconfirm.html` (CVSS 10.0)
4. `nmap --script cisco-smi,snmp-info`

**`[Redis]`**
1. Show version + auth status + writable dir path
2. Dump keys — `KEYS *` + `GET` top 20
3. RCE via cron write — inject reverse shell into `/var/spool/cron/root`
4. Metasploit `redis_replication_cmd_exec` — unauthenticated RCE

**`[PostgreSQL]`**
1. Show auth type + credentials found (trust / default pair)
2. List databases + tables via `psql -c \l`
3. RCE via `COPY TO PROGRAM` — run OS command as postgres user
4. Metasploit `postgres_login` — default credential scanner

**`[Ghostcat AJP]`**
1. Show AJP response — confirm connector open (CVE-2020-1938)
2. Read arbitrary file — `ajp-request` nmap script (default `/WEB-INF/web.xml`)
3. Metasploit Ghostcat file read module
4. `nmap --script ajp-headers,ajp-request`

**`[WebLogic]`**
1. Show T3 handshake version + admin console exposure
2. Metasploit CVE-2019-2725 — T3 AsyncResponseService pre-auth RCE
3. Metasploit CVE-2015-4852 — Commons Collections gadget chain RCE
4. `nmap --script http-title,http-auth-finder` on ports 7001/7002

---

## C2 LISTENER — `c2.sh`

13 payload types + socat/nc listener. PTY upgrade guide included.

| # | Payload | Notes |
|---|---------|-------|
| 01 | Bash `-i` | Universal |
| 02 | Bash fd 196 | Alternate bash |
| 03 | Python 3 | socket + subprocess |
| 04 | Python 2 | socket + subprocess |
| 05 | PHP | fsockopen + proc_open |
| 06 | Perl | Socket module |
| 07 | Netcat `-e` | BusyBox / classic nc |
| 08 | Netcat mkfifo | When nc has no `-e` |
| 09 | Ruby | TCPSocket |
| 10 | Socat PTY | Full interactive PTY — best quality |
| 11 | AWK | Minimal environment fallback |
| 12 | PowerShell | Windows TCPClient loop |
| 13 | PowerShell encoded | Base64 UTF-16LE — bypasses cmd logging |

---

## CVE QUICK-STRIKE — `exploit.sh`

Port-based CVE match → searchsploit → Metasploit one-keypress launch.

| Port | CVE / Vulnerability | Impact |
|------|---------------------|--------|
| 445 | MS17-010 EternalBlue | Windows SMB RCE |
| 445 | MS17-010 PSExec | Stable EternalBlue variant |
| 445 | PrintNightmare CVE-2021-1675 | Print Spooler RCE |
| 445 | EternalRomance CVE-2017-0144 | Alternate SMB RCE |
| 3389 | BlueKeep CVE-2019-0708 | RDP pre-auth RCE |
| 21 | vsftpd 2.3.4 Backdoor | Root shell via port 6200 |
| 21 | ProFTPD 1.3.3c Backdoor | modpath root shell |
| 21 | ProFTPD mod_copy | Arbitrary file read/write |
| 6379 | Redis Unauth RCE | Cron / SSH key write → shell |
| 5900 | VNC Auth Bypass | No-password VNC |
| 2049 | NFS Unauth Mount | Unauthenticated share access |
| 27017 | MongoDB Unauth | Full DB access |
| 9200 | ElasticSearch Unauth | Read all indices |
| 80/8080 | Shellshock CVE-2014-6271 | HTTP CGI bash injection |
| 443 | Heartbleed CVE-2014-0160 | OpenSSL memory leak / key dump |
| 1099 | Java RMI | Remote class load RCE |
| 8161 | ActiveMQ CVE-2023-46604 | Unauthenticated RCE |
| 161 | SNMP Default Community | Info leak |
| 512/513 | rexec / rlogin | Legacy Unix trust — no password |
| 4786 | Cisco Smart Install CVE-2018-0171 | Config r/w + firmware replace |
| 8291 | MikroTik Winbox CVE-2018-14847 | Credential DB read (RouterOS ≤ 6.42) |
| 23 | Telnet No-Auth / CVE-2026-24061 | No-cred shell + inetutils auth bypass → root |
| 5432 | PostgreSQL Default/No-Auth | Trust auth or default creds → DB access + `COPY PROGRAM` RCE |
| 7001 | WebLogic CVE-2019-2725 | T3 deserialization pre-auth RCE — CVSS 9.8 |
| 8009 | Ghostcat CVE-2020-1938 | Tomcat AJP unauthenticated file read from any webapp |

---

## ROOTLESS

All probes use standard TCP/UDP socket connections — no raw sockets, no root.  
Always pick **Quick mode** on NetHunter. UDP probes are attempted but not required.

```
✔  Modbus · S7 · RTSP · MQTT · SMB · HTTP · FTP · Telnet · SNMP · all protocol probes
✔  Hydra TCP connect brute-force
✔  testssl.sh / sslscan TLS audit
✔  dig + ldapsearch DNS / AD enumeration
✔  socat / nc reverse shell listener
✔  All MSF TCP connect exploit modules
✘  ARP scan  ·  SYN scan (-sS)  ·  OS fingerprint (-O)  ·  MAC lookup
```
