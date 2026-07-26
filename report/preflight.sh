#!/bin/sh
# ===================================================================================================
# PREFLIGHT — dependency check for the privesc toolkit (winpriv + linpriv + report).
# Run this ON YOUR ATTACKER/OPERATOR BOX *before* going air-gapped. EVERYTHING checked here runs on
# YOUR box, never the target: the generators print commands, you build payloads, serve/catch shells,
# parse dumps offline, and render the report — all attacker-side. (Target-side needs are checked by
# enum.sh / enum.bat ON the target.)
# ===================================================================================================
ok=0; miss=0
chk() {   # chk <command> <what it enables> <install hint>
    if command -v "$1" >/dev/null 2>&1; then
        printf "  [ OK ] %-24s %s\n" "$1" "$2"; ok=$((ok + 1))
    else
        printf "  [MISS] %-24s %s\n         install: %s\n" "$1" "$2" "$3"; miss=$((miss + 1))
    fi
}

echo "===== core ====="
chk python3 "all generators + http.server delivery + gen_report" "apt install python3"
chk bash    "running these scripts / -e revshell catcher"        "apt install bash"

echo "\n===== Windows kit — payload & MSI build (attacker) ====="
chk x86_64-w64-mingw32-gcc "gen_payload/service/dll/winmisc — x64 PE build" "apt install gcc-mingw-w64-x86-64"
chk i686-w64-mingw32-gcc   "32-bit PE build (--arch x86)"                   "apt install gcc-mingw-w64-i686"
chk wixl                   "gen_msi --backend wixl (AlwaysInstallElevated)" "apt install wixl"
chk msfvenom               "gen_msi --backend msfvenom + shellcode payloads" "curl .../metasploit-omnibus msfinstall | sudo sh"

echo "\n===== Linux kit — attacker-side build/host ====="
chk gcc "gen_preload .so / gen_misc kmod / gen_exploit — attacker fallback build (else built ON target)" "apt install build-essential"

echo "\n===== initial access — recon (access/ module) ====="
chk nmap    "port/service scan (enum_net)"                "apt install nmap"
chk nuclei  "known-CVE/exposure scan"                     "go install .../nuclei; or apt"
chk searchsploit "offline exploit-db search (gen_exploit find)" "apt install exploitdb"
chk msfconsole "metasploit modules (gen_exploit run-throughs)" "metasploit-omnibus msfinstall"
chk nxc     "netexec — spray/enum/foothold across protos" "pipx install netexec"
chk ffuf    "web content/param fuzzing (enum_net --web)"  "apt install ffuf"
chk kerbrute "AD user enum / kerberos spray"              "github.com/ropnop/kerbrute"
chk hydra   "auth spray fallback (http-form/mysql)"       "apt install hydra"
chk enum4linux-ng "SMB/AD deep enum"                      "pipx install enum4linux-ng"

echo "\n===== initial access — AD internal: coercion/relay/poison/ADCS (access/) ====="
chk responder    "LLMNR/NBT-NS/mDNS poisoning (gen_poison)"     "apt install responder"
chk ntlmrelayx.py "NTLM relay to LDAP/SMB/ADCS (gen_relay)"     "pipx install impacket"
chk mitm6        "IPv6 DNS takeover (gen_poison mitm6)"          "pipx install mitm6"
chk certipy      "ADCS enum + ESC exploit (gen_adcs)"           "pipx install certipy-ad"
chk Coercer      "coercion all-in-one (gen_relay coerce)"       "pipx install coercer"
chk getST.py     "S4U/RBCD tickets (impacket)"                  "pipx install impacket"

echo "\n===== service footholds (services/ module) ====="
chk smbclient   "SMB shares (gen_smb)"                     "apt install smbclient"
chk showmount   "NFS exports (gen_nfs)"                    "apt install nfs-common"
chk onesixtyone "SNMP community brute (gen_snmp)"          "apt install onesixtyone"
chk snmpwalk    "SNMP enum (gen_snmp)"                     "apt install snmp"
chk redis-cli   "Redis foothold (gen_db --db redis)"       "apt install redis-tools"
chk docker      "exposed Docker API (gen_container docker)" "apt install docker.io"
chk rsync       "rsync modules (gen_remote rsync)"         "apt install rsync"
chk smtp-user-enum "SMTP user enum (gen_remote smtp)"      "apt install smtp-user-enum"

echo "\n===== initial access — cloud identity (access/network/gen_cloud) ====="
chk o365spray    "M365 user-enum + spray"                       "pipx install o365spray"
chk roadtx       "Entra token handling (ROADtools)"             "pipx install roadtools roadtx"

echo "\n===== access/web — web/app exploitation ====="
chk sqlmap  "SQL injection automation (gen_sqli --os-shell)" "apt install sqlmap"
chk jwt_tool "JWT forge/crack (gen_jwt)"                     "github.com/ticarpi/jwt_tool"
chk whatweb "web stack fingerprint"                          "apt install whatweb"
chk feroxbuster "content discovery (or ffuf/gobuster)"       "apt install feroxbuster"
chk tplmap  "SSTI auto-detect/exploit (optional)"            "github.com/epinna/tplmap"
chk ysoserial "Java deserialization gadgets (optional; .jar)" "github.com/frohoff/ysoserial"
chk phpggc  "PHP deserialization gadgets (optional)"          "github.com/ambionics/phpggc"

echo "\n===== initial access — access/network (creds/exec) ====="
chk mssqlclient.py "MSSQL + xp_cmdshell (Route 1 entry)"  "pipx install impacket"
chk wmiexec.py  "cred -> shell via WMI (quiet, impacket)" "pipx install impacket"
chk xfreerdp   "RDP foothold (gen_foothold --proto rdp)"  "apt install freerdp2-x11"

echo "\n===== serve / catch (attacker) ====="
chk nc         "reverse-shell catcher (nc -lvnp) + delivery" "apt install netcat-openbsd"
chk socat      "shell upgrade + RoguePotato OXID redirector" "apt install socat"
chk smbserver.py "SMB exfil/delivery of hives & LSASS dumps (impacket)" "pipx install impacket"

echo "\n===== offline parse / crack (attacker) ====="
chk pypykatz      "gen_creds --mode lsass -> parse the LSASS dump"      "pipx install pypykatz"
chk secretsdump.py "gen_hashdump / SeriousSAM -> dump SAM/NTDS offline" "pipx install impacket"
chk psexec.py     "Pass-the-Hash SYSTEM shell over SMB (impacket)"      "pipx install impacket"
chk hashcat       "crack recovered NTLM / other hashes"                 "apt install hashcat"
chk john          "crack /etc/shadow (unshadow + john)"                 "apt install john"

echo "\n===== network actioning with recovered creds (attacker) ====="
chk nxc        "validate creds / Pass-the-Hash / spray (netexec)" "pipx install netexec  (aka crackmapexec)"
chk evil-winrm "interactive WinRM shell with creds/hash"          "gem install evil-winrm"

echo "\n===== novel vuln research — binary RE (novelre/ module) ====="
chk radare2   "disasm/decompile + sink xref (gen_disasm/variant)" "apt install radare2"
chk gdb       "crash triage / exploitability (gen_crash)"         "apt install gdb  (+ gef/pwndbg)"
chk ROPgadget "ROP gadgets (gen_exploit)"                         "apt install python3-ropgadget"
chk afl-fuzz  "coverage-guided fuzzing (gen_fuzz)"                "apt install aflplusplus"
chk valgrind  "no-rebuild sanitizer for closed bins (gen_sanitize)" "apt install valgrind"
chk one_gadget "libc one-shot gadgets (gen_exploit onegadget)"    "gem install one_gadget"
# angr (pipx install angr) + ghidra (apt install ghidra) are heavier optionals for gen_symbolic/gen_disasm.

echo "\n===== reporting (attacker) ====="
chk pandoc     "gen_report.py -> DOCX (and drives PDF)" "apt install pandoc"
chk weasyprint "gen_report.py -> PDF engine"            "apt install weasyprint"

echo "\n===================================================================================="
echo "  present: $ok    missing: $miss"
echo "===================================================================================="
[ "$miss" -gt 0 ] && echo "  Pre-stage the MISSING items above before an air-gapped engagement." \
                  || echo "  All dependencies present."
echo ""
echo "  Notes:"
echo "   - impacket ships secretsdump.py / psexec.py / smbserver.py — if the wrappers are absent but"
echo "     impacket is installed, call the .py scripts directly from its bin/ dir."
echo "   - nxc / evil-winrm are only needed if you ACTION recovered creds over the network; skip if not."
echo "   - TARGET-side requirements (a shell, nc/python for revshells, gcc+headers ONLY for on-target"
echo "     exploit/.ko builds) are reported by enum.sh / enum.bat when you run them on the target."
