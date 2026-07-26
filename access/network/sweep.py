#!/usr/bin/env python3
"""MASS TRIAGE across a target LIST (e.g. 480 IPs/hostnames) -> a ranked scoreboard of WHICH hosts to
focus on. Two steps: (1) `plan` prints the fast mass-scan command sequence to run across the whole list;
(2) `triage` parses the scan output and ranks every host by likely quick-win, mapping each to the
generator that exploits it. Authorized scope ONLY — this scans your defined engagement range.

Usage:
  python3 sweep.py plan   --targets targets.txt                 # print the mass-scan commands
  python3 sweep.py triage --nmap ports.gnmap [--nxc smb.txt]    # parse -> scoreboard (focus list)
"""
import sys, re

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

arg = sys.argv[1] if len(sys.argv) > 1 else "plan"

# port -> (label, quick-win note + which generator, juiciness 0=best)
WINS = {
    2375: ("docker-api",  "UNAUTH → root on host: services/gen_container.py docker",        0),
    2376: ("docker-tls",  "Docker API (TLS): services/gen_container.py docker",              1),
    6379: ("redis",       "often UNAUTH → RCE: services/gen_db.py --db redis",              0),
    27017:("mongodb",     "often UNAUTH → data/creds: services/gen_db.py --db mongo",       1),
    9200: ("elastic",     "UNAUTH REST → data (+old RCE): services/gen_db.py --db elastic", 1),
    5984: ("couchdb",     "UNAUTH → add-admin+RCE: services/gen_db.py --db couchdb",        1),
    11211:("memcached",   "UNAUTH → sessions/creds: services/gen_db.py --db memcached",     2),
    445:  ("smb",         "null-session/relay/EternalBlue: services/gen_smb + access/gen_relay", 1),
    2049: ("nfs",         "exports → loot/keys: services/gen_nfs.py",                        1),
    21:   ("ftp",         "anon login? services/gen_ftp.py anon",                            2),
    161:  ("snmp",        "community strings: services/gen_snmp.py (UDP — nmap -sU)",        2),
    873:  ("rsync",       "anon modules: services/gen_remote.py rsync",                      2),
    5900: ("vnc",         "no-auth/weak: services/gen_remote.py vnc",                        2),
    23:   ("telnet",      "default creds: services/gen_remote.py telnet",                    3),
    8080: ("http-alt",    "Tomcat/JBoss mgr / web: services/gen_container.py tomcat · web/", 1),
    80:   ("http",        "web app → access/web/ (nuclei/ffuf first)",                         2),
    443:  ("https",       "web app → access/web/",                                             2),
    3389: ("rdp",         "spray CAREFULLY (lockout): access/gen_spray.py --proto rdp",      3),
    5985: ("winrm",       "cred → shell: access/gen_shell.py --proto winrm",              3),
    1433: ("mssql",       "SQLi/spray → xp_cmdshell: access/gen_shell --proto mssql",     2),
    3306: ("mysql",       "spray → UDF/OUTFILE: services/gen_db.py --db mysql",              2),
    5432: ("postgres",    "COPY…PROGRAM RCE: services/gen_db.py --db postgres",              2),
    1521: ("oracle",      "SID/creds (ODAT): services/gen_db.py --db oracle",                2),
    389:  ("ldap",        "anon bind? domain enum: access/enum_net --ad",                    2),
    88:   ("kerberos",    "AS-REP roast / kerbrute: access/gen_spray --proto kerberos",      2),
    25:   ("smtp",        "user-enum/relay: services/gen_remote.py smtp",                    3),
}

if arg == "plan":
    tf = opt("--targets", "targets.txt")
    print(f"# MASS TRIAGE plan for {tf}. Run top-to-bottom (each step feeds the next); outputs feed `sweep.py triage`.")
    print(f"# needs: {tf} = your authorized scope, one IP/host/CIDR per line (<x> = you supply this file).\n")
    print(f"# 1) live hosts (skip if you already know they're up):")
    print(f"nmap -sn -iL {tf} -oG live.gnmap; grep Up live.gnmap | cut -d' ' -f2 > live.txt")
    print(f"#    -> ok: live.txt now holds the responding hosts (used by every step below).\n")
    print(f"# 2) FAST port scan across all (masscan is faster for 480; nmap greppable for triage):")
    print(f"nmap -Pn -iL live.txt --top-ports 200 --open --min-rate 2000 -oG ports.gnmap")
    print(f"#    (or:  masscan -iL live.txt -p1-65535 --rate 5000 -oG ports.gnmap)")
    print(f"#    -> ok: ports.gnmap is written with each host's open ports — this is the file triage parses.\n")
    print(f"# 3) SMB sweep (null session + signing + OS, all hosts at once):")
    print(f"nxc smb live.txt > smb.txt ; nxc smb live.txt --shares -u '' -p '' >> smb.txt")
    print(f"nxc smb live.txt --gen-relay-list relay_targets.txt      # signing-OFF = relay candidates")
    print(f"#    -> ok: smb.txt captures names/OS/signing + any null-session shares; relay_targets.txt = relay list.\n")
    print(f"# 4) web + known-CVE sweep (pull web hosts, then httpx/nuclei):")
    print(f"grep -E '(80|443|8080|8443)/open' ports.gnmap | cut -d' ' -f2 > web.txt")
    print(f"httpx -l web.txt -title -tech-detect -sc -o web_httpx.txt")
    print(f"nuclei -l web.txt -severity critical,high -o nuclei.txt")
    print(f"#    -> ok: nuclei.txt lists any critical/high findings across the web hosts.\n")
    print(f"# 5) service/version on the open set (for CVE matching):")
    print(f"nmap -Pn -sCV -iL live.txt -oA services --open\n")
    print(f"# -> then:  python3 sweep.py triage --nmap ports.gnmap --nxc smb.txt")

elif arg == "triage":
    ng = opt("--nmap"); nxc = opt("--nxc")
    if not ng:
        print("need --nmap ports.gnmap (from `sweep.py plan` step 2)"); sys.exit(1)
    # needs: --nmap = the greppable scan from `plan` step 2; --nxc (optional) = the SMB sweep from step 3.
    hosts = {}   # ip -> {"name":.., "ports":set()}
    for line in open(ng):
        m = re.search(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
        if not m or "Ports:" not in line: continue
        ip, name = m.group(1), m.group(2)
        h = hosts.setdefault(ip, {"name": name, "ports": set()})
        for pm in re.finditer(r"(\d+)/open/", line):
            h["ports"].add(int(pm.group(1)))
    # fold in nxc null-session hits (optional)
    null_shares = set()
    if nxc:
        for line in open(nxc):
            if re.search(r"(READ|WRITE)", line) and "\\\\" in line or "Enumerated shares" in line:
                mm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if mm: null_shares.add(mm.group(1))
    # score each host = best (lowest) win among its ports
    rows = []
    for ip, h in hosts.items():
        wins = [(WINS[p][2], p, WINS[p]) for p in h["ports"] if p in WINS]
        if not wins: continue
        wins.sort()
        best = wins[0][0] - (1 if ip in null_shares else 0)   # null-session bumps priority
        rows.append((best, ip, h["name"], wins, ip in null_shares))
    rows.sort()
    print(f"# TRIAGE SCOREBOARD — {len(hosts)} hosts scanned, {len(rows)} with a quick-win service. Focus top-down.\n")
    for score, ip, name, wins, nulls in rows:
        tag = " [NULL-SESSION]" if nulls else ""
        print(f"═══ {ip}  {('('+name+')') if name else ''}{tag}")
        for _, p, (label, note, _j) in wins:
            print(f"    {p:<6}{label:<12}{note}")
    print(f"\n# -> ok: hosts are ranked top-down; the top rows are the exposed-RCE/unauth quick-wins to hit first.")
    print(f"# work the top of the list first (0=exposed-RCE/unauth, higher=needs-creds).")
    print(f"# each line names the generator to run on that host. Log everything you confirm -> report/.")
else:
    print("use: plan --targets <file> | triage --nmap <ports.gnmap> [--nxc <smb.txt>]"); sys.exit(1)
