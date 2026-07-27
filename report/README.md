# Privesc reporting — customer-ready findings writeups

Turns proven privilege-escalation findings into a **Markdown report + DOCX + PDF**, with the full
**proof-of-concept command trail** (every command run and its observed result) and **auto-filled
severity / CWE / remediation** per finding. Companion to the `potato` (Windows) and `linpriv` (Linux)
privesc kits — you paste the commands those kits emit into `steps`, and this writes the report.

## Files
- `gen_report.py` — the generator (`--init` scaffolds; then renders md/docx/pdf).
- `_report_kb.py` — remediation knowledge base keyed by `vector_type` (severity, CWE, description, fix, refs).
- `findings.example.json` — a filled two-finding example (Windows + Linux) showing the schema.

## Workflow
```bash
python3 gen_report.py --init findings.json     # scaffold (copy of the example)
#   edit findings.json: engagement block + ONE finding per PROVEN privesc, each with its steps/commands
python3 gen_report.py findings.json            # -> report.md + report.docx + report.pdf
#   options:  -o <basename>   --formats md,docx,pdf
```

## Finding schema
```json
{
  "title": "Unquoted service path on WIN-SQL01 permits SYSTEM code execution",
  "vector_type": "unquoted_service",          // key into _report_kb.py — drives severity/CWE/remediation
  "affected_host": "10.0.0.5 (WIN-SQL01)",
  "evidence": "one-line summary of what confirmed it",
  "steps": [                                   // THE PROOF — exact commands + VERBATIM output
    {"cmd": "whoami", "output": "nt authority\\system"}
  ],
  "evidence_source": "engagement.log lines 210-260",  // provenance: where in the capture this came from
  "images": [                                  // optional screenshots, embedded into md/docx/pdf
    {"path": "screenshots/win-sql01-system.png", "caption": "whoami returns SYSTEM"}
  ],
  "artifacts": [                               // optional — feeds the cleanup manifest
    {"desc": "Planted C:\\Program.exe", "remove": "del C:\\Program.exe"}
  ],
  "severity": "High",                          // optional — overrides the KB default
  "references": "CVE-...."                      // optional — appended to the KB refs
}
```
Image `path`s are resolved relative to the directory you run `gen_report.py` from (keep a `screenshots/`
subfolder next to your findings file).

## Evidence integrity (make the report defensible)
The report is only as trustworthy as the output you paste — so capture it, don't retype it:

1. **Record the whole session verbatim.** Run your operator terminal under `script`:
   ```bash
   script -q -T timing.log engagement.log        # everything you see — incl. target output through your
                                                 # reverse shell / mssqlclient — is captured with timestamps
   ```
   (or `asciinema rec engagement.cast` for a replayable recording).
2. **Fill `steps` from the log, not from memory** — copy the exact command + its exact output. Set
   `evidence_source` to the log/line range, and `engagement.evidence_log` to the capture file. The report then
   states, per finding, which recorded evidence proves it.
3. **Validate before you render:**
   ```bash
   python3 gen_report.py findings.json --check   # fails on empty output / placeholders / missing fields
   ```
   `--check` flags any step with **no captured output**, placeholder tokens (`<target>`, `/path/to`, …),
   unknown vector types, missing hosts, or screenshots not on disk — so nothing paraphrased or unfilled reaches
   the customer. Exit code 2 on errors; run it as a gate before rendering.
4. **Never paraphrase tool output.** Paste it exactly; add a screenshot (`images`) for the key moments.
Valid `vector_type` values are listed in the `--init` template (`_valid_vector_types`) and in `_report_kb.py`.
Unknown types fall back to a generic entry — prefer adding a proper KB entry so the remediation is specific.

## Feed findings back to recce (the enumeration/reporting tool)

If you enumerated with [**recce**](https://github.com/dloucks01/recce), fold your proven findings back
into its workbook + report so the engagement has one source of truth:
```bash
python3 gen_report.py findings.json --export-recce      # -> recce_findings.json (KB-enriched)
#   then, in the recce checkout:  recce skoll-import recce_findings.json -o <engagement>
```
`--export-recce` resolves each finding's severity/CWE/remediation/risk from `_report_kb.py` and parses
the host IP out of `affected_host`, so recce imports it with no copy of this KB. See the repo-root
**[`INTEGRATION.md`](../INTEGRATION.md)** for the full round-trip (recce → fieldkit seeding included).

## Reporting principle
The kit reports **every** proven escalation path per host, ordered most-severe first — not just the first
one exploited. Each path is an independent risk the customer must remediate, so each gets its own writeup
with a concrete fix.

## Internal cleanup manifest (do NOT send to client)
Every state-changing test leaves artifacts on the **target** (planted files, created accounts, edited configs,
restarted services). Track and remove them:
```bash
python3 gen_report.py findings.json --cleanup     # -> report.cleanup.md  (INTERNAL)
```
Add an optional `artifacts` list to any finding — each item `{ "desc": "...", "remove": "<command>" }` (or a plain
string). The manifest groups them by host, labels each with the exploit's **risk** (see below), and appends
generic revert guidance. The client report also gets a short "Changes made during testing" note per finding
(transparency). Re-run enumeration as the low-priv user afterward to confirm nothing remains.

## Risk / reversibility labels (safety on production systems)
`_report_kb.py` tags every vector with an **operational risk** — how dangerous *exploiting* it is on a live box —
and a **safe-proof** note (how to demonstrate the finding without breaking anything):

| Label | Meaning | Prove-without-breaking |
|---|---|---|
| `read-only` | reading/exfil, no change | reading the data IS the proof |
| `reversible` | shell-spawn / minor artifact | spawn+exit; don't leave a backdoor account |
| `service-restart` | may disrupt a running service | prove writability (icacls/`ls -l`), don't bounce a prod service |
| `config-edit` | edits auth/loader files | benign marker you remove; back up first |
| `crash-risk` | kernel/driver — can BSOD/panic | version-match instead of detonating; snapshot + sign-off first |

Use these to sequence an engagement safely: exhaust `read-only`/`reversible` before anything `service-restart`/
`config-edit`, and never fire a `crash-risk` exploit on production without a snapshot and explicit sign-off.

## Preflight — check your attacker box before going air-gapped
```bash
sh preflight.sh      # verifies every ATTACKER-side dependency across all three kits + reporting
```

## Execution model — what runs WHERE
Everything in the `report/` folder and every `gen_*.py` / `gtfo.py` runs on the **ATTACKER** box — they *print*
commands and never touch the target. See `docs`-style summary:

| Runs on the ATTACKER box | Runs on the TARGET (paste into the foothold) |
|---|---|
| all `gen_*.py`, `gtfo.py`, `stage_b64.py` (they only print) | `enum.sh` / `enum.bat` (triage) |
| payload/MSI build: mingw, gcc, `wixl`, `msfvenom` | the printed command blocks (deliver, plant, trigger, escapes) |
| serve/catch: `http.server`, `nc -lvnp`, `smbserver.py` | on-target compile *only if the target has gcc* (`gen_exploit --fetch`, `kmod`) |
| offline parse/crack: `pypykatz`, `secretsdump.py`, `hashcat`, `john` | the privesc actions themselves (`whoami`, `sc config`, `reg add`, GTFOBins…) |
| network actioning: `psexec.py`, `nxc`, `evil-winrm` | |
| reporting: `gen_report.py`, `pandoc`, `weasyprint` | |

`preflight.sh` checks the left column; `enum.sh`/`enum.bat` check the right (a shell, `nc`/`python` for revshells,
and gcc+headers only if you build on the target).

## Export dependencies
`pandoc` (DOCX) + `weasyprint` (PDF engine) — install via `apt`. On an air-gapped operator box, pre-stage
both; without them, `gen_report.py` still writes the Markdown and prints the exact conversion commands.
Convert later anywhere: `pandoc report.md -o report.docx` · `pandoc report.md -o report.pdf --pdf-engine=weasyprint`.
