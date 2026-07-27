# Sköll ⇄ recce — enumeration-driven exploitation, findings back to the sheet

Sköll is the **exploitation** half of an engagement; [**recce**](https://github.com/dloucks01/recce)
is the **enumeration + reporting** half (multi-subnet nmap → one tracked Excel workbook + report).
They round-trip cleanly, so you enumerate once and let each side feed the other:

```
recce enum/vulns ──skoll-export──▶  Sköll sweep + generators  ──findings.json──▶ gen_report
       ▲                                                                              │
       └──────────────  recce skoll-import  ◀── gen_report.py --export-recce ─────────┘
        (proven findings land back in the recce workbook + report)
```

Both directions are **offline, deterministic, stdlib-only** — nothing here scans, connects, or
executes. recce prints commands into a datastore; Sköll prints commands you paste. Authorized
engagements only.

---

## 1. recce → Sköll: turn enumeration into a focused attack plan

On the recce side, after `recce enum` / `recce vulns` (see recce's docs):

```bash
recce skoll-export -o eng          # writes eng/skoll/
```

That folder is the handoff. Copy it next to your Sköll checkout and feed **the richest one** into
mass triage:

```bash
python3 access/network/sweep.py triage --recce eng/skoll/recce-bridge.json
```

`--recce` uses recce's open ports **and the vulnerabilities it already confirmed**, so the
scoreboard floats proven quick-wins to the very top and annotates each host with what recce proved
(`CONFIRM [CRITICAL] …`) plus the exact generator to run. It composes with the classic inputs:

```bash
python3 access/network/sweep.py triage --nmap eng/skoll/ports.gnmap --nxc eng/skoll/smb-null.txt
```

| File in `eng/skoll/` | What it is | Consumed by |
|---|---|---|
| `recce-bridge.json` | ports + service/version + recce's **confirmed** findings + suggested generator per host | `sweep.py triage --recce` (richest) |
| `ports.gnmap` | synthesized nmap-greppable (`-oG`) | `sweep.py triage --nmap` (zero-change path) |
| `smb-null.txt` | netexec-style lines for null/anonymous SMB hosts | `sweep.py triage --nxc` |
| `SKOLL.md` | human, severity-ranked "run **this** on **that** host, because …" plan | you |

From the scoreboard, run the named generator per host (`services/gen_smb.py`, `access/gen_shell.py`,
`services/gen_db.py --db redis`, …) exactly as you would normally.

## 2. Sköll → recce: fold proven findings back into the sheet + report

Write up each **proven** finding in a `findings.json` the normal way (`gen_report.py --init`, fill in
`steps` from your session capture), then in addition to the client report, emit the recce feed:

```bash
python3 report/gen_report.py findings.json --check          # gate: every step has a real command + output
python3 report/gen_report.py findings.json                  # your customer report (md/docx/pdf)
python3 report/gen_report.py findings.json --export-recce   # -> recce_findings.json (KB-enriched)
```

`--export-recce` resolves each finding's severity, CWE, remediation and risk from `_report_kb.py` and
parses the host IP out of `affected_host`, into a self-contained `recce_findings.json` — recce needs
no copy of Sköll's KB. Fold it in on the recce side:

```bash
recce skoll-import recce_findings.json -o eng
```

Every proven finding becomes a **confirmed** vulnerability in recce (source `skoll`) and lands in the
**Vulnerabilities** sheet, the HTML/Markdown report and the DOCX write-ups; the affected host is
marked *access-gained*. Re-importing is idempotent (deduped by title+host), so you can run it as you
prove each finding.

> The engagement now has one source of truth: recce's workbook tracks coverage (what was enumerated)
> **and** outcomes (what Sköll proved), and recce's report reflects both.
