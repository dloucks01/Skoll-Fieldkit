"""Smoke tests for winpriv/gen_potato_scan.py -- the auto-scanner that emits a batch
script probing every staged Potato variant. Generator is print-only, so we drive it
via subprocess and assert on the output (same pattern as test_integration_recce.py)."""
import os
import subprocess
import unittest

WINPRIV = os.path.join(os.path.dirname(__file__), "..", "winpriv")
SCAN = os.path.join(WINPRIV, "gen_potato_scan.py")


def _run(*args):
    r = subprocess.run(["python3", SCAN, *args], capture_output=True, text=True,
                       cwd=WINPRIV)
    assert r.returncode == 0, f"scan generator failed: {r.stderr}"
    return r.stdout


class GenPotatoScan(unittest.TestCase):
    def test_default_scan_covers_every_potato_except_rogue(self):
        # Default = every tool in POTATOES_CMDLINE minus RoguePotato (which needs
        # the attacker-side socat OXID redirector and would just false-fail here).
        out = _run()
        for tool in ("PrintSpoofer64.exe", "GodPotato-NET4.exe", "GodPotato-NET35.exe",
                     "GodPotato-NET2.exe", "EfsPotato.exe", "SharpEfsPotato.exe",
                     "JuicyPotatoNG.exe", "SweetPotato.exe", "GenericPotato.exe"):
            self.assertIn(tool, out, f"expected {tool} in default scan")
        self.assertNotIn("RoguePotato.exe", out,
                         "RoguePotato must be off by default (needs attacker redirector)")

    def test_include_rogue_flag_adds_it(self):
        self.assertIn("RoguePotato.exe", _run("--include-rogue"))

    def test_positional_args_restrict_to_named_tools(self):
        out = _run("EfsPotato.exe", "SharpEfsPotato.exe")
        self.assertIn("EfsPotato.exe", out)
        self.assertIn("SharpEfsPotato.exe", out)
        self.assertNotIn("GodPotato", out)
        self.assertNotIn("SweetPotato.exe", out)

    def test_stagedir_flag_replaces_default_path(self):
        out = _run("--stagedir", r"D:\stage")
        self.assertIn(r"D:\stage", out)
        # The header-comment example fetch commands ALSO get rewritten (helpful UX).
        # But the default C:\Windows\Temp must not appear as an operational path:
        self.assertNotIn(r"C:\Windows\Temp\pscan_", out,
                         "custom --stagedir must replace default in markers")

    def test_timeout_flag_controls_ping_ticks(self):
        # ping -n <TIMEOUT+1> is the parallel sleep before the taskkill safety net.
        self.assertIn("ping -n 11 127.0.0.1", _run("--timeout", "10"))
        self.assertIn("ping -n 4 127.0.0.1", _run("--timeout", "3"))

    def test_short_tags_are_unique_across_godpotato_variants(self):
        # Regression: an earlier truncation collapsed all three GodPotato-NET* into
        # the same short tag, so their marker files and goto labels collided.
        out = _run()
        labels = sorted(set(ln.strip() for ln in out.splitlines() if ln.strip().startswith(":after_")))
        self.assertEqual(len(labels), len(set(labels)))
        # And explicitly assert the three GodPotato variants each got their own.
        for v in ("godpotatonet2", "godpotatonet35", "godpotatonet4"):
            self.assertIn(f":after_{v}", out)

    def test_output_is_valid_batch_shape(self):
        # Not executing it (Linux), but check the batch skeleton -- every probe
        # block has its markers/labels balanced.
        out = _run()
        self.assertIn("@echo off", out)
        self.assertIn("setlocal enabledelayedexpansion", out)
        self.assertIn("endlocal", out)
        # winners echo at the end
        self.assertIn("=== scan complete ===", out)
        self.assertIn("WINNERS", out)
        # Each probe pairs a start /b with a taskkill safety net.
        starts = out.count('start /b ""')
        kills = out.count("taskkill /f /im")
        self.assertEqual(starts, kills, "every probe must have a paired taskkill")

    def test_specific_tool_argv_uses_potatoes_cmdline_template(self):
        # If an operator uses the winner's TOOL in _winpriv_common.py and re-runs
        # gen_full/nonet/forma, the arg pattern must be the SAME one gen_potato_scan
        # tested with. This asserts the direct linkage.
        import sys
        sys.path.insert(0, WINPRIV)
        try:
            import _winpriv_common as P
        finally:
            sys.path.pop(0)
        out = _run("GodPotato-NET4.exe")
        # POTATOES_CMDLINE["GodPotato-NET4.exe"] = '-cmd "{CMD}"' -> we should see
        # `-cmd "cmd.exe /c whoami>...pscan_godpotatonet4.txt"` in the batch.
        self.assertIn('-cmd "cmd.exe /c whoami>', out)
        # And, as a sanity check, that the underlying template hasn't changed:
        self.assertEqual(P.POTATOES_CMDLINE["GodPotato-NET4.exe"], '-cmd "{CMD}"')


if __name__ == "__main__":
    unittest.main()
