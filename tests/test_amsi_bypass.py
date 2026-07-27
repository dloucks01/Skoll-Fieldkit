"""Regression tests for winpriv/_winpriv_common.py's modernised AMSI bypass.

The old bypass hardcoded S3cur3Th1sSh1t 2020 identifiers (LookupFunc, getDelegateType)
and a fixed byte sequence (0xB8,0x57,0x00,0x07,0x80,0xC3) that current Defender
static-signatures on sight, so `powershell -e <b64>` in gen_full/gen_nonet died at
AMSI-scan time before any of it executed. These tests pin the properties that
defeat those static signatures."""
import importlib
import os
import sys
import unittest

WINPRIV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "winpriv"))
if WINPRIV not in sys.path:
    sys.path.insert(0, WINPRIV)


def _reimport():
    import _winpriv_common
    return importlib.reload(_winpriv_common)


class AmsiBypassSignatures(unittest.TestCase):
    def test_no_hardcoded_lookupfunc_or_getdelegatetype(self):
        # The classic S3cur3Th1sSh1t function names -- most-signatured tokens in
        # any AMSI-bypass string. They must NOT appear as literals.
        P = _reimport()
        self.assertNotIn("LookupFunc", P.AMSI)
        self.assertNotIn("getDelegateType", P.AMSI)

    def test_no_literal_amsiscanbuffer_or_amsi_dll(self):
        # `AmsiScanBuffer` and `amsi.dll` as literal strings are THE most-scanned
        # tokens. They must be constructed at runtime by concatenation. The
        # random chunker CAN split anywhere -- e.g. `'Ams'+'iSca'+'nB'+'uffer'`
        # -- so we don't assert individual fragments, only that the full literal
        # never appears.
        P = _reimport()
        self.assertNotIn("AmsiScanBuffer", P.AMSI,
                         "AmsiScanBuffer must be constructed at runtime")
        self.assertNotIn("amsi.dll", P.AMSI,
                         "amsi.dll must be constructed at runtime")
        # The concat operator MUST appear (proof the string was actually chunked
        # rather than eliminated altogether):
        self.assertIn("'+'", P.AMSI, "chunked strings should show '+' concat")

    def test_no_literal_virtualprotect_or_kernel32_dll(self):
        # VirtualProtect + kernel32.dll are what actually make the memory patch
        # possible; both must be runtime-constructed for the same reason.
        P = _reimport()
        self.assertNotIn("VirtualProtect", P.AMSI)
        self.assertNotIn("kernel32.dll", P.AMSI)

    def test_no_literal_unsafenativemethods_get_proc_or_module_handle(self):
        # The reflection path into System.dll's UnsafeNativeMethods is the second
        # heavily-scanned family of strings. All three must be runtime-constructed.
        P = _reimport()
        for lit in ("Microsoft.Win32.UnsafeNativeMethods",
                    "GetProcAddress", "GetModuleHandle", "System.dll"):
            self.assertNotIn(lit, P.AMSI, f"'{lit}' must be runtime-constructed")

    def test_two_builds_produce_different_output(self):
        # The bypass must randomise per build so operators get a per-engagement
        # unique blob (no fixed hash for Defender to signature).
        P = _reimport()
        a = P.build_amsi()
        b = P.build_amsi()
        self.assertNotEqual(a, b, "build_amsi() output must randomise")

    def test_byte_patch_is_one_of_three_semantically_equivalent_patterns(self):
        # Each patch returns 0 (AMSI_RESULT_CLEAN) so AMSI treats every buffer as
        # clean. Randomising WHICH patch also defeats byte-pattern signatures.
        P = _reimport()
        variants = ["0x31,0xC0,0xC3",                   # xor eax, eax ; ret
                    "0xB0,0x00,0xC3",                   # mov al, 0    ; ret
                    "0xB8,0x57,0x00,0x07,0x80,0xC3"]    # classic
        found = False
        for _ in range(30):        # very unlikely 30 calls all miss any variant
            blob = P.build_amsi()
            if any(v in blob for v in variants):
                found = True
                break
        self.assertTrue(found, "no known byte patch appeared in 30 tries")

    def test_essential_mechanics_still_present(self):
        # A modernised bypass that removed the actual mechanics would be worse
        # than useless -- pin the core three operations.
        P = _reimport()
        self.assertIn("Marshal", P.AMSI)          # ::Copy + ::GetDelegateForFunctionPointer
        self.assertIn("MakeByRefType", P.AMSI)    # VirtualProtect delegate signature
        self.assertIn("[IntPtr]", P.AMSI)         # AmsiScanBuffer function pointer

    def test_amsi_variable_is_populated_at_import(self):
        # Callers (gen_full.py, gen_nonet.py) use `P.AMSI` directly as a string.
        # Keep that contract -- module-level AMSI must be a nonempty str.
        P = _reimport()
        self.assertIsInstance(P.AMSI, str)
        self.assertGreater(len(P.AMSI), 500)

    def test_amsi_reimport_yields_fresh_randomisation(self):
        # Every fresh Python process (gen_full.py, gen_nonet.py) gets its own
        # bypass at import. Simulate by reloading the module.
        first = _reimport().AMSI
        second = _reimport().AMSI
        self.assertNotEqual(first, second,
                            "each import must generate a fresh bypass")


class GenScriptsStillProduceValidOutput(unittest.TestCase):
    """gen_full.py and gen_nonet.py concatenate P.AMSI into their PS blob and
    encode the whole thing UTF-16LE base64 for `powershell -e`. Verify neither
    breaks and the encoded output fits under cmd.exe's 8191 char limit."""

    def test_gen_full_produces_encoded_command_under_cmd_limit(self):
        import subprocess
        r = subprocess.run(["python3", "gen_full.py"],
                           cwd=WINPRIV, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, f"gen_full.py failed: {r.stderr}")
        # The generator prints the length; parse it and assert < 8191.
        import re
        m = re.search(r"outer b64 len:\s+(\d+)", r.stdout)
        self.assertIsNotNone(m, "gen_full.py must print `outer b64 len: N`")
        length = int(m.group(1))
        self.assertLess(length, 8191,
                        f"encoded command length {length} exceeds cmd.exe limit")


if __name__ == "__main__":
    unittest.main()
