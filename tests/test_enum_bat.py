"""Regression tests for winpriv/enum.bat.

We can't execute cmd.exe on Linux, so these are lint-style checks on the batch
text — the exact class of bugs that made enum.bat short-circuit mid-run when
pasted on target (unescaped literal parens inside `&& () || ()` / `if () else ()`
blocks confuse cmd's compound-statement parser and abort execution silently)."""
import os
import re
import unittest

ENUM_BAT = os.path.join(os.path.dirname(__file__), "..", "winpriv", "enum.bat")


class EnumBatLint(unittest.TestCase):
    def _read(self):
        with open(ENUM_BAT, encoding="utf-8") as fh:
            return fh.read().splitlines()

    def test_or_else_echo_uses_escaped_parens(self):
        # `whoami ... && (...) || echo (text)` -- the `(text)` after `||`-echo must
        # use `^(...^)` because cmd sees it inside the outer compound statement
        # and parses `(text)` as a nested code block. Silent aborts follow. This
        # is exactly the bug that made enum.bat stop after ~3 sections on target.
        offenders = []
        pattern = re.compile(r"\|\|\s*echo\s+\((?!\^)")
        for i, ln in enumerate(self._read(), 1):
            if pattern.search(ln):
                offenders.append((i, ln.strip()))
        self.assertFalse(
            offenders,
            "unescaped parens after `|| echo` will silently abort cmd.exe:\n" +
            "\n".join(f"  line {i}: {t}" for i, t in offenders))

    def test_else_echo_uses_escaped_parens(self):
        # `if ... (...) else (echo (text))` -- same trap on the else branch.
        offenders = []
        pattern = re.compile(r"else\s*\(\s*echo\s+\((?!\^)")
        for i, ln in enumerate(self._read(), 1):
            if pattern.search(ln):
                offenders.append((i, ln.strip()))
        self.assertFalse(
            offenders,
            "unescaped parens in `else (echo (X))` will silently abort cmd.exe:\n" +
            "\n".join(f"  line {i}: {t}" for i, t in offenders))

    def test_all_recommendation_arrows_are_escaped(self):
        # `==>` needs to be `==^>` inside a `(...)` block because `>` redirects.
        # Check every `==>` outside REM comments (which don't execute) is escaped.
        for i, ln in enumerate(self._read(), 1):
            stripped = ln.strip()
            if stripped.startswith("REM") or stripped.startswith("::"):
                continue
            if "==>" in ln and "==^>" not in ln:
                self.fail(f"line {i}: unescaped ==> will redirect stdout: {stripped}")

    def test_endlocal_present_and_last(self):
        # A missing `endlocal` after `setlocal enabledelayedexpansion` leaks env
        # into the parent shell. It has to be present, and last, or later sections
        # are inadvertently inside the enabled-delayed-expansion scope with edge
        # cases from the code above.
        lines = [ln.strip() for ln in self._read()]
        self.assertEqual(lines[-1], "endlocal")


if __name__ == "__main__":
    unittest.main()
