"""Every shell script in the kit must parse cleanly. Same class of guard as
tests/test_enum_bat.py -- we can't execute the shells fully in CI (some target
Linux privesc primitives that need root), but `bash -n` catches every syntax bug
that would silently abort on the operator's target (unclosed heredocs, missing
`fi`, stray `)` in a subshell, etc.). shellcheck is used as an OPTIONAL upgrade
when available."""
import os
import glob
import shutil
import subprocess
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _sh_files():
    return sorted(
        p for p in glob.glob(os.path.join(ROOT, "**", "*.sh"), recursive=True)
        if "/.git/" not in p and "/__pycache__/" not in p
    )


class ShellSyntax(unittest.TestCase):
    def test_every_sh_parses_under_bash_n(self):
        # bash -n catches: unclosed quotes/heredocs, missing fi/done/esac, unbalanced
        # subshell parens, invalid `case` bodies, etc. Runs offline, no execution.
        fails = []
        for path in _sh_files():
            r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
            if r.returncode != 0:
                rel = os.path.relpath(path, ROOT)
                fails.append(f"{rel}: {r.stderr.strip()}")
        self.assertFalse(fails,
                         "shell scripts fail bash -n:\n  " + "\n  ".join(fails))

    def test_shellcheck_error_level_clean(self):
        # shellcheck -S error surfaces only real bugs (SC2016-ish and up). Warnings
        # (e.g. SC2010 "don't use ls | grep") are style and skipped here.
        if shutil.which("shellcheck") is None:
            self.skipTest("shellcheck not installed")
        fails = []
        for path in _sh_files():
            r = subprocess.run(["shellcheck", "-S", "error", path],
                               capture_output=True, text=True)
            if r.returncode != 0:
                rel = os.path.relpath(path, ROOT)
                fails.append(f"--- {rel} ---\n{r.stdout.strip()}")
        self.assertFalse(fails, "shellcheck -S error hits:\n\n" + "\n\n".join(fails))


if __name__ == "__main__":
    unittest.main()
