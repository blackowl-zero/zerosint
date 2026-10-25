"""
Tests for --check-password: the password never comes from argv.

    python -m unittest discover -s tests
    python tests/test_password_cli.py
"""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# so it also runs as a plain script from any directory
sys.path.insert(0, ROOT)

import main  # noqa: E402


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class PasswordCliTest(unittest.TestCase):
    def test_old_style_argument_rejected(self):
        p = subprocess.run([sys.executable, "main.py", "--check-password", "hunter2"],
                           cwd=ROOT, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(p.returncode, 2)
        self.assertIn("no longer takes the password", p.stderr)
        self.assertNotIn("hunter2", p.stdout + p.stderr)

    def test_password_never_echoed_in_any_argv_form(self):
        """Whatever way a password ends up on the command line, it is never printed."""
        secret = "Sup3rS3cretPw"
        forms = [
            ["--check-password", "-" + secret],           # looks like a flag
            ["--check-password=-" + secret],
            ["--check-pass", "-" + secret],                # argparse abbreviation
            ["--check-password", "--", "-" + secret],
            ["--check-password", secret, "--plain"],
            ["--plain", "--check-password", "-" + secret],
            ["--check-password", "--plain", secret],
            ["--check-pasword", "-" + secret],             # typo in the flag name
            ["--chek-password", secret],
            ["--plain", secret],                           # stray value, no flag at all
            ["-v" + secret],                               # glued to another flag
        ]
        for argv in forms:
            with self.subTest(argv=argv):
                p = subprocess.run([sys.executable, "main.py", *argv], cwd=ROOT,
                                   capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL, timeout=60)
                self.assertEqual(p.returncode, 2)
                self.assertNotIn(secret, p.stdout + p.stderr)

    def test_piped_password_not_printed_logged_or_saved(self):
        """Real run against the pwned-passwords API, with -v: the password shows up nowhere."""
        secret = "Zr0s1nt-bench-Pw"
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([sys.executable, os.path.join(ROOT, "main.py"),
                                "--check-password", "--plain", "-v"],
                               cwd=d, input=secret + "\n", capture_output=True, text=True,
                               timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn(secret, p.stdout + p.stderr)
            self.assertEqual(os.listdir(d), [])  # no report, json or db written

    @unittest.skipUnless(hasattr(os, "fork"), "needs a POSIX pty")
    def test_ctrl_c_at_prompt_exits_cleanly(self):
        """Real terminal: Ctrl+C at the hidden prompt -> short message, exit 130, no traceback."""
        import pty
        import select
        import time
        pid, fd = pty.fork()
        if pid == 0:  # child: the real CLI on a real tty
            os.chdir(ROOT)
            os.execv(sys.executable, [sys.executable, "main.py", "--check-password", "--plain"])
        out = b""
        deadline = time.monotonic() + 30
        while b"Password" not in out and time.monotonic() < deadline:
            if select.select([fd], [], [], 0.5)[0]:
                out += os.read(fd, 1024)
        os.write(fd, b"\x03")  # the terminal turns this into SIGINT
        while time.monotonic() < deadline:
            if not select.select([fd], [], [], 0.5)[0]:
                continue
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        _, status = os.waitpid(pid, 0)
        text = out.decode(errors="replace")
        self.assertIn("Password", text)
        self.assertNotIn("Traceback", text)
        self.assertIn("Cancelled.", text)
        self.assertEqual(os.waitstatus_to_exitcode(status), 130)

    def test_reads_from_pipe(self):
        self.assertEqual(main.read_password(io.StringIO("s3cret\n")), "s3cret")

    def test_pipe_keeps_inner_spaces(self):
        self.assertEqual(main.read_password(io.StringIO(" a b \n")), " a b ")

    def test_tty_uses_getpass(self):
        with mock.patch("main.getpass.getpass", return_value="pw") as gp:
            self.assertEqual(main.read_password(_TTY()), "pw")
        gp.assert_called_once()

    def _run_main(self, stdin_text: str, found: int = 3):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["main.py", "--check-password", "--plain"]), \
             mock.patch.object(sys, "stdin", io.StringIO(stdin_text)), \
             mock.patch("main.check_password_pwned", return_value=found) as chk, \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = main.main()
            except SystemExit as e:
                rc = e.code
        return rc, chk, out.getvalue(), err.getvalue()

    def test_flag_checks_password_from_stdin(self):
        rc, chk, out, _ = self._run_main("pw\n")
        self.assertEqual(rc, 0)
        chk.assert_called_once_with("pw")
        self.assertIn("Found 3 times", out)

    def test_empty_password_rejected(self):
        rc, chk, _, err = self._run_main("\n")
        self.assertEqual(rc, 2)
        self.assertIn("No password given.", err)
        chk.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
