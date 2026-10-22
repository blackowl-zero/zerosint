#!/usr/bin/env python3
"""
ZeroSint: simple interactive menu.

    python3 menu.py

Does not change any scan logic: scans run main.py in a subprocess
(same UI, same reports/JSON/DB). Falls back to plain input() if rich is missing.
"""
from __future__ import annotations

import getpass
import json
import os
import platform
import subprocess
import sys
import webbrowser

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.table import Table
    console = Console()
except ImportError:  # no rich -> plain prompts
    console = None

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(HERE, "zerosint_report.html")
FINDINGS = os.path.join(HERE, "zerosint_findings.json")
FIELDS = ["email", "username", "domain", "name", "phone", "ip", "org"]

# settings kept while the menu is running
settings = {"depth": 2, "plain": False}


# ---------------- small helpers (rich or plain) ----------------
def say(msg: str, style: str = "") -> None:
    if console:
        console.print(msg, style=style or None, markup=False)
    else:
        print(msg)


def ask(label: str, default: str = "") -> str:
    if console:
        return Prompt.ask(label, default=default, show_default=bool(default)).strip()
    v = input(f"{label}{f' [{default}]' if default else ''}: ").strip()
    return v or default


def ask_int(label: str, default: int) -> int:
    if console:
        return IntPrompt.ask(label, default=default)
    try:
        return int(input(f"{label} [{default}]: ").strip() or default)
    except ValueError:
        return default


def confirm(label: str, default: bool = True) -> bool:
    if console:
        return Confirm.ask(label, default=default)
    v = input(f"{label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not v else v.startswith("y")


def pause() -> None:
    try:
        input("\nPress Enter to return to the menu...")
    except EOFError:
        pass


def clear() -> None:
    if console:
        console.clear()
    else:
        print("\n" * 2)


# ---------------- actions ----------------
def run_scan(inputs: dict[str, str]) -> None:
    """Run main.py with the given inputs. main.py does all the work."""
    if not inputs:
        say("No input provided.", "yellow")
        return
    cmd = [sys.executable, os.path.join(HERE, "main.py"), "--depth", str(settings["depth"])]
    for k, v in inputs.items():
        cmd += [f"--{k}", v]
    if settings["plain"]:
        cmd.append("--plain")
    say("Running: " + " ".join(cmd[1:]), "grey50")
    try:
        rc = subprocess.run(cmd, cwd=HERE).returncode
    except KeyboardInterrupt:
        say("\nInterrupted.", "yellow")
        return
    if rc == 0 and os.path.exists(REPORT) and confirm("Open the HTML report?", False):
        open_report()


def quick_email() -> None:
    email = ask("Email")
    if "@" not in email:
        say("That does not look like an email.", "red")
        return
    run_scan({"email": email})


def custom_scan() -> None:
    say("Fill in what you know. Press Enter to skip a field.", "grey50")
    inputs = {f: v for f in FIELDS if (v := ask(f.capitalize()))}
    if inputs and confirm(f"Scan with {', '.join(inputs)} (depth {settings['depth']})?"):
        run_scan(inputs)


def check_password() -> None:
    # in-process + getpass: the password is not shown on screen or in the process list
    from modules.breach_mod import check_password_pwned
    pw = getpass.getpass("Password (hidden): ")
    if not pw:
        return
    n = check_password_pwned(pw)
    if n < 0:
        say("Could not reach the pwned-passwords API.", "yellow")
    elif n == 0:
        say("Not found in known breaches.", "green")
    else:
        say(f"Found {n:,} times in breaches. Change it.", "bold red")


def view_last() -> None:
    """Show the summary of the last scan from zerosint_findings.json."""
    if not os.path.exists(FINDINGS):
        say("No scan yet.", "yellow")
        return
    try:
        from core.models import Finding
        from core.correlator import summarize
        with open(FINDINGS, encoding="utf-8") as fh:
            data = json.load(fh)
        results = {}
        # index keys: two entries can share type+value (input phone + phoneinfoga result)
        for i, d in enumerate(data):
            results[i] = Finding(**d)
        summary = summarize(results)
        seeds = [f.value for f in results.values() if f.source == "input"]
        label = seeds[0] if seeds else "last scan"
    except Exception as e:  # noqa: BLE001
        say(f"Could not read {FINDINGS}: {e}", "red")
        return

    from ui import console as ui_console
    ui = ui_console.make_ui()
    if ui is not None:
        ui.summary(results, summary, label, {"Report": os.path.basename(REPORT), "JSON": os.path.basename(FINDINGS)})
    else:
        t = summary["by_tier"]
        print(f"{label}: {summary['total']} findings "
              f"(high={t['high']} med={t['medium']} low={t['low']})")
        for f in sorted(results.values(), key=lambda f: -f.confidence)[:20]:
            if f.source != "input":
                print(f"  {f.confidence:.2f}  {f.type:<12} {f.value}")


def open_report() -> None:
    if not os.path.exists(REPORT):
        say("No report yet.", "yellow")
        return
    # WSL: open with the Windows browser
    if "microsoft" in platform.uname().release.lower():
        try:
            win = subprocess.run(["wslpath", "-w", REPORT], capture_output=True,
                                 text=True, check=True).stdout.strip()
            subprocess.Popen(["explorer.exe", win])
            say("Opened in the browser.", "green")
            return
        except (OSError, subprocess.CalledProcessError):
            pass
    if not webbrowser.open("file://" + REPORT):
        say(f"Open it manually: {REPORT}")


def run_tests() -> None:
    subprocess.run([sys.executable, os.path.join(HERE, "tests", "test_xposed_mod.py")], cwd=HERE)


def change_settings() -> None:
    settings["depth"] = max(1, min(5, ask_int("Max pivot depth (1-5)", settings["depth"])))
    settings["plain"] = confirm("Plain output (no Rich UI)?", settings["plain"])


# ---------------- menu ----------------
MENU = [
    ("1", "Quick scan (email)", quick_email),
    ("2", "Full scan (email, username, domain...)", custom_scan),
    ("3", "Password check (k-anonymity)", check_password),
    ("4", "Last results", view_last),
    ("5", "Open HTML report", open_report),
    ("6", "Settings", change_settings),
    ("7", "Run tests", run_tests),
    ("0", "Exit", None),
]


def show_menu() -> None:
    sub = f"depth={settings['depth']} | {'plain' if settings['plain'] else 'rich'} output"
    if console:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold cyan", justify="right")
        t.add_column()
        for key, label, _ in MENU:
            t.add_row(key, label)
        console.print(Panel(t, title="[bold]ZeroSint[/]", subtitle=sub,
                            border_style="blue", expand=False))
        console.print("[grey50]Passive recon | authorized use only | "
                      "breach API: max 25 checks/hour[/]")
    else:
        print("=== ZeroSint ===  (" + sub + ")")
        for key, label, _ in MENU:
            print(f"  {key}) {label}")


def main() -> int:
    os.chdir(HERE)
    sys.path.insert(0, HERE)
    while True:
        clear()
        show_menu()
        try:
            choice = ask("Choice", "1")
        except (KeyboardInterrupt, EOFError):
            print()
            return 0
        action = next((fn for key, _, fn in MENU if key == choice), "invalid")
        if action is None:
            return 0
        if action == "invalid":
            say("Unknown option.", "red")
        else:
            try:
                action()
            except KeyboardInterrupt:
                say("\nCancelled.", "yellow")
            except EOFError:
                return 0
        try:
            pause()
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    sys.exit(main())
