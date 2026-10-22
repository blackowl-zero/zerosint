#!/usr/bin/env python3
"""
ZeroSint: passive OSINT aggregator with pivoting and correlation.

Combines: Maigret, theHarvester, recon-ng, SpiderFoot, PhoneInfoga + XposedOrNot/HIBP breach check.
Missing tools are skipped (graceful degrade), so it always runs.

Usage:
    python main.py --username blackowl-zero --email me@example.com
    python main.py --domain example.com --depth 2 -o report.html
    python main.py --check-password 'to_diko_mou_password'   # k-anonymity util
    python main.py --email me@example.com --plain            # plain output (pipes/CI)

Authorized / educational use only. Passive recon. No credential testing.
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import sys

# load .env if python-dotenv is installed (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from core.models import Target
from core.normalizer import normalize
from core.orchestrator import Orchestrator
from core.correlator import correlate, summarize
from storage.db import Storage
from report import html_report
from ui import console as ui_console  # safe import: does not fail if rich is missing

from modules.breach_mod import BreachModule, check_password_pwned
from modules.xposed_mod import XposedModule
from modules.maigret_mod import MaigretModule
from modules.harvester_mod import HarvesterModule
from modules.reconng_mod import ReconngModule
from modules.spiderfoot_mod import SpiderfootModule
from modules.phoneinfoga_mod import PhoneInfogaModule


def build_modules():
    return [
        MaigretModule(),
        HarvesterModule(),
        ReconngModule(),
        SpiderfootModule(),
        PhoneInfogaModule(),
        # breach checks: free XposedOrNot first, then HIBP (only if a key is set)
        XposedModule(),
        BreachModule(),
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description="ZeroSint: passive recon aggregator")
    ap.add_argument("--name")
    ap.add_argument("--username")
    ap.add_argument("--email")
    ap.add_argument("--phone")
    ap.add_argument("--domain")
    ap.add_argument("--ip")
    ap.add_argument("--org")
    ap.add_argument("--depth", type=int, default=2, help="max pivot depth (default 2)")
    ap.add_argument("-o", "--output", default="zerosint_report.html")
    ap.add_argument("--json", default="zerosint_findings.json")
    ap.add_argument("--db", default="zerosint.db")
    ap.add_argument("--label", default=None, help="friendly name for the report")
    ap.add_argument("--check-password", metavar="PW",
                    help="k-anonymity password breach check (standalone util)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--plain", action="store_true",
                    help="plain text output, no Rich UI (for pipes, CI, logs)")
    args = ap.parse_args()

    # Rich UI by default; None = plain (--plain, not a TTY, or rich is missing)
    ui = ui_console.make_ui(plain=args.plain)
    level = logging.DEBUG if args.verbose else logging.INFO
    if ui is not None:
        ui.setup_logging(level)
    else:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)-7s %(message)s",
            datefmt="%H:%M:%S",
        )

    # standalone utility: check your own password with k-anonymity
    if args.check_password:
        n = check_password_pwned(args.check_password)
        if n < 0:
            print("Could not reach pwned-passwords API.")
        elif n == 0:
            print("Not found in known breaches.")
        else:
            print(f"Found {n:,} times in breaches. Change it.")
        return 0

    raw = {
        "name": args.name, "username": args.username, "email": args.email,
        "phone": args.phone, "domain": args.domain, "ip": args.ip, "org": args.org,
    }
    raw = {k: v for k, v in raw.items() if v}
    if not raw:
        ap.error("Provide at least one input (e.g. --username or --email).")

    label = args.label or next(iter(raw.values()))
    target = Target(label=label)
    target.seeds = normalize(raw)
    logging.info("Seeds: %s", ", ".join(f"{s.type}={s.value}" for s in target.seeds))

    if ui is not None:
        ui.header(label, target.seeds)
    orch = Orchestrator(
        build_modules(), max_depth=args.depth,
        progress_callback=ui.on_event if ui is not None else None,
    )
    with (ui.live_scan() if ui is not None else contextlib.nullcontext()):
        results = orch.run(target)
    results = correlate(results)
    summary = summarize(results)

    # persist
    store = Storage(args.db)
    scan_id = store.new_scan(label)
    store.save(scan_id, results, orch.edges)
    store.close()

    # reports
    html_report.export_json(results, args.json)
    html_report.export_html(results, orch.edges, summary, label, args.output)

    if ui is not None:
        try:
            ui.summary(results, summary, label, {
                "Report": args.output, "JSON": args.json,
                "DB": f"{args.db} (scan #{scan_id})",
            })
            return 0
        except Exception as e:  # noqa: BLE001 - UI error -> plain summary
            logging.warning("Rich summary failed (%s), falling back to plain.", e)
    _print_plain_summary(label, summary, args, scan_id)
    return 0


def _print_plain_summary(label: str, summary: dict, args, scan_id) -> None:
    print("\n" + "=" * 50)
    print(f"  Target : {label}")
    print(f"  Found  : {summary['total']} findings "
          f"(high={summary['by_tier']['high']} "
          f"med={summary['by_tier']['medium']} "
          f"low={summary['by_tier']['low']})")
    print(f"  Report : {args.output}")
    print(f"  JSON   : {args.json}")
    print(f"  DB     : {args.db} (scan #{scan_id})")
    print("=" * 50)


if __name__ == "__main__":
    sys.exit(main())
