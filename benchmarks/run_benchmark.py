#!/usr/bin/env python3
"""
zerosint benchmark: run zerosint on a fixed set of targets and measure

  * errors: tracebacks, module crashes, timeouts, exec/request/HTTP/parse
    errors, exhausted retries, non-zero exits. Counted from the scan's log
    output and exit codes, never by eye.
  * false positives: findings that do not belong to the target. Some are
    flagged automatically by objective rules (webmail domains that were not
    asked for and everything found under them, <SFURL>-wrapped values,
    duplicate rows). The rest need the owner's verdict ("mine" / "not_mine"),
    so no false-positive number is produced until every finding is reviewed.

zerosint's own outputs (report, JSON, db) go to a temp dir that is deleted
after each target. Only the results file you name is written.

Usage (inside WSL):
  python benchmarks/run_benchmark.py run --repo PATH --gmail ADDR --label main \
      --out benchmarks/baseline_main.json [--python PATH] [--depth 2]
  python benchmarks/run_benchmark.py review RESULTS [RESULTS...] --out review.md
  python benchmarks/run_benchmark.py score RESULTS --verdicts benchmarks/verdicts.json
  python benchmarks/run_benchmark.py compare BEFORE AFTER

The results files hold scan data about real people (your own accounts), so
benchmarks/*.json is git-ignored.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

USERNAMES = ["target-user-a", "target-user-b"]

# Kept here (not imported from zerosint) so old and new code are measured
# with exactly the same rule.
FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.gr", "ymail.com",
    "hotmail.com", "hotmail.gr", "outlook.com", "outlook.com.gr", "live.com",
    "msn.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.de", "gmx.net", "yandex.com",
    "yandex.ru", "mail.ru", "zoho.com", "tutanota.com", "tuta.io", "otenet.gr",
    "windowslive.com",
})

NETWORK_PROBES = [
    "https://api.xposedornot.com/",
    "https://github.com",
    "https://crt.sh",
    "https://api.pwnedpasswords.com/range/00000",
]

# (category, regex on one log line). First match wins.
ERROR_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("module_crash", re.compile(r"\] crashed on ")),
    ("rate_limit_exhausted", re.compile(r"still rate limited", re.I)),
    ("timeout", re.compile(r"\btimeout\b|timed out|did not start in time", re.I)),
    ("exec_error", re.compile(r"binary not found|exec error|could not start|server exited early"
                              r"|module not installed|no output file", re.I)),
    ("request_error", re.compile(r"request error|API/JSON error|pwned-passwords error"
                                 r"|liveness check error", re.I)),
    ("http_error", re.compile(r"\bHTTP \d{3}\b")),
    ("parse_error", re.compile(r"parse error|could not parse|bad JSON|unexpected JSON"
                               r"|db read error|no e164", re.I)),
]
LEVEL_RE = re.compile(r"^\d\d:\d\d:\d\d (WARNING|ERROR|CRITICAL)\s+(.*)$")
MODULE_RE = re.compile(r"\[([A-Za-z][\w.-]*)\]")
RUN_RE = re.compile(r"\[depth (\d+)\] (\S+) -> (\w+)\((.*)\)\s*$")
# not errors: expected, informative warnings
BENIGN_RE = re.compile(r"graceful degrade|Reached max_findings|dead-link filtering skipped"
                       r"|Scan interrupted|Rich summary failed", re.I)


# ---------------------------------------------------------------- helpers
def is_webmail(value: str) -> bool:
    v = value.strip().lower().rstrip(".")
    return any(v == d or v.endswith("." + d) for d in FREEMAIL_DOMAINS)


def finding_key(f: dict) -> str:
    """Same identity a person reading the report would use: type + value
    (+ account for breaches, which are per account)."""
    key = f"{f['type']}:{str(f['value']).strip().lower()}"
    account = (f.get("meta") or {}).get("account")
    if f["type"] == "breach" and account:
        key += f"#{str(account).strip().lower()}"
    return key


def reported(findings: list[dict]) -> list[dict]:
    """The rows zerosint reports (it hides source == 'input')."""
    return [f for f in findings if f.get("source") != "input"]


# ---------------------------------------------------------------- errors
def classify_log(text: str) -> dict:
    by_category: dict[str, int] = {}
    by_module: dict[str, int] = {}
    events: list[dict] = []

    def add(cat: str, module: str, line: str) -> None:
        by_category[cat] = by_category.get(cat, 0) + 1
        by_module[module] = by_module.get(module, 0) + 1
        events.append({"category": cat, "module": module, "line": line.strip()[:300]})

    for line in text.splitlines():
        if line.startswith("Traceback (most recent call last)"):
            add("traceback", "(none)", line)
            continue
        m = LEVEL_RE.match(line)
        if not m:
            continue
        level, msg = m.groups()
        if BENIGN_RE.search(msg):
            continue
        mod = MODULE_RE.search(msg)
        module = mod.group(1) if mod else "(none)"
        cat = next((c for c, rx in ERROR_PATTERNS if rx.search(msg)), None)
        if cat is None:
            cat = "other_error" if level in ("ERROR", "CRITICAL") else "other_warning"
        add(cat, module, line)
    return {"total": sum(by_category.values()), "by_category": by_category,
            "by_module": by_module, "events": events}


def webmail_module_runs(text: str, requested_domains: set[str]) -> dict[str, int]:
    """Module runs started on a webmail domain nobody asked for."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        m = RUN_RE.search(line)
        if not m:
            continue
        _depth, module, type_, value = m.groups()
        if type_ in DOMAIN_TYPES and is_webmail(value) and not _requested(value, requested_domains):
            out[module] = out.get(module, 0) + 1
    return out


# same rule as zerosint's orchestrator: these types name a domain, and a
# subdomain of a domain the user asked for counts as asked for
DOMAIN_TYPES = ("domain", "subdomain", "host")


def _requested(value: str, requested_domains: set[str]) -> bool:
    v = value.strip().lower().rstrip(".")
    return any(v == d or v.endswith("." + d) for d in requested_domains)


# ---------------------------------------------------------------- false positives
def auto_flags(findings: list[dict], requested_domains: set[str]) -> dict[str, list[str]]:
    """Objective false-positive rules. Returns {rule: [finding_key, ...]}, one entry
    per false-positive row (for duplicates: every copy after the first)."""
    # parent links are values; resolve them by (value) among non-leaf types first
    by_value: dict[str, dict] = {}
    for f in findings:
        by_value.setdefault(str(f["value"]).strip().lower(), f)

    def under_unrequested_webmail(f: dict) -> bool:
        seen = set()
        parent = f.get("parent")
        while parent and parent.strip().lower() not in seen:
            p = parent.strip().lower()
            seen.add(p)
            if is_webmail(p) and "@" not in p and not _requested(p, requested_domains):
                return True
            parent = (by_value.get(p) or {}).get("parent")
        return False

    rows = reported(findings)
    flags: dict[str, list[str]] = {"webmail_domain": [], "webmail_noise": [],
                                   "sfurl": [], "duplicate": []}
    for f in rows:
        k = finding_key(f)
        v = str(f["value"]).strip().lower()
        if f["type"] in DOMAIN_TYPES and is_webmail(v) and not _requested(v, requested_domains) \
                and not under_unrequested_webmail(f):
            flags["webmail_domain"].append(k)
        elif under_unrequested_webmail(f):
            flags["webmail_noise"].append(k)
        if "<sfurl>" in v:
            flags["sfurl"].append(k)

    # duplicate rows a reader sees as "the same thing twice":
    #  - the same breach for an email and for the username cut from it (bob, bob@x)
    #  - the same value reported twice under the same key (kept for safety)
    breaches: dict[str, set[str]] = {}
    for f in rows:
        if f["type"] == "breach":
            acct = str((f.get("meta") or {}).get("account") or "").strip().lower()
            breaches.setdefault(str(f["value"]).strip().lower(), set()).add(acct)
    for name, accounts in breaches.items():
        for a in accounts:
            if "@" not in a and any(b.split("@", 1)[0] == a for b in accounts if "@" in b):
                flags["duplicate"].append(f"breach:{name}#{a}")
    seen_keys: set[str] = set()
    for f in rows:
        k = finding_key(f)
        if k in seen_keys:
            flags["duplicate"].append(k)
        seen_keys.add(k)
    return flags


VERDICTS = ("mine", "not_mine")


def score_target(findings: list[dict], verdicts: dict[str, str],
                 requested_domains: set[str]) -> dict:
    bad = {k: v for k, v in verdicts.items() if v not in VERDICTS}
    if bad:
        raise ValueError(f"verdicts must be one of {VERDICTS}, got: {bad}")
    flags = auto_flags(findings, requested_domains)
    rows = reported(findings)
    keys = [finding_key(f) for f in rows]
    # one false positive per flagged row; a row flagged by two rules counts once
    auto_rows = {k for rule in ("webmail_domain", "webmail_noise", "sfurl") for k in flags[rule]}
    dup_extra = len(flags["duplicate"])
    not_mine = {k for k in keys if verdicts.get(k) == "not_mine"} - auto_rows
    unreviewed = sorted({k for k in keys if k not in verdicts and k not in auto_rows})
    return {
        "rows": len(rows),
        "auto_flags": {k: len(v) for k, v in flags.items()},
        "not_mine": len(not_mine),
        "unreviewed": len(unreviewed),
        "unreviewed_keys": unreviewed,
        "false_positives": None if unreviewed else len(auto_rows) + len(not_mine) + dup_extra,
    }


def target_reliable(t: dict) -> tuple[bool, str]:
    """Was this target's run complete enough to be counted?"""
    if t.get("timed_out"):
        return False, "scan timed out (findings file missing or incomplete)"
    if t.get("exit_code") not in (0,):
        return False, f"zerosint exited with {t.get('exit_code')}"
    if t.get("findings_file_ok") is False:
        return False, "no findings file written"
    return True, ""


def reduction(before, after):
    """(before - after) / before * 100, or None when it cannot be computed."""
    if before is None or after is None or before == 0:
        return None
    return round((before - after) / before * 100, 1)


# ---------------------------------------------------------------- running
def network_check() -> dict:
    import requests
    out = {}
    for url in NETWORK_PROBES:
        try:
            out[url] = requests.get(url, timeout=10).status_code
        except requests.RequestException as e:
            out[url] = f"error: {type(e).__name__}"
    return out


def targets(gmail: str) -> list[dict]:
    t = [{"name": f"username:{u}", "args": ["--username", u], "requested_domains": []}
         for u in USERNAMES]
    t.append({"name": "email:webmail", "args": ["--email", gmail], "requested_domains": []})
    return t


def run_target(python: str, repo: str, target: dict, depth: int, timeout: int) -> dict:
    work = tempfile.mkdtemp(prefix="zerosint_bench_")
    try:
        cmd = [python, "main.py", *target["args"], "--depth", str(depth), "--plain",
               "-o", os.path.join(work, "report.html"),
               "--json", os.path.join(work, "findings.json"),
               "--db", os.path.join(work, "scan.db")]
        t0 = time.monotonic()
        timed_out = False
        try:
            p = subprocess.run(cmd, cwd=repo, stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=timeout,
                               env={**os.environ, "PYTHONUNBUFFERED": "1"})
            rc, log = p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired as e:
            timed_out, rc = True, None
            log = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes)
                   else (e.stdout or "")) + ((e.stderr or b"").decode(errors="replace")
                                              if isinstance(e.stderr, bytes) else (e.stderr or ""))
        duration = round(time.monotonic() - t0, 1)
        try:
            with open(os.path.join(work, "findings.json"), encoding="utf-8") as fh:
                findings = json.load(fh)
            findings_ok = True
        except (OSError, ValueError):
            findings, findings_ok = [], False
    finally:
        shutil.rmtree(work, ignore_errors=True)

    requested = set(target["requested_domains"])
    errors = classify_log(log)
    if timed_out:
        errors["by_category"]["scan_timeout"] = 1
        errors["total"] += 1
    elif rc not in (0,):
        errors["by_category"]["nonzero_exit"] = 1
        errors["total"] += 1
    return {
        "name": target["name"], "args_kind": target["name"].split(":")[0],
        "exit_code": rc, "timed_out": timed_out, "duration_s": duration,
        "findings_file_ok": findings_ok, "errors": errors,
        "webmail_module_runs": webmail_module_runs(log, requested),
        "requested_domains": sorted(requested),
        "findings": [{k: f.get(k) for k in ("type", "value", "source", "parent", "depth",
                                             "confidence", "meta")} for f in findings],
        "log": log,
    }


def cmd_run(a) -> int:
    repo = os.path.abspath(a.repo)
    python = a.python or os.path.join(repo, ".venv", "bin", "python")
    commit = a.commit or subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                                        capture_output=True, text=True).stdout.strip()
    tools = {b: shutil.which(b) for b in ("maigret", "theHarvester", "recon-cli", "spiderfoot",
                                          "sf.py", "phoneinfoga")}
    print(f"[bench] tools on PATH: {tools}", flush=True)
    res = {"label": a.label, "repo": repo, "commit": commit, "depth": a.depth,
           "tools": tools, "started": datetime.now(timezone.utc).isoformat(),
           "network_before": network_check(), "targets": []}
    for t in targets(a.gmail):
        print(f"[bench] {a.label}: {t['name']} ...", flush=True)
        r = run_target(python, repo, t, a.depth, a.timeout)
        print(f"[bench]   exit={r['exit_code']} {r['duration_s']}s errors={r['errors']['total']} "
              f"rows={len(reported(r['findings']))}", flush=True)
        res["targets"].append(r)
    res["network_after"] = network_check()
    res["finished"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=2)
    print(f"[bench] wrote {a.out}")
    return 0


# ---------------------------------------------------------------- review / score / compare
def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def cmd_review(a) -> int:
    """List every reported finding (union of all results) for the owner to judge."""
    seen: dict[str, dict] = {}
    for path in a.results:
        res = _load(path)
        for t in res["targets"]:
            flags = auto_flags(t["findings"], set(t["requested_domains"]))
            auto = {k: rule for rule, ks in flags.items() for k in ks}
            for f in reported(t["findings"]):
                k = finding_key(f)
                e = seen.setdefault(k, {"f": f, "targets": set(), "runs": set(), "auto": auto.get(k)})
                e["targets"].add(t["name"])
                e["runs"].add(res["label"])
    lines = ["| # | type | value | from | target | runs | auto-flag |", "|---|---|---|---|---|---|---|"]
    index = {}
    for i, (k, e) in enumerate(sorted(seen.items(), key=lambda kv: (kv[1]["f"]["type"], kv[0])), 1):
        f = e["f"]
        index[i] = k
        lines.append(f"| {i} | {f['type']} | {str(f['value'])[:90]} | {f.get('parent') or ''} | "
                     f"{', '.join(sorted(e['targets']))} | {', '.join(sorted(e['runs']))} | "
                     f"{e['auto'] or ''} |")
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(a.out + ".index.json", "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2)
    print(f"[bench] {len(seen)} findings to review -> {a.out}")
    return 0


def cmd_score(a) -> int:
    verdicts = _load(a.verdicts) if a.verdicts and os.path.exists(a.verdicts) else {}
    res = _load(a.results)
    for t in res["targets"]:
        t["score"] = score_target(t["findings"], verdicts, set(t["requested_domains"]))
    with open(a.results, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=2)
    for t in res["targets"]:
        s = t["score"]
        print(f"{t['name']}: rows={s['rows']} fp={s['false_positives']} "
              f"unreviewed={s['unreviewed']} auto={s['auto_flags']}")
    return 0


def _sum(values):
    vals = list(values)
    return None if any(v is None for v in vals) else sum(vals)


def cmd_compare(a) -> int:
    A, B = _load(a.before), _load(a.after)

    def totals(res):
        cats: dict[str, int] = {}
        mods: dict[str, int] = {}
        for t in res["targets"]:
            for c, n in t["errors"]["by_category"].items():
                cats[c] = cats.get(c, 0) + n
            for m, n in t["errors"]["by_module"].items():
                mods[m] = mods.get(m, 0) + n
        fp = _sum((t.get("score") or {}).get("false_positives") for t in res["targets"])
        webmail = sum(sum(t["webmail_module_runs"].values()) for t in res["targets"])
        return {"errors": sum(cats.values()), "cats": cats, "mods": mods, "fp": fp,
                "webmail_runs": webmail}

    ta, tb = totals(A), totals(B)
    notes = []
    for label, res in (("before", A), ("after", B)):
        for when in ("network_before", "network_after"):
            bad = {u: s for u, s in res[when].items() if s != 200}
            if bad:
                notes.append(f"{label} {when}: unreachable/non-200 {bad}")
    # a target whose run did not complete on either side makes every total unreliable
    broken = []
    for t1, t2 in zip(A["targets"], B["targets"]):
        for label, t in (("before", t1), ("after", t2)):
            ok, why = target_reliable(t)
            if not ok:
                broken.append(t["name"])
                notes.append(f"{label} {t['name']}: {why}")
    rate_limited = ta["cats"].get("rate_limit_exhausted", 0) or tb["cats"].get("rate_limit_exhausted", 0)
    if rate_limited:
        notes.append("rate limits hit: error counts depend on API quota, not on the code")
    unreliable_totals = bool(broken) or bool(rate_limited)

    def row(name, b, c, unreliable=False):
        fmt = lambda v: "not measured" if v is None else str(v)  # noqa: E731
        if unreliable:
            pct = "not reliably measurable"
        elif b == 0 and c and c > 0:
            pct = f"increase (0 -> {c})"
        else:
            r = reduction(b, c)
            pct = "n/a" if r is None else f"{r}%" + (" (small base)" if b is not None and b < 5 else "")
        return f"| {name} | {fmt(b)} | {fmt(c)} | {pct} |"

    out = [f"before: {A['label']} @ {A['commit'][:7]}   after: {B['label']} @ {B['commit'][:7]}", "",
           "| metric | before | after | reduction |", "|---|---|---|---|",
           row("errors (total)", ta["errors"], tb["errors"], unreliable_totals),
           row("false positives (total)", ta["fp"], tb["fp"], bool(broken)),
           row("module runs on webmail domains", ta["webmail_runs"], tb["webmail_runs"],
               bool(broken)), "",
           "| error category | before | after | reduction |", "|---|---|---|---|"]
    for c in sorted(set(ta["cats"]) | set(tb["cats"])):
        out.append(row(c, ta["cats"].get(c, 0), tb["cats"].get(c, 0), unreliable_totals))
    out += ["", "| errors by module | before | after | reduction |", "|---|---|---|---|"]
    for m in sorted(set(ta["mods"]) | set(tb["mods"])):
        out.append(row(m, ta["mods"].get(m, 0), tb["mods"].get(m, 0), unreliable_totals))
    out += ["", "| per target | errors before | errors after | FP before | FP after | FP reduction |",
            "|---|---|---|---|---|---|"]
    for t1, t2 in zip(A["targets"], B["targets"]):
        s1, s2 = t1.get("score") or {}, t2.get("score") or {}
        f1, f2 = s1.get("false_positives"), s2.get("false_positives")
        pct = row("", f1, f2, t1["name"] in broken).rsplit("|", 2)[-2].strip()
        out.append(f"| {t1['name']} | {t1['errors']['total']} | {t2['errors']['total']} | "
                   f"{f1} | {f2} | {pct} |")
    if notes:
        out += ["", "Reliability notes:"] + [f"- {n}" for n in notes]
    print("\n".join(out))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--repo", required=True, help="zerosint checkout to benchmark")
    r.add_argument("--gmail", required=True, help="gmail address for the webmail scenario")
    r.add_argument("--label", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--python", help="interpreter (default: <repo>/.venv/bin/python)")
    r.add_argument("--commit", help="commit id to record (when git can't read the checkout)")
    r.add_argument("--depth", type=int, default=2)
    r.add_argument("--timeout", type=int, default=3600, help="seconds per target")
    rv = sub.add_parser("review")
    rv.add_argument("results", nargs="+")
    rv.add_argument("--out", required=True)
    s = sub.add_parser("score")
    s.add_argument("results")
    s.add_argument("--verdicts")
    c = sub.add_parser("compare")
    c.add_argument("before")
    c.add_argument("after")
    a = ap.parse_args()
    return {"run": cmd_run, "review": cmd_review, "score": cmd_score, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
