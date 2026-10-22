"""
Rich terminal UI for ZeroSint.

ALL rich code lives HERE. The core knows nothing about the UI; it only
calls an optional progress_callback(event, *args).

If rich is not installed, this module still imports and make_ui() returns
None -> main.py falls back to plain output.
The tool must NEVER crash because rich is missing.
"""
from __future__ import annotations

import contextlib
import logging
import sys

try:
    from rich import box
    from rich.console import Console, Group
    from rich.live import Live
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.spinner import Spinner
    from rich.style import Style
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:  # no rich -> plain mode
    RICH_AVAILABLE = False

TIER_STYLE = {"high": "bold green", "medium": "yellow", "low": "grey50"}
TOP_N = 50  # how many findings the final table shows (the rest are in the report)


def make_ui(plain: bool = False):
    """
    Returns RichUI or None (= plain output).
    Plain when: --plain, stdout is not a TTY (pipe/CI/log), or rich is missing.
    """
    if plain or not RICH_AVAILABLE:
        return None
    try:
        if not sys.stdout.isatty():
            return None
    except (AttributeError, ValueError):
        return None
    return RichUI()


def _short(value: str, width: int) -> str:
    """Truncate long values to fit an 80-column terminal."""
    value = str(value)
    return value if len(value) <= width else value[: width - 3] + "..."


class _LiveView:
    """
    The Live renderable. rich redraws it on its own (auto refresh), so the
    spinner keeps moving even when a module blocks for a long time.
    """

    def __init__(self) -> None:
        self.spinner = Spinner("dots", text="starting...", style="cyan")
        self.counts: dict[str, int] = {}
        self.seen: set[str] = set()   # unique findings (same key as the orchestrator)
        self.modules_run = 0

    def module_start(self, module: str, seed) -> None:
        self.modules_run += 1
        self.spinner.update(text=Text.assemble(
            (module, "bold cyan"), " -> ",
            (f"{seed.type}", "magenta"), "(", _short(seed.value, 40), ")",
        ))

    def finding(self, f) -> None:
        if f.key in self.seen:
            return
        self.seen.add(f.key)
        self.counts[f.type] = self.counts.get(f.type, 0) + 1

    def __rich__(self):
        counts = Table(box=box.SIMPLE, show_header=True, header_style="bold",
                       pad_edge=False, min_width=30)
        counts.add_column("Type")
        counts.add_column("Found", justify="right")
        for t, n in sorted(self.counts.items(), key=lambda kv: -kv[1]):
            counts.add_row(t, str(n))
        counts.add_row(Text("total", style="bold"),
                       Text(str(sum(self.counts.values())), style="bold"))
        return Panel(
            Group(self.spinner, counts),
            title=f"Scanning: {self.modules_run} module runs",
            border_style="cyan", expand=False,
        )


class RichUI:
    def __init__(self) -> None:
        self.console = Console()
        self.view = _LiveView()

    # ---- logging ----
    def setup_logging(self, level: int) -> None:
        """Logging via RichHandler, on the same console as the Live view (prints above it)."""
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="%H:%M:%S",
            handlers=[RichHandler(console=self.console, show_path=False,
                                  markup=False, rich_tracebacks=False)],
        )

    # ---- header ----
    def header(self, label: str, seeds) -> None:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="magenta", no_wrap=True)
        grid.add_column(overflow="fold")
        for s in seeds:
            grid.add_row(str(s.type), _short(s.value, 60))
        note = Text("passive recon | authorized use only", style="grey50")
        self.console.print(Panel(
            Group(grid, note),
            title=Text(f"ZeroSint: {_short(label, 50)}", style="bold"),
            border_style="blue", expand=False,
        ))

    # ---- live progress ----
    def on_event(self, event: str, *args) -> None:
        """The progress_callback passed to the Orchestrator."""
        if event == "module_start":
            self.view.module_start(*args)
        elif event == "finding":
            self.view.finding(*args)

    def live_scan(self):
        """Context manager: shows the live panel while the scan runs."""
        try:
            return Live(self.view, console=self.console,
                        refresh_per_second=8, transient=False)
        except Exception:  # noqa: BLE001 - a UI error must not break the scan
            return contextlib.nullcontext()

    # ---- final summary ----
    def summary(self, results: dict, summary: dict, label: str,
                outputs: dict[str, str]) -> None:
        tiers = summary["by_tier"]
        head = Text.assemble(
            ("Target  ", "bold"), _short(label, 50), "\n",
            ("Found   ", "bold"), (str(summary["total"]), "bold"), " findings  ",
            (f"high={tiers['high']}", TIER_STYLE["high"]), "  ",
            (f"medium={tiers['medium']}", TIER_STYLE["medium"]), "  ",
            (f"low={tiers['low']}", TIER_STYLE["low"]),
        )
        if summary["by_type"]:
            head.append("\n")
            head.append("By type ", style="bold")
            head.append("  ".join(f"{t}={n}" for t, n in
                                  sorted(summary["by_type"].items(), key=lambda kv: -kv[1])))
        for name, path in outputs.items():
            head.append("\n")
            head.append(f"{name:<8}", style="bold")
            head.append(str(path))
        self.console.print(Panel(head, title="Summary", border_style="green", expand=False))

        findings = sorted(
            (f for f in results.values() if f.source != "input"),
            key=lambda f: -f.confidence,
        )
        if not findings:
            self.console.print("[grey50]No findings.[/]")
            return

        table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False,
                      title="Top findings (by confidence)", title_justify="left")
        # fixed widths for the small columns; Value gets the rest (80 cols -> ~18)
        widths = {"type": 12, "sources": 13, "conf": 11, "seed": 14}
        value_w = max(16, self.console.width - sum(widths.values()) - 12)
        table.add_column("Type", style="magenta", no_wrap=True, overflow="ellipsis",
                         width=widths["type"])
        table.add_column("Value", no_wrap=True, overflow="ellipsis", max_width=value_w)
        table.add_column("Sources", no_wrap=True, overflow="ellipsis", max_width=widths["sources"])
        table.add_column("Conf", no_wrap=True, justify="right", width=widths["conf"])
        table.add_column("From seed", no_wrap=True, overflow="ellipsis", max_width=widths["seed"])

        for f in findings[:TOP_N]:
            tier = f.meta.get("tier", "low")
            if f.type == "profile_url":
                # show the URL and make it clickable in terminals that support it
                value = Text(f.value, style=Style(color="blue", underline=True, link=f.value))
            else:
                value = Text(f.value)
            sources = ",".join(f.meta.get("all_sources", [f.source]))
            conf = Text(f"{f.confidence:.2f} {tier}", style=TIER_STYLE.get(tier, ""))
            table.add_row(f.type, value, sources, conf, f.parent or "")
        self.console.print(table)
        if len(findings) > TOP_N:
            self.console.print(
                f"[grey50]... {len(findings) - TOP_N} more in {outputs.get('Report', 'the report')}[/]"
            )
