"""
Orchestrator: the core of the tool. Pivot loop.

Keeps a queue of seeds. For each seed it finds the modules that accept it and
runs them. Any new finding (not seen before) goes back into the queue as a new
seed, up to max_depth. Without that limit the scan would never end.
"""
from __future__ import annotations

import logging
from collections import deque

from .models import Finding, Target
from .webmail import DOMAIN_TYPES, is_under, is_webmail
from modules.base import BaseModule

log = logging.getLogger("osint")


class Orchestrator:
    def __init__(
        self,
        modules: list[BaseModule],
        max_depth: int = 2,
        max_findings: int = 2000,
        progress_callback=None,
    ) -> None:
        self.modules = modules
        # optional UI hook: callback(event, *args). None = no change.
        self.progress_callback = progress_callback
        self.max_depth = max_depth
        self.max_findings = max_findings
        self.results: dict[str, Finding] = {}   # key -> Finding (deduped)
        self.edges: list[tuple[str, str]] = []  # (parent_node_id, child_node_id), unique
        self._edge_set: set[tuple[str, str]] = set()
        self.interrupted = False  # True after a Ctrl+C inside run()
        self._requested_domains: set[str] = set()
        self._webmail_logged: set[str] = set()

    def _notify(self, event: str, *args) -> None:
        """Notify the UI. A UI error must never break the scan."""
        if self.progress_callback is None:
            return
        try:
            self.progress_callback(event, *args)
        except Exception as e:  # noqa: BLE001
            log.debug("progress_callback error (ignored): %s", e)

    def _store(self, f: Finding) -> bool:
        """Store a finding. Return True if it is new."""
        if f.key in self.results:
            # already seen: keep the higher confidence
            existing = self.results[f.key]
            if f.confidence > existing.confidence:
                existing.confidence = f.confidence
            # record the new source for the correlator
            srcs = existing.meta.setdefault("all_sources", [existing.source])
            if f.source not in srcs:
                srcs.append(f.source)
            return False
        f.meta.setdefault("all_sources", [f.source])
        self.results[f.key] = f
        return True

    def _is_unrequested_webmail(self, f: Finding) -> bool:
        """The one place the webmail rule lives: a webmail domain (gmail.com,
        mail.gmail.com, ...) is dropped, whoever found it, unless the user asked
        for it (or a parent domain of it) with --domain."""
        if f.type not in DOMAIN_TYPES or not is_webmail(f.value):
            return False
        if any(is_under(f.value, d) for d in self._requested_domains):
            return False
        if f.value.lower() not in self._webmail_logged:
            self._webmail_logged.add(f.value.lower())
            log.info("Not scanning webmail domain %s (from %s)", f.value,
                     f.meta.get("derived_from") or f.parent or f.source)
        return True

    def run(self, target: Target) -> dict[str, Finding]:
        queue: deque[Finding] = deque()
        # domains the user typed (not derived from an email)
        self._requested_domains = {
            s.value for s in target.seeds
            if s.type in DOMAIN_TYPES and s.source == "input" and not s.meta.get("derived_from")
        }

        # queue the initial seeds
        for seed in target.seeds:
            if self._is_unrequested_webmail(seed):
                continue
            if self._store(seed):
                queue.append(seed)

        available = [m for m in self.modules if m.available()]
        skipped = [m.name for m in self.modules if not m.available()]
        if skipped:
            log.warning("Modules not available (graceful degrade): %s", ", ".join(skipped))
        log.info("Active modules: %s", ", ".join(m.name for m in available) or "none")

        try:
            processed = self._pivot(queue, available)
        except KeyboardInterrupt:
            # Ctrl+C: stop pivoting, keep everything found so far
            self.interrupted = True
            found = sum(1 for f in self.results.values() if f.source != "input")
            log.warning("Scan interrupted, keeping %d findings found so far.", found)
            return self.results

        log.info("Pivot done. processed_seeds=%d total_findings=%d",
                 processed, len(self.results))
        return self.results

    def _pivot(self, queue: deque[Finding], available: list[BaseModule]) -> int:
        """The pivot loop. Returns the number of processed seeds."""
        processed = 0
        while queue:
            if len(self.results) >= self.max_findings:
                log.warning("Reached max_findings=%d, stopping pivot.", self.max_findings)
                break

            seed = queue.popleft()
            if seed.depth >= self.max_depth:
                continue

            for mod in available:
                if not mod.handles(seed):
                    continue
                log.info("[depth %d] %s -> %s(%s)",
                         seed.depth, mod.name, seed.type, seed.value)
                self._notify("module_start", mod.name, seed)
                try:
                    found = mod.run(seed)
                except Exception as e:  # noqa: BLE001 - one module must not take down the run
                    log.error("[%s] crashed on %s: %s", mod.name, seed.value, e)
                    found = []

                for f in found:
                    if self._is_unrequested_webmail(f):
                        continue
                    self._notify("finding", f)
                    is_new = self._store(f)
                    # edge for the graph (parent seed -> finding)
                    edge = (seed.node_id, f.node_id)
                    if edge not in self._edge_set:
                        self._edge_set.add(edge)
                        self.edges.append(edge)
                    if is_new and f.depth < self.max_depth:
                        queue.append(f)
            processed += 1
        return processed
