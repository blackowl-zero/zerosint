"""
BaseModule: the interface every wrapper implements (Maigret, theHarvester...).

Rules:
- `accepts` = the seed types the module accepts.
- `run(seed)` = does the work and returns list[Finding].
- If the external tool is NOT installed, the module degrades gracefully
  (returns [] and logs a warning) and does NOT crash the program.
"""
from __future__ import annotations

import logging
import shutil
import subprocess

from core.models import Finding

log = logging.getLogger("osint")


class BaseModule:
    name: str = "base"
    accepts: set[str] = set()
    # name of the external binary it needs (None = pure python)
    requires_binary: str | None = None

    def available(self) -> bool:
        """Is this module available on this system?"""
        if self.requires_binary is None:
            return True
        return shutil.which(self.requires_binary) is not None

    def handles(self, seed: Finding) -> bool:
        return seed.type in self.accepts

    def run(self, seed: Finding) -> list[Finding]:
        raise NotImplementedError

    # ---- subprocess helper with timeout ----
    def _exec(self, cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        log.debug("[%s] exec: %s", self.name, " ".join(cmd))
        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            log.warning("[%s] timeout (%ss): %s", self.name, timeout, cmd[0])
            return -1, "", "timeout"
        except FileNotFoundError:
            log.warning("[%s] binary not found: %s", self.name, cmd[0])
            return -1, "", "not found"
        except Exception as e:  # noqa: BLE001
            log.warning("[%s] exec error: %s", self.name, e)
            return -1, "", str(e)
