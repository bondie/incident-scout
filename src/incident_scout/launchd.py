"""Run `scout check` periodically as a macOS LaunchAgent.

launchd (unlike cron) runs a missed interval once the Mac wakes up, and never starts a second
instance while the previous check is still running.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

LABEL = "dev.incident-scout.check"

Runner = Callable[..., Any]


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def log_path() -> Path:
    return Path.home() / "Library" / "Logs" / "incident-scout.log"


def agent(project_dir: Path, config_path: Path, interval_minutes: int) -> dict[str, Any]:
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is not on PATH")
    path = os.pathsep.join(
        dict.fromkeys(
            [str(Path(uv).parent), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
        )
    )
    return {
        "Label": LABEL,
        "ProgramArguments": [
            uv,
            "--directory",
            str(project_dir),
            "run",
            "--frozen",
            "--quiet",
            "scout",
            "--config",
            str(config_path),
            "check",
        ],
        "StartInterval": interval_minutes * 60,
        "RunAtLoad": True,
        "ProcessType": "Background",
        "EnvironmentVariables": {"PATH": path},
        "StandardOutPath": str(log_path()),
        "StandardErrorPath": str(log_path()),
    }


def install(
    project_dir: Path, config_path: Path, interval_minutes: int, runner: Runner = subprocess.run
) -> Path:
    target = plist_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    log_path().parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(plistlib.dumps(agent(project_dir, config_path, interval_minutes)))
    domain = f"gui/{os.getuid()}"
    runner(["/bin/launchctl", "bootout", f"{domain}/{LABEL}"], check=False, capture_output=True)
    runner(["/bin/launchctl", "bootstrap", domain, str(target)], check=True)
    return target


def uninstall(runner: Runner = subprocess.run) -> bool:
    target = plist_path()
    runner(
        ["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"],
        check=False,
        capture_output=True,
    )
    if not target.exists():
        return False
    target.unlink()
    return True
