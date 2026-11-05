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
SERVER_LABEL = "dev.incident-scout.serve"

Runner = Callable[..., Any]


def plist_path(label: str = LABEL) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def log_path() -> Path:
    return Path.home() / "Library" / "Logs" / "incident-scout.log"


def agent(
    project_dir: Path, config_path: Path, interval_minutes: int, command: str = "check"
) -> dict[str, Any]:
    """A periodic `scout check`, or with command="serve" the decision page kept running."""
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is not on PATH")
    path = os.pathsep.join(
        dict.fromkeys(
            [str(Path(uv).parent), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
        )
    )
    definition: dict[str, Any] = {
        "Label": LABEL if command == "check" else SERVER_LABEL,
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
            command,
        ],
        "RunAtLoad": True,
        "ProcessType": "Background",
        "EnvironmentVariables": {"PATH": path},
        "StandardOutPath": str(log_path()),
        "StandardErrorPath": str(log_path()),
    }
    if command == "check":
        definition["StartInterval"] = interval_minutes * 60
    if command != "check":
        definition["KeepAlive"] = True
    return definition


def install(
    project_dir: Path,
    config_path: Path,
    interval_minutes: int,
    runner: Runner | None = None,
    command: str = "check",
) -> Path:
    definition = agent(project_dir, config_path, interval_minutes, command)
    label = definition["Label"]
    target = plist_path(label)
    target.parent.mkdir(parents=True, exist_ok=True)
    log_path().parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(plistlib.dumps(definition))
    domain = f"gui/{os.getuid()}"
    run = runner or subprocess.run
    run(["/bin/launchctl", "bootout", f"{domain}/{label}"], check=False, capture_output=True)
    run(["/bin/launchctl", "bootstrap", domain, str(target)], check=True)
    return target


def uninstall(runner: Runner | None = None, label: str = LABEL) -> bool:
    target = plist_path(label)
    run = runner or subprocess.run
    run(
        ["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
        check=False,
        capture_output=True,
    )
    if not target.exists():
        return False
    target.unlink()
    return True
