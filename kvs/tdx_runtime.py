from __future__ import annotations

import os


def is_running_in_tdx_guest() -> bool:
    # Heuristic checks for common Linux TDX guest interfaces.
    tdx_paths = (
        "/dev/tdx_guest",
        "/sys/class/misc/tdx_guest",
        "/sys/devices/virtual/misc/tdx_guest",
        "/sys/firmware/tdx",
    )
    if any(os.path.exists(path) for path in tdx_paths):
        return True

    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as fp:
            cpuinfo = fp.read().lower()
    except OSError:
        return False

    return "tdx_guest" in cpuinfo


def enforce_tdx_requirement(require_tdx: bool) -> None:
    if not require_tdx:
        return
    if is_running_in_tdx_guest():
        return
    raise RuntimeError(
        "require_tdx=true but TDX guest environment was not detected. "
        "Run this process inside a TDX VM guest or set require_tdx=false."
    )
