"""Entry point for FolderVault."""

from __future__ import annotations

import ctypes
import importlib
import importlib.util
import subprocess
import sys
import tkinter as tk
from pathlib import Path

_APP_DIR = str(Path(__file__).resolve().parent)
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)


def _ensure_dependencies() -> None:
    """Install required third-party packages automatically if missing."""
    if importlib.util.find_spec("cryptography") is not None:
        return
    req_file = Path(__file__).resolve().parent / "requirements.txt"
    cmd = [sys.executable, "-m", "pip", "install"]
    if req_file.is_file():
        cmd.extend(["-r", str(req_file)])
    else:
        cmd.append("cryptography>=42.0.0")
    try:
        subprocess.run(cmd, check=False)
        importlib.invalidate_caches()
    except OSError:
        pass


def _enable_windows_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main() -> None:
    _ensure_dependencies()
    from app import FolderVaultApp

    _enable_windows_dpi_awareness()
    root = tk.Tk()
    FolderVaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
