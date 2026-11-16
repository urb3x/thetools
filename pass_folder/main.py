"""Entry point for FolderVault."""

from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from pathlib import Path

_APP_DIR = str(Path(__file__).resolve().parent)
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from app import FolderVaultApp


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
    _enable_windows_dpi_awareness()
    root = tk.Tk()
    FolderVaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
