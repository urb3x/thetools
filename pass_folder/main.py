"""Entry point for FolderVault."""

from __future__ import annotations

import ctypes
import sys
import tkinter as tk

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
