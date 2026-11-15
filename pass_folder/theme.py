"""Modern Dark/Light ttk theme manager and custom Tkinter widgets."""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from tkinter import ttk
from typing import Dict

from password_utils import PasswordAssessment


@dataclass(frozen=True)
class ThemePalette:
    """Color palette for the application UI."""

    name: str
    bg: str
    surface: str
    surface_alt: str
    border: str
    fg: str
    fg_muted: str
    accent: str
    accent_hover: str
    accent_fg: str
    success: str
    warning: str
    danger: str
    input_bg: str
    input_fg: str
    log_bg: str


DARK_PALETTE = ThemePalette(
    name="dark",
    bg="#0f172a",
    surface="#1e293b",
    surface_alt="#273449",
    border="#334155",
    fg="#f1f5f9",
    fg_muted="#94a3b8",
    accent="#6366f1",
    accent_hover="#4f46e5",
    accent_fg="#ffffff",
    success="#10b981",
    warning="#f59e0b",
    danger="#ef4444",
    input_bg="#0b1220",
    input_fg="#f8fafc",
    log_bg="#0b1220",
)

LIGHT_PALETTE = ThemePalette(
    name="light",
    bg="#f1f5f9",
    surface="#ffffff",
    surface_alt="#e2e8f0",
    border="#cbd5e1",
    fg="#0f172a",
    fg_muted="#475569",
    accent="#4f46e5",
    accent_hover="#4338ca",
    accent_fg="#ffffff",
    success="#059669",
    warning="#d97706",
    danger="#dc2626",
    input_bg="#f8fafc",
    input_fg="#0f172a",
    log_bg="#f8fafc",
)

PALETTES: Dict[str, ThemePalette] = {
    "dark": DARK_PALETTE,
    "light": LIGHT_PALETTE,
}


def apply_ttk_theme(root: tk.Tk, palette: ThemePalette) -> ttk.Style:
    """Configure ttk.Style('clam') with the given ThemePalette."""
    style = ttk.Style(root)
    style.theme_use("clam")

    root.configure(bg=palette.bg)

    style.configure(
        ".",
        background=palette.bg,
        foreground=palette.fg,
        fieldbackground=palette.input_bg,
        bordercolor=palette.border,
        font=("Segoe UI", 10),
    )

    style.configure("TFrame", background=palette.bg)
    style.configure("Card.TFrame", background=palette.surface, relief="flat")
    style.configure(
        "Card.TLabelframe",
        background=palette.surface,
        bordercolor=palette.border,
        relief="solid",
        borderwidth=1,
    )
    style.configure(
        "Card.TLabelframe.Label",
        background=palette.surface,
        foreground=palette.fg,
        font=("Segoe UI", 10, "bold"),
    )

    style.configure("TLabel", background=palette.bg, foreground=palette.fg)
    style.configure(
        "Title.TLabel",
        background=palette.bg,
        foreground=palette.fg,
        font=("Segoe UI", 16, "bold"),
    )
    style.configure(
        "Subtitle.TLabel",
        background=palette.bg,
        foreground=palette.fg_muted,
        font=("Segoe UI", 9),
    )
    style.configure(
        "Card.TLabel",
        background=palette.surface,
        foreground=palette.fg,
    )
    style.configure(
        "CardMuted.TLabel",
        background=palette.surface,
        foreground=palette.fg_muted,
        font=("Segoe UI", 9),
    )
    style.configure(
        "Mono.TLabel",
        background=palette.surface,
        foreground=palette.fg_muted,
        font=("Consolas", 9),
    )
    style.configure(
        "Badge.TLabel",
        background=palette.surface_alt,
        foreground=palette.fg,
        padding=(8, 3),
        font=("Segoe UI", 8, "bold"),
    )

    style.configure(
        "TEntry",
        fieldbackground=palette.input_bg,
        foreground=palette.input_fg,
        insertcolor=palette.fg,
        bordercolor=palette.border,
        lightcolor=palette.accent,
        darkcolor=palette.border,
        padding=(8, 6),
    )
    style.map(
        "TEntry",
        bordercolor=[("focus", palette.accent)],
        lightcolor=[("focus", palette.accent)],
    )

    style.configure(
        "TCombobox",
        fieldbackground=palette.input_bg,
        background=palette.surface_alt,
        foreground=palette.input_fg,
        arrowcolor=palette.fg,
        bordercolor=palette.border,
        padding=(6, 5),
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", palette.input_bg)],
        foreground=[("readonly", palette.input_fg)],
    )

    style.configure(
        "TButton",
        background=palette.surface_alt,
        foreground=palette.fg,
        bordercolor=palette.border,
        padding=(12, 7),
        font=("Segoe UI", 9, "bold"),
    )
    style.map(
        "TButton",
        background=[("active", palette.border), ("disabled", palette.surface)],
        foreground=[("disabled", palette.fg_muted)],
    )

    style.configure(
        "Accent.TButton",
        background=palette.accent,
        foreground=palette.accent_fg,
        bordercolor=palette.accent,
        padding=(16, 9),
        font=("Segoe UI", 10, "bold"),
    )
    style.map(
        "Accent.TButton",
        background=[("active", palette.accent_hover), ("disabled", palette.surface_alt)],
        foreground=[("disabled", palette.fg_muted)],
    )

    style.configure(
        "Danger.TButton",
        background=palette.danger,
        foreground="#ffffff",
        bordercolor=palette.danger,
        padding=(12, 8),
        font=("Segoe UI", 9, "bold"),
    )

    style.configure(
        "Card.TCheckbutton",
        background=palette.surface,
        foreground=palette.fg,
    )
    style.map(
        "Card.TCheckbutton",
        background=[("active", palette.surface)],
    )

    style.configure(
        "TNotebook",
        background=palette.bg,
        borderwidth=0,
        tabmargins=(0, 0, 0, 0),
    )
    style.configure(
        "TNotebook.Tab",
        background=palette.surface_alt,
        foreground=palette.fg_muted,
        padding=(18, 9),
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", palette.surface), ("active", palette.border)],
        foreground=[("selected", palette.fg), ("active", palette.fg)],
    )

    style.configure(
        "Accent.Horizontal.TProgressbar",
        troughcolor=palette.input_bg,
        background=palette.accent,
        bordercolor=palette.border,
        lightcolor=palette.accent,
        darkcolor=palette.accent,
        thickness=12,
    )

    return style


class PasswordStrengthBar(ttk.Frame):
    """Segmented visual password strength meter with live feedback."""

    def __init__(self, parent: tk.Misc, palette: ThemePalette) -> None:
        super().__init__(parent, style="Card.TFrame")
        self._palette = palette
        self._segments: list[int] = []

        self._canvas = tk.Canvas(
            self,
            height=8,
            bg=palette.surface,
            highlightthickness=0,
            bd=0,
        )
        self._canvas.pack(fill="x", expand=True, pady=(2, 4))
        self._canvas.bind("<Configure>", self._on_resize)

        info_row = ttk.Frame(self, style="Card.TFrame")
        info_row.pack(fill="x")
        self._label_var = tk.StringVar(value="Strength: Empty")
        self._feedback_var = tk.StringVar(value="")

        self._strength_lbl = ttk.Label(
            info_row,
            textvariable=self._label_var,
            style="Card.TLabel",
            font=("Segoe UI", 9, "bold"),
        )
        self._strength_lbl.pack(side="left")

        self._feedback_lbl = ttk.Label(
            info_row,
            textvariable=self._feedback_var,
            style="CardMuted.TLabel",
        )
        self._feedback_lbl.pack(side="right")

        self._last_score = 0
        self._draw_segments()

    def set_palette(self, palette: ThemePalette) -> None:
        self._palette = palette
        self._canvas.configure(bg=palette.surface)
        self._draw_segments()

    def update_assessment(self, assessment: PasswordAssessment) -> None:
        self._last_score = assessment.score
        self._label_var.set(f"Strength: {assessment.label}")
        self._feedback_var.set(assessment.feedback)
        self._draw_segments()

    def _on_resize(self, _event: tk.Event) -> None:
        self._draw_segments()

    def _draw_segments(self) -> None:
        self._canvas.delete("all")
        width = max(self._canvas.winfo_width(), 200)
        gap = 6
        seg_w = (width - gap * 3) / 4

        score_colors = {
            0: self._palette.surface_alt,
            1: self._palette.danger,
            2: self._palette.warning,
            3: "#38bdf8",
            4: self._palette.success,
        }
        active_color = score_colors.get(self._last_score, self._palette.surface_alt)

        for idx in range(4):
            x0 = idx * (seg_w + gap)
            x1 = x0 + seg_w
            fill = active_color if idx < self._last_score else self._palette.surface_alt
            self._canvas.create_rectangle(x0, 0, x1, 8, fill=fill, outline="")


class LogConsole(ttk.Frame):
    """Scrollable, color-tagged activity log widget."""

    def __init__(self, parent: tk.Misc, palette: ThemePalette) -> None:
        super().__init__(parent, style="Card.TFrame")
        self._palette = palette

        self._text = tk.Text(
            self,
            height=7,
            wrap="word",
            state="disabled",
            bg=palette.log_bg,
            fg=palette.fg,
            insertbackground=palette.fg,
            relief="flat",
            padx=10,
            pady=8,
            font=("Consolas", 9),
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)

        self._text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self._configure_tags()

    def _configure_tags(self) -> None:
        self._text.tag_configure("TIME", foreground=self._palette.fg_muted)
        self._text.tag_configure("INFO", foreground=self._palette.fg)
        self._text.tag_configure("SUCCESS", foreground=self._palette.success)
        self._text.tag_configure("WARN", foreground=self._palette.warning)
        self._text.tag_configure("ERROR", foreground=self._palette.danger)

    def set_palette(self, palette: ThemePalette) -> None:
        self._palette = palette
        self._text.configure(
            bg=palette.log_bg,
            fg=palette.fg,
            insertbackground=palette.fg,
        )
        self._configure_tags()

    def log(self, message: str, level: str = "INFO") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        tag = level.upper()
        if tag not in ("INFO", "SUCCESS", "WARN", "ERROR"):
            tag = "INFO"

        self._text.configure(state="normal")
        self._text.insert("end", f"[{ts}] ", "TIME")
        self._text.insert("end", f"{tag:<7} ", tag)
        self._text.insert("end", f"{message}\n", "INFO")
        self._text.see("end")
        self._text.configure(state="disabled")

    def clear(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")
