"""Advanced Tkinter GUI for folder encryption and password protection."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

_CRYPTO_IMPORT_ERROR: Optional[str] = None
try:
    from crypto_engine import (
        CompressionLevel,
        CryptoError,
        KdfType,
        OperationResult,
        decrypt_vault,
        encrypt_folder,
        inspect_vault,
        scan_folder,
        verify_vault,
    )
    CRYPTO_AVAILABLE = True
except ModuleNotFoundError as exc:
    CRYPTO_AVAILABLE = False
    _CRYPTO_IMPORT_ERROR = str(exc)

    class CryptoError(Exception):
        pass

    class KdfType:
        ARGON2ID = "argon2id"
        PBKDF2_SHA256 = "pbkdf2_sha256"

    class CompressionLevel:
        BALANCED = 6
        FAST = 1
        MAXIMUM = 9
        NONE = 0

    OperationResult = object  # type: ignore[misc,assignment]
from password_utils import evaluate_password, format_bytes, generate_strong_password
from theme import PALETTES, LogConsole, PasswordStrengthBar, apply_ttk_theme
from timestamp_utils import (
    TimestampError,
    format_timestamp,
    get_file_timestamps,
    parse_timestamp,
    spoof_directory_tree,
    spoof_file_timestamps,
)

KDF_CHOICES = {
    "Argon2id (Recommended, Memory-Hard)": KdfType.ARGON2ID,
    "PBKDF2-HMAC-SHA256 (600,000 iter)": KdfType.PBKDF2_SHA256,
}

COMPRESSION_CHOICES = {
    "Balanced (Deflate-6)": CompressionLevel.BALANCED,
    "Fast (Deflate-1)": CompressionLevel.FAST,
    "Maximum (Deflate-9)": CompressionLevel.MAXIMUM,
    "Store Only (No Compression)": CompressionLevel.NONE,
}


class FolderVaultApp:
    """Main application window for FolderVault."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FolderVault — AES-256-GCM Folder Encryptor")
        self.root.geometry("860x780")
        self.root.minsize(760, 680)

        self._theme_name = "dark"
        self._palette = PALETTES[self._theme_name]
        apply_ttk_theme(self.root, self._palette)

        self._msg_queue: queue.Queue[tuple] = queue.Queue()
        self._cancel_event: Optional[threading.Event] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._is_busy = False

        # Encrypt state variables
        self.enc_folder_var = tk.StringVar()
        self.enc_output_var = tk.StringVar()
        self.enc_folder_info_var = tk.StringVar(value="No folder selected.")
        self.enc_pw_var = tk.StringVar()
        self.enc_pw_confirm_var = tk.StringVar()
        self.enc_show_pw_var = tk.BooleanVar(value=False)
        self.enc_kdf_var = tk.StringVar(value=list(KDF_CHOICES.keys())[0])
        self.enc_comp_var = tk.StringVar(value=list(COMPRESSION_CHOICES.keys())[0])
        self.enc_delete_orig_var = tk.BooleanVar(value=False)

        # Decrypt state variables
        self.dec_vault_var = tk.StringVar()
        self.dec_dest_var = tk.StringVar()
        self.dec_pw_var = tk.StringVar()
        self.dec_show_pw_var = tk.BooleanVar(value=False)
        self.dec_inspector_var = tk.StringVar(value="Select a .pfvault file to inspect metadata.")

        # Spoof Timestamps state variables
        now_str = format_timestamp(datetime.now())
        self.spoof_file_var = tk.StringVar()
        self.spoof_info_var = tk.StringVar(value="No file or folder selected.")
        self.spoof_created_enabled_var = tk.BooleanVar(value=True)
        self.spoof_created_var = tk.StringVar(value=now_str)
        self.spoof_modified_enabled_var = tk.BooleanVar(value=True)
        self.spoof_modified_var = tk.StringVar(value=now_str)
        self.spoof_accessed_enabled_var = tk.BooleanVar(value=True)
        self.spoof_accessed_var = tk.StringVar(value=now_str)
        self.spoof_recursive_var = tk.BooleanVar(value=False)

        # Progress state variables
        self.progress_stage_var = tk.StringVar(value="Ready")
        self.progress_detail_var = tk.StringVar(value="")
        self.progress_pct_var = tk.StringVar(value="0%")
        self.progress_val_var = tk.DoubleVar(value=0.0)

        self._build_ui()
        self.enc_pw_var.trace_add("write", self._on_enc_password_changed)

        self._log("FolderVault initialized. Cipher: AES-256-GCM | KDF: Argon2id / PBKDF2-SHA256.", "INFO")
        self.root.after(60, self._poll_queue)

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=16)
        container.pack(fill="both", expand=True)

        # Header bar
        header = ttk.Frame(container)
        header.pack(fill="x", pady=(0, 12))

        title_box = ttk.Frame(header)
        title_box.pack(side="left", fill="x", expand=True)
        ttk.Label(title_box, text="FolderVault", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            title_box,
            text="Authenticated Folder Encryption (AES-256-GCM + Argon2id)",
            style="Subtitle.TLabel",
        ).pack(anchor="w")

        header_actions = ttk.Frame(header)
        header_actions.pack(side="right")
        ttk.Label(
            header_actions,
            text="AEAD • 256-BIT",
            style="Badge.TLabel",
        ).pack(side="left", padx=(0, 8))
        self._theme_btn = ttk.Button(
            header_actions,
            text="Light Mode",
            command=self._toggle_theme,
        )
        self._theme_btn.pack(side="left")

        # Tabs
        self._notebook = ttk.Notebook(container)
        self._notebook.pack(fill="both", expand=True, pady=(0, 12))

        enc_tab = ttk.Frame(self._notebook, padding=12)
        dec_tab = ttk.Frame(self._notebook, padding=12)
        spoof_tab = ttk.Frame(self._notebook, padding=12)
        self._notebook.add(enc_tab, text="  Encrypt Folder  ")
        self._notebook.add(dec_tab, text="  Decrypt / Verify Vault  ")
        self._notebook.add(spoof_tab, text="  Spoof Timestamps  ")

        self._build_encrypt_tab(enc_tab)
        self._build_decrypt_tab(dec_tab)
        self._build_spoof_tab(spoof_tab)

        # Progress & Log panel
        bottom_card = ttk.Labelframe(container, text="Operation Progress & Activity Log", style="Card.TLabelframe", padding=12)
        bottom_card.pack(fill="both", expand=False)

        prog_top = ttk.Frame(bottom_card, style="Card.TFrame")
        prog_top.pack(fill="x", pady=(0, 4))
        ttk.Label(prog_top, textvariable=self.progress_stage_var, style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Label(prog_top, textvariable=self.progress_pct_var, style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(side="right")

        prog_bar_row = ttk.Frame(bottom_card, style="Card.TFrame")
        prog_bar_row.pack(fill="x", pady=(0, 4))
        self._progressbar = ttk.Progressbar(
            prog_bar_row,
            variable=self.progress_val_var,
            maximum=100.0,
            mode="determinate",
            style="Accent.Horizontal.TProgressbar",
        )
        self._progressbar.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._cancel_btn = ttk.Button(
            prog_bar_row,
            text="Cancel",
            style="Danger.TButton",
            command=self._cancel_operation,
            state="disabled",
        )
        self._cancel_btn.pack(side="right")

        ttk.Label(bottom_card, textvariable=self.progress_detail_var, style="CardMuted.TLabel").pack(anchor="w", pady=(0, 8))

        self._log_console = LogConsole(bottom_card, self._palette)
        self._log_console.pack(fill="both", expand=True)

        log_footer = ttk.Frame(bottom_card, style="Card.TFrame")
        log_footer.pack(fill="x", pady=(6, 0))
        ttk.Button(log_footer, text="Clear Log", command=self._log_console.clear).pack(side="right")

    def _build_encrypt_tab(self, parent: ttk.Frame) -> None:
        # Source & Destination Card
        paths_card = ttk.Labelframe(parent, text="1. Select Folder & Output Vault", style="Card.TLabelframe", padding=12)
        paths_card.pack(fill="x", pady=(0, 10))
        paths_card.columnconfigure(1, weight=1)

        ttk.Label(paths_card, text="Source Folder:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(paths_card, textvariable=self.enc_folder_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(paths_card, text="Browse...", command=self._browse_enc_folder).grid(row=0, column=2, padx=(8, 0), pady=4)

        ttk.Label(paths_card, textvariable=self.enc_folder_info_var, style="Mono.TLabel").grid(
            row=1, column=1, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(paths_card, text="Output File:", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(paths_card, textvariable=self.enc_output_var).grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Button(paths_card, text="Save As...", command=self._browse_enc_output).grid(row=2, column=2, padx=(8, 0), pady=4)

        # Password Card
        pw_card = ttk.Labelframe(parent, text="2. Protection Password", style="Card.TLabelframe", padding=12)
        pw_card.pack(fill="x", pady=(0, 10))
        pw_card.columnconfigure(1, weight=1)

        ttk.Label(pw_card, text="Password:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self._enc_pw_entry = ttk.Entry(pw_card, textvariable=self.enc_pw_var, show="•")
        self._enc_pw_entry.grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(pw_card, text="Generate Strong", command=self._generate_password).grid(row=0, column=2, padx=(8, 0), pady=4)

        ttk.Label(pw_card, text="Confirm:", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        self._enc_pw_confirm_entry = ttk.Entry(pw_card, textvariable=self.enc_pw_confirm_var, show="•")
        self._enc_pw_confirm_entry.grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Checkbutton(
            pw_card,
            text="Show",
            variable=self.enc_show_pw_var,
            style="Card.TCheckbutton",
            command=self._toggle_enc_pw_visibility,
        ).grid(row=1, column=2, sticky="w", padx=(8, 0), pady=4)

        self._strength_bar = PasswordStrengthBar(pw_card, self._palette)
        self._strength_bar.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(8, 0))

        # Options & Action Card
        opt_card = ttk.Labelframe(parent, text="3. Security Options", style="Card.TLabelframe", padding=12)
        opt_card.pack(fill="x", pady=(0, 10))
        opt_card.columnconfigure(1, weight=1)
        opt_card.columnconfigure(3, weight=1)

        ttk.Label(opt_card, text="Key Derivation:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(
            opt_card,
            textvariable=self.enc_kdf_var,
            values=list(KDF_CHOICES.keys()),
            state="readonly",
        ).grid(row=0, column=1, sticky="ew", padx=(0, 16), pady=4)

        ttk.Label(opt_card, text="Compression:", style="Card.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(
            opt_card,
            textvariable=self.enc_comp_var,
            values=list(COMPRESSION_CHOICES.keys()),
            state="readonly",
        ).grid(row=0, column=3, sticky="ew", pady=4)

        ttk.Checkbutton(
            opt_card,
            text="Delete original folder after verified encryption (asks confirmation)",
            variable=self.enc_delete_orig_var,
            style="Card.TCheckbutton",
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))

        action_row = ttk.Frame(parent)
        action_row.pack(fill="x")
        self._encrypt_btn = ttk.Button(
            action_row,
            text="Encrypt & Password-Protect Folder",
            style="Accent.TButton",
            command=self._start_encrypt,
        )
        self._encrypt_btn.pack(side="right")

    def _build_decrypt_tab(self, parent: ttk.Frame) -> None:
        vault_card = ttk.Labelframe(parent, text="1. Select Encrypted Vault (.pfvault)", style="Card.TLabelframe", padding=12)
        vault_card.pack(fill="x", pady=(0, 10))
        vault_card.columnconfigure(1, weight=1)

        ttk.Label(vault_card, text="Vault File:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(vault_card, textvariable=self.dec_vault_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(vault_card, text="Browse...", command=self._browse_dec_vault).grid(row=0, column=2, padx=(8, 0), pady=4)

        ttk.Label(vault_card, text="Extract To:", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(vault_card, textvariable=self.dec_dest_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(vault_card, text="Folder...", command=self._browse_dec_dest).grid(row=1, column=2, padx=(8, 0), pady=4)

        inspector_card = ttk.Labelframe(parent, text="2. Vault Header Inspector", style="Card.TLabelframe", padding=12)
        inspector_card.pack(fill="x", pady=(0, 10))
        ttk.Label(
            inspector_card,
            textvariable=self.dec_inspector_var,
            style="Mono.TLabel",
            justify="left",
        ).pack(anchor="w", fill="x")

        pw_card = ttk.Labelframe(parent, text="3. Vault Password", style="Card.TLabelframe", padding=12)
        pw_card.pack(fill="x", pady=(0, 10))
        pw_card.columnconfigure(1, weight=1)

        ttk.Label(pw_card, text="Password:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self._dec_pw_entry = ttk.Entry(pw_card, textvariable=self.dec_pw_var, show="•")
        self._dec_pw_entry.grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Checkbutton(
            pw_card,
            text="Show",
            variable=self.dec_show_pw_var,
            style="Card.TCheckbutton",
            command=self._toggle_dec_pw_visibility,
        ).grid(row=0, column=2, sticky="w", padx=(8, 0), pady=4)

        action_row = ttk.Frame(parent)
        action_row.pack(fill="x")
        self._verify_btn = ttk.Button(
            action_row,
            text="Verify Integrity Only",
            command=self._start_verify,
        )
        self._verify_btn.pack(side="left")

        self._decrypt_btn = ttk.Button(
            action_row,
            text="Decrypt & Extract Folder",
            style="Accent.TButton",
            command=self._start_decrypt,
        )
        self._decrypt_btn.pack(side="right")

    def _build_spoof_tab(self, parent: ttk.Frame) -> None:
        file_card = ttk.Labelframe(parent, text="1. Select Target File or Folder", style="Card.TLabelframe", padding=12)
        file_card.pack(fill="x", pady=(0, 10))
        file_card.columnconfigure(1, weight=1)

        ttk.Label(file_card, text="Target Path:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(file_card, textvariable=self.spoof_file_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(file_card, text="File...", command=self._browse_spoof_file).grid(row=0, column=2, padx=(8, 0), pady=4)
        ttk.Button(file_card, text="Folder...", command=self._browse_spoof_folder).grid(row=0, column=3, padx=(6, 0), pady=4)

        ttk.Label(
            file_card,
            textvariable=self.spoof_info_var,
            style="Mono.TLabel",
            justify="left",
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(6, 0))

        ts_card = ttk.Labelframe(parent, text="2. Spoofed Timestamps (Local Time)", style="Card.TLabelframe", padding=12)
        ts_card.pack(fill="x", pady=(0, 10))
        ts_card.columnconfigure(1, weight=1)

        ttk.Label(
            ts_card,
            text="Format: YYYY-MM-DD HH:MM:SS  (also accepts YYYY-MM-DD HH:MM or YYYY-MM-DD)",
            style="CardMuted.TLabel",
        ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        ttk.Checkbutton(
            ts_card,
            text="Creation Time:",
            variable=self.spoof_created_enabled_var,
            style="Card.TCheckbutton",
            command=self._update_spoof_entry_states,
        ).grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        self._spoof_created_entry = ttk.Entry(ts_card, textvariable=self.spoof_created_var)
        self._spoof_created_entry.grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(ts_card, text="Now", command=lambda: self._set_spoof_now("created")).grid(row=1, column=2, padx=(8, 0), pady=4)
        ttk.Button(
            ts_card,
            text="Match Edit",
            command=lambda: self.spoof_created_var.set(self.spoof_modified_var.get()),
        ).grid(row=1, column=3, padx=(6, 0), pady=4)

        ttk.Checkbutton(
            ts_card,
            text="Last Edit Time:",
            variable=self.spoof_modified_enabled_var,
            style="Card.TCheckbutton",
            command=self._update_spoof_entry_states,
        ).grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        self._spoof_modified_entry = ttk.Entry(ts_card, textvariable=self.spoof_modified_var)
        self._spoof_modified_entry.grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Button(ts_card, text="Now", command=lambda: self._set_spoof_now("modified")).grid(row=2, column=2, padx=(8, 0), pady=4)
        ttk.Button(
            ts_card,
            text="Match Creation",
            command=lambda: self.spoof_modified_var.set(self.spoof_created_var.get()),
        ).grid(row=2, column=3, padx=(6, 0), pady=4)

        ttk.Checkbutton(
            ts_card,
            text="Last Used Time:",
            variable=self.spoof_accessed_enabled_var,
            style="Card.TCheckbutton",
            command=self._update_spoof_entry_states,
        ).grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        self._spoof_accessed_entry = ttk.Entry(ts_card, textvariable=self.spoof_accessed_var)
        self._spoof_accessed_entry.grid(row=3, column=1, sticky="ew", pady=4)
        ttk.Button(ts_card, text="Now", command=lambda: self._set_spoof_now("accessed")).grid(row=3, column=2, padx=(8, 0), pady=4)
        ttk.Button(
            ts_card,
            text="Match Edit",
            command=lambda: self.spoof_accessed_var.set(self.spoof_modified_var.get()),
        ).grid(row=3, column=3, padx=(6, 0), pady=4)

        ttk.Checkbutton(
            ts_card,
            text="Apply recursively to all files & subfolders (when target is a folder)",
            variable=self.spoof_recursive_var,
            style="Card.TCheckbutton",
        ).grid(row=4, column=0, columnspan=4, sticky="w", pady=(8, 0))

        action_row = ttk.Frame(parent)
        action_row.pack(fill="x")
        ttk.Button(
            action_row,
            text="Load Current Times",
            command=self._load_current_spoof_times,
        ).pack(side="left")

        self._spoof_apply_btn = ttk.Button(
            action_row,
            text="Apply Spoofed Timestamps",
            style="Accent.TButton",
            command=self._apply_spoof_timestamps,
        )
        self._spoof_apply_btn.pack(side="right")

    # ------------------------------------------------------------------
    # UI Event Handlers
    # ------------------------------------------------------------------
    def _toggle_theme(self) -> None:
        self._theme_name = "light" if self._theme_name == "dark" else "dark"
        self._palette = PALETTES[self._theme_name]
        apply_ttk_theme(self.root, self._palette)
        self._strength_bar.set_palette(self._palette)
        self._log_console.set_palette(self._palette)
        self._theme_btn.configure(
            text="Dark Mode" if self._theme_name == "light" else "Light Mode"
        )

    def _toggle_enc_pw_visibility(self) -> None:
        show_char = "" if self.enc_show_pw_var.get() else "•"
        self._enc_pw_entry.configure(show=show_char)
        self._enc_pw_confirm_entry.configure(show=show_char)

    def _toggle_dec_pw_visibility(self) -> None:
        show_char = "" if self.dec_show_pw_var.get() else "•"
        self._dec_pw_entry.configure(show=show_char)

    def _on_enc_password_changed(self, *_args: object) -> None:
        assessment = evaluate_password(self.enc_pw_var.get())
        self._strength_bar.update_assessment(assessment)

    def _generate_password(self) -> None:
        pw = generate_strong_password(20)
        self.enc_pw_var.set(pw)
        self.enc_pw_confirm_var.set(pw)
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        self._log("Generated 20-character random password and copied it to clipboard.", "SUCCESS")

    def _browse_enc_folder(self) -> None:
        selected = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not selected:
            return
        folder = Path(selected)
        self.enc_folder_var.set(str(folder))
        if not self.enc_output_var.get():
            self.enc_output_var.set(str(folder.with_suffix(".pfvault")))

        if not CRYPTO_AVAILABLE:
            self.enc_folder_info_var.set("Encryption requires 'cryptography' (pip install -r requirements.txt).")
            return
        try:
            stats = scan_folder(folder)
            self.enc_folder_info_var.set(
                f"Files: {stats.file_count:,}  |  Subfolders: {stats.dir_count:,}  |  "
                f"Total Size: {format_bytes(stats.total_bytes)}"
            )
            self._log(f"Selected folder '{folder.name}' ({stats.file_count} files, {format_bytes(stats.total_bytes)}).", "INFO")
        except OSError as exc:
            self.enc_folder_info_var.set(f"Error scanning folder: {exc}")

    def _browse_enc_output(self) -> None:
        initial = self.enc_output_var.get()
        initial_dir = str(Path(initial).parent) if initial else None
        selected = filedialog.asksaveasfilename(
            title="Save Encrypted Vault As",
            defaultextension=".pfvault",
            filetypes=[("FolderVault Archive", "*.pfvault"), ("All Files", "*.*")],
            initialdir=initial_dir,
        )
        if selected:
            self.enc_output_var.set(selected)

    def _browse_dec_vault(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select Encrypted Vault",
            filetypes=[("FolderVault Archive", "*.pfvault"), ("All Files", "*.*")],
        )
        if not selected:
            return
        vault = Path(selected)
        self.dec_vault_var.set(str(vault))
        if not self.dec_dest_var.get():
            self.dec_dest_var.set(str(vault.parent / f"{vault.stem}_decrypted"))

        if not CRYPTO_AVAILABLE:
            self.dec_inspector_var.set("Vault inspection requires 'cryptography' (pip install -r requirements.txt).")
            return
        try:
            hdr = inspect_vault(vault)
            created = datetime.fromtimestamp(hdr.created_timestamp).strftime("%Y-%m-%d %H:%M:%S")
            size_str = format_bytes(vault.stat().st_size)
            self.dec_inspector_var.set(
                f"Format: PFVAULT v{hdr.version}  |  Size: {size_str}  |  Created: {created}\n"
                f"Cipher: {hdr.cipher_description}  |  Chunk Size: {format_bytes(hdr.chunk_size)}\n"
                f"KDF:    {hdr.kdf_description}"
            )
            self._log(f"Inspected vault '{vault.name}' ({hdr.cipher_description}, {hdr.kdf_description}).", "INFO")
        except (CryptoError, OSError) as exc:
            self.dec_inspector_var.set(f"Invalid vault file: {exc}")
            self._log(f"Vault inspection failed: {exc}", "ERROR")

    def _browse_dec_dest(self) -> None:
        selected = filedialog.askdirectory(title="Select Destination Folder")
        if selected:
            self.dec_dest_var.set(selected)

    def _browse_spoof_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select File to Spoof Timestamps",
            filetypes=[("All Files", "*.*")],
        )
        if not selected:
            return
        path = Path(selected)
        self.spoof_file_var.set(str(path))
        self._refresh_spoof_file_info(path, populate_fields=True)

    def _browse_spoof_folder(self) -> None:
        selected = filedialog.askdirectory(title="Select Folder to Spoof Timestamps")
        if not selected:
            return
        path = Path(selected)
        self.spoof_file_var.set(str(path))
        self._refresh_spoof_file_info(path, populate_fields=True)

    def _refresh_spoof_file_info(self, path: Path, *, populate_fields: bool = False) -> None:
        try:
            ts = get_file_timestamps(path)
            created_str = format_timestamp(ts.created)
            modified_str = format_timestamp(ts.modified)
            accessed_str = format_timestamp(ts.accessed)
            kind_str = "Folder" if path.is_dir() else f"File ({format_bytes(ts.size_bytes)})"
            self.spoof_info_var.set(
                f"Created:   {created_str}  |  Type: {kind_str}\n"
                f"Last Edit: {modified_str}  |  Accessed: {accessed_str}"
            )
            if populate_fields:
                self.spoof_created_var.set(created_str)
                self.spoof_modified_var.set(modified_str)
                self.spoof_accessed_var.set(accessed_str)
            self._log(
                f"Loaded timestamps for '{path.name}' "
                f"(Created: {created_str}, Last Edit: {modified_str}, Last Used: {accessed_str}).",
                "INFO",
            )
        except TimestampError as exc:
            self.spoof_info_var.set(f"Error reading path: {exc}")
            self._log(f"Timestamp inspection failed: {exc}", "ERROR")

    def _load_current_spoof_times(self) -> None:
        file_str = self.spoof_file_var.get().strip()
        if not file_str:
            messagebox.showwarning("Missing Target", "Please select a target file or folder first.")
            return
        self._refresh_spoof_file_info(Path(file_str), populate_fields=True)

    def _set_spoof_now(self, target: str) -> None:
        now_str = format_timestamp(datetime.now())
        if target == "created":
            self.spoof_created_var.set(now_str)
        elif target == "modified":
            self.spoof_modified_var.set(now_str)
        elif target == "accessed":
            self.spoof_accessed_var.set(now_str)

    def _update_spoof_entry_states(self) -> None:
        self._spoof_created_entry.configure(
            state="normal" if self.spoof_created_enabled_var.get() else "disabled"
        )
        self._spoof_modified_entry.configure(
            state="normal" if self.spoof_modified_enabled_var.get() else "disabled"
        )
        self._spoof_accessed_entry.configure(
            state="normal" if self.spoof_accessed_enabled_var.get() else "disabled"
        )

    def _apply_spoof_timestamps(self) -> None:
        file_str = self.spoof_file_var.get().strip()
        if not file_str:
            messagebox.showwarning("Missing Target", "Please select a target file or folder.")
            return
        path = Path(file_str)
        if not path.exists():
            messagebox.showerror("Invalid Path", f"File or folder does not exist:\n{path}")
            return

        use_created = self.spoof_created_enabled_var.get()
        use_modified = self.spoof_modified_enabled_var.get()
        use_accessed = self.spoof_accessed_enabled_var.get()
        if not use_created and not use_modified and not use_accessed:
            messagebox.showwarning(
                "No Timestamp Selected",
                "Enable at least one of 'Creation Time', 'Last Edit Time', or 'Last Used Time'.",
            )
            return

        try:
            created_dt = parse_timestamp(self.spoof_created_var.get()) if use_created else None
            modified_dt = parse_timestamp(self.spoof_modified_var.get()) if use_modified else None
            accessed_dt = parse_timestamp(self.spoof_accessed_var.get()) if use_accessed else None
            if path.is_dir() and self.spoof_recursive_var.get():
                updated, count = spoof_directory_tree(
                    path,
                    created=created_dt,
                    modified=modified_dt,
                    accessed=accessed_dt,
                )
            else:
                updated = spoof_file_timestamps(
                    path,
                    created=created_dt,
                    modified=modified_dt,
                    accessed=accessed_dt,
                )
                count = 1
        except TimestampError as exc:
            self._log(f"Timestamp spoof failed: {exc}", "ERROR")
            messagebox.showerror("Timestamp Spoof Failed", str(exc))
            return

        created_str = format_timestamp(updated.created)
        modified_str = format_timestamp(updated.modified)
        accessed_str = format_timestamp(updated.accessed)
        kind_str = "Folder" if path.is_dir() else f"File ({format_bytes(updated.size_bytes)})"
        self.spoof_info_var.set(
            f"Created:   {created_str}  |  Type: {kind_str}\n"
            f"Last Edit: {modified_str}  |  Accessed: {accessed_str}"
        )
        scope_note = f" ({count:,} items updated recursively)" if count > 1 else ""
        summary = (
            f"Updated timestamps for '{path.name}'{scope_note}:\n"
            f"Creation Time: {created_str}\n"
            f"Last Edit Time: {modified_str}\n"
            f"Last Used Time: {accessed_str}"
        )
        self._log(
            f"Spoofed timestamps on '{path.name}'{scope_note} -> "
            f"Created: {created_str} | Last Edit: {modified_str} | Last Used: {accessed_str}.",
            "SUCCESS",
        )
        messagebox.showinfo("Timestamps Updated", summary)

    # ------------------------------------------------------------------
    # Background Task Execution
    # ------------------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        self._is_busy = busy
        state = "disabled" if busy else "normal"
        self._encrypt_btn.configure(state=state)
        self._decrypt_btn.configure(state=state)
        self._verify_btn.configure(state=state)
        self._spoof_apply_btn.configure(state=state)
        self._cancel_btn.configure(state="normal" if busy else "disabled")

    def _cancel_operation(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
            self._log("Cancellation requested...", "WARN")
            self._cancel_btn.configure(state="disabled")

    def _run_background(self, task_name: str, worker_fn: Callable[[], OperationResult]) -> None:
        if self._is_busy:
            return
        self._cancel_event = threading.Event()
        self._set_busy(True)
        self._update_progress(f"Starting {task_name}...", 0.0, "")

        def runner() -> None:
            try:
                result = worker_fn()
                self._msg_queue.put(("DONE", task_name, result))
            except Exception as exc:  # noqa: BLE001
                self._msg_queue.put(("ERROR", task_name, exc))

        self._worker_thread = threading.Thread(target=runner, daemon=True)
        self._worker_thread.start()

    def _progress_callback(self, stage: str, fraction: float, detail: Optional[str]) -> None:
        self._msg_queue.put(("PROGRESS", stage, fraction, detail or ""))

    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self._msg_queue.get_nowait()
                kind = msg[0]
                if kind == "PROGRESS":
                    _, stage, fraction, detail = msg
                    self._update_progress(stage, fraction, detail)
                elif kind == "DONE":
                    _, task_name, result = msg
                    self._on_task_done(task_name, result)
                elif kind == "ERROR":
                    _, task_name, exc = msg
                    self._on_task_error(task_name, exc)
        except queue.Empty:
            pass
        self.root.after(60, self._poll_queue)

    def _update_progress(self, stage: str, fraction: float, detail: str) -> None:
        pct = max(0.0, min(100.0, fraction * 100.0))
        self.progress_stage_var.set(stage)
        self.progress_val_var.set(pct)
        self.progress_pct_var.set(f"{pct:.0f}%")
        self.progress_detail_var.set(detail)

    def _on_task_done(self, task_name: str, result: OperationResult) -> None:
        self._set_busy(False)
        self._update_progress(f"{task_name} completed", 1.0, str(result.output_path or "All chunks verified"))
        summary = (
            f"{task_name} succeeded in {result.elapsed_seconds:.2f}s — "
            f"{result.files_processed:,} items, {format_bytes(result.bytes_processed)} "
            f"({result.cipher_description}, {result.kdf_description})."
        )
        self._log(summary, "SUCCESS")
        messagebox.showinfo("Success", summary)

    def _on_task_error(self, task_name: str, exc: Exception) -> None:
        self._set_busy(False)
        self._update_progress(f"{task_name} failed", 0.0, str(exc))
        self._log(f"{task_name} failed: {exc}", "ERROR")
        messagebox.showerror(f"{task_name} Failed", str(exc))

    def _log(self, message: str, level: str = "INFO") -> None:
        self._log_console.log(message, level)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _require_crypto(self) -> bool:
        if CRYPTO_AVAILABLE:
            return True
        msg = (
            "The 'cryptography' package is required for folder encryption and decryption.\n\n"
            "Install it with:\n    pip install cryptography\n\n"
            "(The Spoof Timestamps tab works without any extra packages.)"
        )
        if _CRYPTO_IMPORT_ERROR:
            msg += f"\n\nDetails: {_CRYPTO_IMPORT_ERROR}"
        messagebox.showerror("Missing Dependency", msg)
        return False

    def _start_encrypt(self) -> None:
        if not self._require_crypto():
            return
        folder_str = self.enc_folder_var.get().strip()
        output_str = self.enc_output_var.get().strip()
        password = self.enc_pw_var.get()
        confirm = self.enc_pw_confirm_var.get()

        if not folder_str:
            messagebox.showwarning("Missing Folder", "Please select a folder to encrypt.")
            return
        folder = Path(folder_str)
        if not folder.is_dir():
            messagebox.showerror("Invalid Folder", f"Folder does not exist:\n{folder}")
            return
        if not output_str:
            messagebox.showwarning("Missing Output", "Please specify an output .pfvault file.")
            return
        output = Path(output_str)
        if not password:
            messagebox.showwarning("Missing Password", "Please enter a password.")
            return
        if password != confirm:
            messagebox.showerror("Password Mismatch", "Passwords do not match.")
            return

        assessment = evaluate_password(password)
        if assessment.score <= 1:
            proceed = messagebox.askyesno(
                "Weak Password",
                f"Your password is rated '{assessment.label}' ({assessment.feedback}).\n\n"
                "Continue anyway?",
            )
            if not proceed:
                return

        delete_orig = self.enc_delete_orig_var.get()
        if delete_orig:
            confirmed = messagebox.askyesno(
                "Confirm Original Folder Deletion",
                f"The original folder will be PERMANENTLY DELETED after encryption:\n\n{folder}\n\n"
                "Are you sure you want to continue?",
                icon="warning",
            )
            if not confirmed:
                return

        kdf = KDF_CHOICES[self.enc_kdf_var.get()]
        comp = COMPRESSION_CHOICES[self.enc_comp_var.get()]

        self._log(f"Encrypting '{folder}' -> '{output}'...", "INFO")
        self._run_background(
            "Encryption",
            lambda: encrypt_folder(
                folder,
                output,
                password,
                kdf=kdf,
                compression=comp,
                delete_original=delete_orig,
                progress_cb=self._progress_callback,
                cancel_event=self._cancel_event,
            ),
        )

    def _start_decrypt(self) -> None:
        if not self._require_crypto():
            return
        vault_str = self.dec_vault_var.get().strip()
        dest_str = self.dec_dest_var.get().strip()
        password = self.dec_pw_var.get()

        if not vault_str:
            messagebox.showwarning("Missing Vault", "Please select a .pfvault file.")
            return
        vault = Path(vault_str)
        if not vault.is_file():
            messagebox.showerror("Invalid File", f"Vault file does not exist:\n{vault}")
            return
        if not dest_str:
            messagebox.showwarning("Missing Destination", "Please select an extraction folder.")
            return
        if not password:
            messagebox.showwarning("Missing Password", "Please enter the vault password.")
            return

        dest = Path(dest_str)
        self._log(f"Decrypting '{vault}' -> '{dest}'...", "INFO")
        self._run_background(
            "Decryption",
            lambda: decrypt_vault(
                vault,
                dest,
                password,
                progress_cb=self._progress_callback,
                cancel_event=self._cancel_event,
            ),
        )

    def _start_verify(self) -> None:
        if not self._require_crypto():
            return
        vault_str = self.dec_vault_var.get().strip()
        password = self.dec_pw_var.get()

        if not vault_str:
            messagebox.showwarning("Missing Vault", "Please select a .pfvault file.")
            return
        vault = Path(vault_str)
        if not vault.is_file():
            messagebox.showerror("Invalid File", f"Vault file does not exist:\n{vault}")
            return
        if not password:
            messagebox.showwarning("Missing Password", "Please enter the vault password.")
            return

        self._log(f"Verifying integrity of '{vault}'...", "INFO")
        self._run_background(
            "Verification",
            lambda: verify_vault(
                vault,
                password,
                progress_cb=self._progress_callback,
                cancel_event=self._cancel_event,
            ),
        )
