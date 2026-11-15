"""Utilities for inspecting and spoofing file creation and modification timestamps."""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
_EPOCH_AS_FILETIME = 116444736000000000  # 100-ns intervals between 1601-01-01 and 1970-01-01
_HUNDREDS_OF_NS = 10_000_000

_ACCEPTED_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d",
)


class TimestampError(Exception):
    """Raised when reading, parsing, or updating file timestamps fails."""


@dataclass(frozen=True)
class FileTimestamps:
    """Snapshot of a file's timestamps and size."""

    created: datetime
    modified: datetime
    accessed: datetime
    size_bytes: int


def format_timestamp(dt: datetime) -> str:
    """Format a datetime into the standard UI timestamp string."""
    return dt.strftime(TIMESTAMP_FORMAT)


def parse_timestamp(value: str) -> datetime:
    """Parse a user-provided local date/time string into a datetime."""
    cleaned = value.strip()
    if not cleaned:
        raise TimestampError("Timestamp cannot be empty. Use YYYY-MM-DD HH:MM:SS.")
    for fmt in _ACCEPTED_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    raise TimestampError(
        f"Invalid date/time '{cleaned}'. Expected format: YYYY-MM-DD HH:MM:SS."
    )


def get_file_timestamps(path: Path) -> FileTimestamps:
    """Return the current creation, modified, and accessed timestamps of a file or folder."""
    if not path.exists():
        raise TimestampError(f"Path does not exist: {path}")
    try:
        st = path.stat()
    except OSError as exc:
        raise TimestampError(f"Could not read metadata: {exc}") from exc

    created_ts = getattr(st, "st_birthtime", st.st_ctime)
    return FileTimestamps(
        created=datetime.fromtimestamp(created_ts),
        modified=datetime.fromtimestamp(st.st_mtime),
        accessed=datetime.fromtimestamp(st.st_atime),
        size_bytes=st.st_size,
    )


def spoof_file_timestamps(
    path: Path,
    *,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    accessed: Optional[datetime] = None,
) -> FileTimestamps:
    """Update a file or folder's creation, last-modified, and/or last-accessed timestamps.

    Returns the updated FileTimestamps read back from disk.
    """
    if not path.exists():
        raise TimestampError(f"Path does not exist: {path}")
    if created is None and modified is None and accessed is None:
        raise TimestampError("Select at least one timestamp to update.")

    if sys.platform == "win32":
        _set_windows_file_times(path, created=created, modified=modified, accessed=accessed)
    else:
        if created is not None:
            raise TimestampError("Spoofing creation time is only supported on Windows.")
        current = get_file_timestamps(path)
        atime = (accessed or current.accessed).timestamp()
        mtime = (modified or current.modified).timestamp()
        try:
            os.utime(path, (atime, mtime))
        except OSError as exc:
            raise TimestampError(f"Failed to update timestamps: {exc}") from exc

    return get_file_timestamps(path)


def spoof_directory_tree(
    folder: Path,
    *,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    accessed: Optional[datetime] = None,
) -> tuple[FileTimestamps, int]:
    """Recursively update timestamps for all files, subfolders, and the root folder.

    Processes bottom-up so child updates do not overwrite parent folder timestamps.
    Returns (root_timestamps, total_items_updated).
    """
    if not folder.is_dir():
        raise TimestampError(f"Folder does not exist: {folder}")
    if created is None and modified is None and accessed is None:
        raise TimestampError("Select at least one timestamp to update.")

    count = 0
    for root_dir, dir_names, file_names in os.walk(folder, topdown=False):
        root_path = Path(root_dir)
        for name in file_names:
            spoof_file_timestamps(
                root_path / name,
                created=created,
                modified=modified,
                accessed=accessed,
            )
            count += 1
        for name in dir_names:
            spoof_file_timestamps(
                root_path / name,
                created=created,
                modified=modified,
                accessed=accessed,
            )
            count += 1

    root_ts = spoof_file_timestamps(
        folder,
        created=created,
        modified=modified,
        accessed=accessed,
    )
    count += 1
    return root_ts, count


def _set_windows_file_times(
    path: Path,
    *,
    created: Optional[datetime],
    modified: Optional[datetime],
    accessed: Optional[datetime],
) -> None:
    """Use Win32 SetFileTime to update creation, access, and write timestamps."""
    from ctypes import wintypes

    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    def to_filetime(dt: datetime) -> FILETIME:
        try:
            unix_ts = dt.timestamp()
        except (OSError, OverflowError, ValueError) as exc:
            raise TimestampError(f"Timestamp out of supported range: {dt}") from exc
        ticks = int(round(unix_ts * _HUNDREDS_OF_NS)) + _EPOCH_AS_FILETIME
        if ticks < 0:
            raise TimestampError("Timestamp must be on or after 1601-01-01 00:00:00.")
        return FILETIME(ticks & 0xFFFFFFFF, (ticks >> 32) & 0xFFFFFFFF)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.SetFileTime.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ]
    kernel32.SetFileTime.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    file_write_attributes = 0x0100
    file_share_all = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    file_flags = 0x00000080 | 0x02000000  # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS
    invalid_handle = ctypes.c_void_p(-1).value

    handle = kernel32.CreateFileW(
        str(path),
        file_write_attributes,
        file_share_all,
        None,
        open_existing,
        file_flags,
        None,
    )
    if handle == invalid_handle or handle is None:
        err = ctypes.get_last_error()
        raise TimestampError(f"Could not open file for attribute write: {ctypes.WinError(err)}")

    try:
        c_ft = to_filetime(created) if created is not None else None
        a_ft = to_filetime(accessed) if accessed is not None else None
        m_ft = to_filetime(modified) if modified is not None else None

        ok = kernel32.SetFileTime(
            handle,
            ctypes.byref(c_ft) if c_ft is not None else None,
            ctypes.byref(a_ft) if a_ft is not None else None,
            ctypes.byref(m_ft) if m_ft is not None else None,
        )
        if not ok:
            err = ctypes.get_last_error()
            raise TimestampError(f"SetFileTime failed: {ctypes.WinError(err)}")
    finally:
        kernel32.CloseHandle(handle)
