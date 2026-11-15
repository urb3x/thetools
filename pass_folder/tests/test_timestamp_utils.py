"""Unit tests for timestamp_utils and the Spoof Timestamps tab."""

from __future__ import annotations

import tempfile
import tkinter as tk
import unittest
from datetime import datetime
from pathlib import Path

from app import FolderVaultApp
from timestamp_utils import (
    TimestampError,
    format_timestamp,
    get_file_timestamps,
    parse_timestamp,
    spoof_directory_tree,
    spoof_file_timestamps,
)


class TimestampUtilsTests(unittest.TestCase):
    def test_parse_timestamp_accepts_supported_formats(self) -> None:
        self.assertEqual(
            parse_timestamp("2021-05-14 09:30:45"),
            datetime(2021, 5, 14, 9, 30, 45),
        )
        self.assertEqual(
            parse_timestamp("2021-05-14 09:30"),
            datetime(2021, 5, 14, 9, 30, 0),
        )
        self.assertEqual(
            parse_timestamp("2021-05-14T09:30:45"),
            datetime(2021, 5, 14, 9, 30, 45),
        )
        self.assertEqual(
            parse_timestamp("2021-05-14"),
            datetime(2021, 5, 14, 0, 0, 0),
        )

    def test_parse_timestamp_rejects_invalid_strings(self) -> None:
        for bad in ("", "   ", "14/05/2021", "2021-13-01 00:00:00", "not-a-date"):
            with self.assertRaises(TimestampError):
                parse_timestamp(bad)

    def test_spoof_both_creation_and_modified_times(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.txt"
            target.write_text("hello world", encoding="utf-8")

            new_created = datetime(2019, 3, 15, 14, 22, 10)
            new_modified = datetime(2022, 11, 2, 8, 5, 33)

            updated = spoof_file_timestamps(
                target,
                created=new_created,
                modified=new_modified,
                accessed=new_modified,
            )

            self.assertEqual(format_timestamp(updated.created), "2019-03-15 14:22:10")
            self.assertEqual(format_timestamp(updated.modified), "2022-11-02 08:05:33")
            self.assertEqual(format_timestamp(updated.accessed), "2022-11-02 08:05:33")

            reread = get_file_timestamps(target)
            self.assertEqual(format_timestamp(reread.created), "2019-03-15 14:22:10")
            self.assertEqual(format_timestamp(reread.modified), "2022-11-02 08:05:33")

    def test_spoof_only_creation_preserves_modified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "only_created.txt"
            target.write_text("data", encoding="utf-8")
            before = get_file_timestamps(target)

            new_created = datetime(2018, 1, 20, 12, 0, 0)
            updated = spoof_file_timestamps(target, created=new_created)

            self.assertEqual(format_timestamp(updated.created), "2018-01-20 12:00:00")
            self.assertAlmostEqual(
                updated.modified.timestamp(),
                before.modified.timestamp(),
                places=2,
            )

    def test_spoof_only_modified_preserves_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "only_modified.txt"
            target.write_text("data", encoding="utf-8")
            before = get_file_timestamps(target)

            new_modified = datetime(2020, 7, 4, 18, 45, 0)
            updated = spoof_file_timestamps(target, modified=new_modified)

            self.assertEqual(format_timestamp(updated.modified), "2020-07-04 18:45:00")
            self.assertAlmostEqual(
                updated.created.timestamp(),
                before.created.timestamp(),
                places=2,
            )

    def test_spoof_only_accessed_preserves_creation_and_modified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "only_accessed.txt"
            target.write_text("data", encoding="utf-8")
            before = get_file_timestamps(target)

            new_accessed = datetime(2021, 9, 12, 6, 15, 30)
            updated = spoof_file_timestamps(target, accessed=new_accessed)

            self.assertEqual(format_timestamp(updated.accessed), "2021-09-12 06:15:30")
            self.assertAlmostEqual(
                updated.created.timestamp(),
                before.created.timestamp(),
                places=2,
            )
            self.assertAlmostEqual(
                updated.modified.timestamp(),
                before.modified.timestamp(),
                places=2,
            )

    def test_spoof_folder_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            folder = Path(tmpdir) / "my_folder"
            folder.mkdir()

            new_created = datetime(2017, 6, 1, 10, 0, 0)
            new_modified = datetime(2020, 8, 15, 16, 30, 0)
            new_accessed = datetime(2023, 2, 20, 9, 45, 0)

            updated = spoof_file_timestamps(
                folder,
                created=new_created,
                modified=new_modified,
                accessed=new_accessed,
            )

            self.assertEqual(format_timestamp(updated.created), "2017-06-01 10:00:00")
            self.assertEqual(format_timestamp(updated.modified), "2020-08-15 16:30:00")
            self.assertEqual(format_timestamp(updated.accessed), "2023-02-20 09:45:00")

    def test_spoof_directory_tree_recursive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root_dir = Path(tmpdir) / "root_folder"
            sub_dir = root_dir / "nested"
            sub_dir.mkdir(parents=True)
            file_a = root_dir / "a.txt"
            file_b = sub_dir / "b.txt"
            file_a.write_text("a", encoding="utf-8")
            file_b.write_text("b", encoding="utf-8")

            target_dt = datetime(2016, 4, 10, 12, 34, 56)
            root_ts, count = spoof_directory_tree(
                root_dir,
                created=target_dt,
                modified=target_dt,
                accessed=target_dt,
            )

            self.assertEqual(count, 4)  # root_folder, nested, a.txt, b.txt
            for p in (root_dir, sub_dir, file_a, file_b):
                ts = get_file_timestamps(p)
                self.assertEqual(format_timestamp(ts.created), "2016-04-10 12:34:56")
                self.assertEqual(format_timestamp(ts.modified), "2016-04-10 12:34:56")
                self.assertEqual(format_timestamp(ts.accessed), "2016-04-10 12:34:56")
            self.assertEqual(format_timestamp(root_ts.modified), "2016-04-10 12:34:56")

    def test_spoof_error_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "does_not_exist.txt"
            with self.assertRaises(TimestampError):
                get_file_timestamps(missing)
            with self.assertRaises(TimestampError):
                spoof_file_timestamps(missing, modified=datetime.now())

            existing = Path(tmpdir) / "exists.txt"
            existing.write_text("x", encoding="utf-8")
            with self.assertRaises(TimestampError):
                spoof_file_timestamps(existing)

    def test_app_has_spoof_timestamps_tab(self) -> None:
        root = tk.Tk()
        root.withdraw()
        try:
            app = FolderVaultApp(root)
            tab_texts = [app._notebook.tab(tab_id, "text") for tab_id in app._notebook.tabs()]
            self.assertIn("  Spoof Timestamps  ", tab_texts)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
