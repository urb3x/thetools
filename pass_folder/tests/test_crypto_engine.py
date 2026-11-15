"""Unit tests for crypto_engine and password_utils."""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path

from crypto_engine import (
    AuthenticationError,
    CompressionLevel,
    InvalidVaultError,
    KdfType,
    OperationCancelledError,
    decrypt_vault,
    encrypt_folder,
    inspect_vault,
    verify_vault,
)
from password_utils import evaluate_password, generate_strong_password


class TestCryptoEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src_dir = self.root / "secret_docs"
        self.src_dir.mkdir()
        (self.src_dir / "hello.txt").write_text("Hello, AES-256-GCM!", encoding="utf-8")
        nested = self.src_dir / "nested" / "deep"
        nested.mkdir(parents=True)
        (nested / "binary.bin").write_bytes(os.urandom(5000))
        (self.src_dir / "empty_sub").mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_encrypt_decrypt_argon2id_multichunk(self) -> None:
        vault = self.root / "secret_docs.pfvault"
        out_dir = self.root / "restored"

        enc_res = encrypt_folder(
            self.src_dir,
            vault,
            "CorrectHorseBatteryStaple!99",
            kdf=KdfType.ARGON2ID,
            compression=CompressionLevel.NONE,
            chunk_size=1024,  # Force multiple chunks
        )
        self.assertTrue(vault.is_file())
        self.assertEqual(enc_res.files_processed, 2)

        hdr = inspect_vault(vault)
        self.assertEqual(hdr.kdf, KdfType.ARGON2ID)
        self.assertEqual(hdr.chunk_size, 1024)

        dec_res = decrypt_vault(vault, out_dir, "CorrectHorseBatteryStaple!99")
        self.assertEqual(dec_res.files_processed, 2)

        restored_root = out_dir / "secret_docs"
        self.assertEqual(
            (restored_root / "hello.txt").read_text(encoding="utf-8"),
            "Hello, AES-256-GCM!",
        )
        self.assertEqual(
            (restored_root / "nested" / "deep" / "binary.bin").read_bytes(),
            (self.src_dir / "nested" / "deep" / "binary.bin").read_bytes(),
        )
        self.assertTrue((restored_root / "empty_sub").is_dir())

    def test_encrypt_decrypt_pbkdf2(self) -> None:
        vault = self.root / "pbkdf2.pfvault"
        out_dir = self.root / "restored_pbkdf2"

        encrypt_folder(
            self.src_dir,
            vault,
            "MyStrongPass#2026",
            kdf=KdfType.PBKDF2_SHA256,
            compression=CompressionLevel.BALANCED,
        )
        hdr = inspect_vault(vault)
        self.assertEqual(hdr.kdf, KdfType.PBKDF2_SHA256)

        decrypt_vault(vault, out_dir, "MyStrongPass#2026")
        self.assertEqual(
            (out_dir / "secret_docs" / "hello.txt").read_text(encoding="utf-8"),
            "Hello, AES-256-GCM!",
        )

    def test_wrong_password_rejected(self) -> None:
        vault = self.root / "locked.pfvault"
        encrypt_folder(self.src_dir, vault, "RightPassword!123")

        with self.assertRaises(AuthenticationError):
            decrypt_vault(vault, self.root / "out", "WrongPassword!123")

        with self.assertRaises(AuthenticationError):
            verify_vault(vault, "WrongPassword!123")

    def test_tamper_detection_and_truncation(self) -> None:
        vault = self.root / "tamper.pfvault"
        encrypt_folder(self.src_dir, vault, "TamperTest!123", chunk_size=1024)

        verify_res = verify_vault(vault, "TamperTest!123")
        self.assertGreaterEqual(verify_res.files_processed, 1)

        # Flip a byte in the ciphertext payload
        data = bytearray(vault.read_bytes())
        data[-10] ^= 0xFF
        vault.write_bytes(bytes(data))

        with self.assertRaises(AuthenticationError):
            verify_vault(vault, "TamperTest!123")

        # Truncate file
        vault.write_bytes(bytes(data[:80]))
        with self.assertRaises(AuthenticationError):
            verify_vault(vault, "TamperTest!123")

    def test_invalid_magic_rejected(self) -> None:
        bad_file = self.root / "not_a_vault.pfvault"
        bad_file.write_bytes(b"NOT_PFVAULT_" + b"\x00" * 100)
        with self.assertRaises(InvalidVaultError):
            inspect_vault(bad_file)

    def test_empty_folder(self) -> None:
        empty_dir = self.root / "empty_folder"
        empty_dir.mkdir()
        vault = self.root / "empty.pfvault"
        out_dir = self.root / "out_empty"

        encrypt_folder(empty_dir, vault, "EmptyFolder!123")
        decrypt_vault(vault, out_dir, "EmptyFolder!123")
        self.assertTrue((out_dir / "empty_folder").is_dir())

    def test_cancellation_cleans_up(self) -> None:
        vault = self.root / "cancelled.pfvault"
        cancel = threading.Event()
        cancel.set()

        with self.assertRaises(OperationCancelledError):
            encrypt_folder(
                self.src_dir,
                vault,
                "CancelPass!123",
                cancel_event=cancel,
            )
        self.assertFalse(vault.exists())
        self.assertFalse(vault.with_suffix(".pfvault.tmp").exists())


class TestPasswordUtils(unittest.TestCase):
    def test_password_strength_and_generator(self) -> None:
        weak = evaluate_password("12345")
        self.assertLessEqual(weak.score, 1)

        generated = generate_strong_password(20)
        self.assertEqual(len(generated), 20)
        strong = evaluate_password(generated)
        self.assertEqual(strong.score, 4)
        self.assertTrue(all([strong.has_lower, strong.has_upper, strong.has_digit, strong.has_symbol]))


if __name__ == "__main__":
    unittest.main()
