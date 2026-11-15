"""Cryptographic engine for folder encryption and password protection.

Uses industry-standard authenticated encryption:
- Key Derivation: Argon2id (default, RFC 9106) or PBKDF2-HMAC-SHA256
- Cipher: Chunked AES-256-GCM (AEAD) with per-chunk nonces and header-bound AAD
- Container: Versioned .pfvault binary format wrapping a ZIP64 archive
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"PFVAULT1"
FORMAT_VERSION = 1
HEADER_STRUCT = struct.Struct(">8sBBBBIIII16s12sQ")
CHUNK_FRAME_STRUCT = struct.Struct(">IB")
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256-bit AES key

# Default KDF parameters (OWASP 2024+ recommendations)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536  # 64 MiB
ARGON2_LANES = 4
PBKDF2_ITERATIONS = 600_000


class KdfType(IntEnum):
    """Supported key derivation functions."""

    ARGON2ID = 1
    PBKDF2_SHA256 = 2


class CipherType(IntEnum):
    """Supported AEAD ciphers."""

    AES_256_GCM = 1


class CompressionLevel(IntEnum):
    """ZIP archive compression modes."""

    NONE = 0
    FAST = 1
    BALANCED = 6
    MAXIMUM = 9


class CryptoError(Exception):
    """Base error for vault operations."""


class InvalidVaultError(CryptoError):
    """Raised when a file is not a valid or supported .pfvault container."""


class AuthenticationError(CryptoError):
    """Raised when password is incorrect or encrypted data was tampered with."""


class OperationCancelledError(CryptoError):
    """Raised when an operation is cancelled via a cancellation event."""


@dataclass(frozen=True)
class VaultHeader:
    """Parsed metadata from a .pfvault file header."""

    version: int
    kdf: KdfType
    cipher: CipherType
    flags: int
    chunk_size: int
    kdf_param_1: int
    kdf_param_2: int
    kdf_param_3: int
    salt: bytes
    base_nonce: bytes
    created_timestamp: int
    raw_bytes: bytes

    @property
    def kdf_description(self) -> str:
        """Human-readable summary of KDF settings."""
        if self.kdf == KdfType.ARGON2ID:
            mem_mib = self.kdf_param_2 // 1024
            return (
                f"Argon2id (t={self.kdf_param_1}, "
                f"m={mem_mib} MiB, p={self.kdf_param_3})"
            )
        if self.kdf == KdfType.PBKDF2_SHA256:
            return f"PBKDF2-HMAC-SHA256 ({self.kdf_param_1:,} iterations)"
        return f"Unknown ({self.kdf})"

    @property
    def cipher_description(self) -> str:
        """Human-readable cipher name."""
        if self.cipher == CipherType.AES_256_GCM:
            return "AES-256-GCM (AEAD)"
        return f"Unknown ({self.cipher})"


@dataclass(frozen=True)
class FolderStats:
    """Summary statistics for a directory."""

    file_count: int
    dir_count: int
    total_bytes: int


@dataclass(frozen=True)
class OperationResult:
    """Result returned by encrypt, decrypt, or verify operations."""

    output_path: Optional[Path]
    files_processed: int
    bytes_processed: int
    elapsed_seconds: float
    kdf_description: str
    cipher_description: str


ProgressCallback = Callable[[str, float, Optional[str]], None]


def scan_folder(folder_path: Path) -> FolderStats:
    """Count files, subdirectories, and total byte size in a folder."""
    if not folder_path.is_dir():
        raise FileNotFoundError(f"Folder not found: {folder_path}")

    file_count = 0
    dir_count = 0
    total_bytes = 0

    for root, dirs, files in os.walk(folder_path):
        dir_count += len(dirs)
        for name in files:
            file_count += 1
            file_path = Path(root) / name
            try:
                total_bytes += file_path.stat().st_size
            except OSError:
                pass

    return FolderStats(
        file_count=file_count,
        dir_count=dir_count,
        total_bytes=total_bytes,
    )


def inspect_vault(vault_path: Path) -> VaultHeader:
    """Read and validate the 64-byte header of a .pfvault file."""
    if not vault_path.is_file():
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    with vault_path.open("rb") as f:
        raw = f.read(HEADER_STRUCT.size)

    if len(raw) < HEADER_STRUCT.size:
        raise InvalidVaultError("File is too small to be a valid .pfvault archive.")

    (
        magic,
        version,
        kdf_id,
        cipher_id,
        flags,
        chunk_size,
        p1,
        p2,
        p3,
        salt,
        base_nonce,
        created_ts,
    ) = HEADER_STRUCT.unpack(raw)

    if magic != MAGIC:
        raise InvalidVaultError("Invalid file signature (not a .pfvault archive).")
    if version != FORMAT_VERSION:
        raise InvalidVaultError(f"Unsupported vault format version: {version}.")
    if chunk_size <= 0 or chunk_size > 64 * 1024 * 1024:
        raise InvalidVaultError(f"Invalid chunk size in header: {chunk_size}.")

    try:
        kdf = KdfType(kdf_id)
    except ValueError as exc:
        raise InvalidVaultError(f"Unsupported KDF identifier: {kdf_id}.") from exc

    try:
        cipher = CipherType(cipher_id)
    except ValueError as exc:
        raise InvalidVaultError(f"Unsupported cipher identifier: {cipher_id}.") from exc

    return VaultHeader(
        version=version,
        kdf=kdf,
        cipher=cipher,
        flags=flags,
        chunk_size=chunk_size,
        kdf_param_1=p1,
        kdf_param_2=p2,
        kdf_param_3=p3,
        salt=salt,
        base_nonce=base_nonce,
        created_timestamp=created_ts,
        raw_bytes=raw,
    )


def _derive_key(password: str, header: VaultHeader) -> bytes:
    """Derive a 256-bit encryption key from password and header parameters."""
    password_bytes = password.encode("utf-8")

    if header.kdf == KdfType.ARGON2ID:
        kdf = Argon2id(
            salt=header.salt,
            length=KEY_SIZE,
            iterations=header.kdf_param_1,
            memory_cost=header.kdf_param_2,
            lanes=header.kdf_param_3,
        )
        return kdf.derive(password_bytes)

    if header.kdf == KdfType.PBKDF2_SHA256:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=header.salt,
            iterations=header.kdf_param_1,
        )
        return kdf.derive(password_bytes)

    raise InvalidVaultError(f"Unsupported KDF: {header.kdf}")


def _chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Derive a unique 96-bit nonce for chunk_index from the base nonce."""
    base_int = int.from_bytes(base_nonce, "big")
    derived = (base_int + chunk_index) & ((1 << 96) - 1)
    return derived.to_bytes(NONCE_SIZE, "big")


def _check_cancelled(cancel_event: Optional[threading.Event]) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise OperationCancelledError("Operation cancelled by user.")


def _emit_progress(
    callback: Optional[ProgressCallback],
    stage: str,
    fraction: float,
    detail: Optional[str] = None,
) -> None:
    if callback is not None:
        callback(stage, max(0.0, min(1.0, fraction)), detail)


def _archive_folder_to_zip(
    folder_path: Path,
    zip_path: Path,
    compression: CompressionLevel,
    progress_cb: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> tuple[int, int]:
    """Pack folder_path (preserving root folder name and empty dirs) into zip_path."""
    entries: list[tuple[Path, str, bool]] = []
    root_name = folder_path.name

    for current_root, dirs, files in os.walk(folder_path):
        rel_root = Path(current_root).relative_to(folder_path)
        arc_dir = (Path(root_name) / rel_root).as_posix()
        if not dirs and not files:
            entries.append((Path(current_root), arc_dir + "/", True))
        for fname in files:
            full_path = Path(current_root) / fname
            arc_file = (Path(root_name) / rel_root / fname).as_posix()
            entries.append((full_path, arc_file, False))

    if not entries:
        entries.append((folder_path, root_name + "/", True))

    zip_compression = (
        zipfile.ZIP_STORED
        if compression == CompressionLevel.NONE
        else zipfile.ZIP_DEFLATED
    )
    compresslevel = None if compression == CompressionLevel.NONE else int(compression)

    total_items = len(entries)
    total_bytes = 0

    with zipfile.ZipFile(
        zip_path,
        mode="w",
        compression=zip_compression,
        compresslevel=compresslevel,
        allowZip64=True,
    ) as zf:
        for idx, (src_path, arc_name, is_dir) in enumerate(entries, start=1):
            _check_cancelled(cancel_event)
            if is_dir:
                zf.mkdir(arc_name)
            else:
                total_bytes += src_path.stat().st_size
                zf.write(src_path, arcname=arc_name)
            _emit_progress(
                progress_cb,
                "Archiving folder",
                (idx / total_items) * 0.45,
                f"{idx}/{total_items}: {arc_name}",
            )

    return sum(1 for _, _, is_dir in entries if not is_dir), total_bytes


def _safe_extract_zip(
    zip_path: Path,
    dest_dir: Path,
    progress_cb: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> tuple[int, int]:
    """Extract a ZIP archive into dest_dir with Zip-Slip path traversal protection."""
    dest_resolved = dest_dir.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, mode="r") as zf:
        members = zf.infolist()
        total = max(len(members), 1)
        files_extracted = 0
        bytes_extracted = 0

        for idx, info in enumerate(members, start=1):
            _check_cancelled(cancel_event)
            target_path = (dest_resolved / info.filename).resolve()
            if (
                target_path != dest_resolved
                and dest_resolved not in target_path.parents
            ):
                raise InvalidVaultError(
                    f"Unsafe archive path detected: {info.filename}"
                )

            if info.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, target_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                files_extracted += 1
                bytes_extracted += info.file_size

            _emit_progress(
                progress_cb,
                "Extracting files",
                0.65 + (idx / total) * 0.35,
                f"{idx}/{len(members)}: {info.filename}",
            )

    return files_extracted, bytes_extracted


def encrypt_folder(
    folder_path: Path,
    output_path: Path,
    password: str,
    *,
    kdf: KdfType = KdfType.ARGON2ID,
    compression: CompressionLevel = CompressionLevel.BALANCED,
    delete_original: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: Optional[ProgressCallback] = None,
    cancel_event: Optional[threading.Event] = None,
) -> OperationResult:
    """Archive and encrypt folder_path into output_path using AES-256-GCM."""
    if not folder_path.is_dir():
        raise FileNotFoundError(f"Source folder does not exist: {folder_path}")
    if not password:
        raise ValueError("Password must not be empty.")

    start_time = time.perf_counter()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if kdf == KdfType.ARGON2ID:
        p1, p2, p3 = ARGON2_TIME_COST, ARGON2_MEMORY_COST_KIB, ARGON2_LANES
    elif kdf == KdfType.PBKDF2_SHA256:
        p1, p2, p3 = PBKDF2_ITERATIONS, 0, 0
    else:
        raise ValueError(f"Unsupported KDF: {kdf}")

    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(NONCE_SIZE)
    created_ts = int(time.time())

    raw_header = HEADER_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION,
        int(kdf),
        int(CipherType.AES_256_GCM),
        0,
        chunk_size,
        p1,
        p2,
        p3,
        salt,
        base_nonce,
        created_ts,
    )
    header = VaultHeader(
        version=FORMAT_VERSION,
        kdf=kdf,
        cipher=CipherType.AES_256_GCM,
        flags=0,
        chunk_size=chunk_size,
        kdf_param_1=p1,
        kdf_param_2=p2,
        kdf_param_3=p3,
        salt=salt,
        base_nonce=base_nonce,
        created_timestamp=created_ts,
        raw_bytes=raw_header,
    )

    with tempfile.TemporaryDirectory(prefix="pfvault_enc_") as tmp_dir:
        tmp_zip = Path(tmp_dir) / "payload.zip"
        tmp_out = output_path.with_suffix(output_path.suffix + ".tmp")

        try:
            file_count, raw_bytes_count = _archive_folder_to_zip(
                folder_path, tmp_zip, compression, progress_cb, cancel_event
            )

            _check_cancelled(cancel_event)
            _emit_progress(
                progress_cb,
                "Deriving encryption key",
                0.48,
                header.kdf_description,
            )
            key = _derive_key(password, header)
            aesgcm = AESGCM(key)

            zip_size = tmp_zip.stat().st_size
            bytes_encrypted = 0
            chunk_index = 0

            with tmp_zip.open("rb") as src, tmp_out.open("wb") as dst:
                dst.write(raw_header)

                while True:
                    _check_cancelled(cancel_event)
                    chunk = src.read(chunk_size)
                    next_peek = src.read(1)
                    if next_peek:
                        src.seek(-1, os.SEEK_CUR)
                        is_final = 0
                    else:
                        is_final = 1

                    nonce = _chunk_nonce(base_nonce, chunk_index)
                    aad = raw_header + struct.pack(">QB", chunk_index, is_final)
                    ciphertext = aesgcm.encrypt(nonce, chunk, aad)

                    dst.write(CHUNK_FRAME_STRUCT.pack(len(ciphertext), is_final))
                    dst.write(ciphertext)

                    bytes_encrypted += len(chunk)
                    chunk_index += 1

                    frac = 0.50 + (
                        (bytes_encrypted / max(zip_size, 1)) * 0.48
                    )
                    _emit_progress(
                        progress_cb,
                        "Encrypting (AES-256-GCM)",
                        frac,
                        f"Chunk {chunk_index}",
                    )

                    if is_final == 1:
                        break

            os.replace(tmp_out, output_path)
        except Exception:
            if tmp_out.exists():
                tmp_out.unlink(missing_ok=True)
            raise

    if delete_original:
        _emit_progress(
            progress_cb,
            "Removing original folder",
            0.99,
            str(folder_path),
        )
        shutil.rmtree(folder_path)

    _emit_progress(progress_cb, "Completed", 1.0, str(output_path))
    elapsed = time.perf_counter() - start_time

    return OperationResult(
        output_path=output_path,
        files_processed=file_count,
        bytes_processed=raw_bytes_count,
        elapsed_seconds=elapsed,
        kdf_description=header.kdf_description,
        cipher_description=header.cipher_description,
    )


def _decrypt_to_zip(
    vault_path: Path,
    password: str,
    dest_zip: Optional[Path],
    progress_cb: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> tuple[VaultHeader, int]:
    """Decrypt and authenticate all chunks; optionally write plaintext zip."""
    header = inspect_vault(vault_path)
    _check_cancelled(cancel_event)

    _emit_progress(
        progress_cb,
        "Deriving decryption key",
        0.10,
        header.kdf_description,
    )
    key = _derive_key(password, header)
    aesgcm = AESGCM(key)

    vault_size = vault_path.stat().st_size
    payload_total = max(vault_size - HEADER_STRUCT.size, 1)
    bytes_read = 0
    chunk_index = 0
    saw_final = False

    out_handle = dest_zip.open("wb") if dest_zip is not None else None
    try:
        with vault_path.open("rb") as src:
            src.seek(HEADER_STRUCT.size)

            while True:
                _check_cancelled(cancel_event)
                frame = src.read(CHUNK_FRAME_STRUCT.size)
                if not frame:
                    if not saw_final:
                        raise AuthenticationError(
                            "Vault file is truncated or missing final chunk."
                        )
                    break

                if len(frame) < CHUNK_FRAME_STRUCT.size:
                    raise InvalidVaultError("Corrupted chunk header in vault.")

                ct_len, is_final = CHUNK_FRAME_STRUCT.unpack(frame)
                if is_final not in (0, 1):
                    raise InvalidVaultError("Invalid chunk flag in vault.")

                ciphertext = src.read(ct_len)
                if len(ciphertext) != ct_len:
                    raise AuthenticationError(
                        "Vault file is truncated inside encrypted chunk."
                    )

                nonce = _chunk_nonce(header.base_nonce, chunk_index)
                aad = header.raw_bytes + struct.pack(">QB", chunk_index, is_final)

                try:
                    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
                except InvalidTag as exc:
                    raise AuthenticationError(
                        "Incorrect password or corrupted/tampered vault data."
                    ) from exc

                if out_handle is not None:
                    out_handle.write(plaintext)

                bytes_read += CHUNK_FRAME_STRUCT.size + ct_len
                chunk_index += 1

                max_frac = 0.98 if dest_zip is None else 0.62
                frac = 0.15 + (bytes_read / payload_total) * (max_frac - 0.15)
                _emit_progress(
                    progress_cb,
                    "Verifying & decrypting" if dest_zip else "Verifying integrity",
                    frac,
                    f"Chunk {chunk_index}",
                )

                if is_final == 1:
                    trailing = src.read(1)
                    if trailing:
                        raise AuthenticationError(
                            "Unexpected trailing data after final vault chunk."
                        )
                    saw_final = True
                    break
    finally:
        if out_handle is not None:
            out_handle.close()

    return header, chunk_index


def decrypt_vault(
    vault_path: Path,
    dest_dir: Path,
    password: str,
    *,
    progress_cb: Optional[ProgressCallback] = None,
    cancel_event: Optional[threading.Event] = None,
) -> OperationResult:
    """Authenticate, decrypt, and extract a .pfvault archive into dest_dir."""
    if not password:
        raise ValueError("Password must not be empty.")

    start_time = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="pfvault_dec_") as tmp_dir:
        tmp_zip = Path(tmp_dir) / "decrypted.zip"
        header, _ = _decrypt_to_zip(
            vault_path, password, tmp_zip, progress_cb, cancel_event
        )
        files_extracted, bytes_extracted = _safe_extract_zip(
            tmp_zip, dest_dir, progress_cb, cancel_event
        )

    _emit_progress(progress_cb, "Completed", 1.0, str(dest_dir))
    elapsed = time.perf_counter() - start_time

    return OperationResult(
        output_path=dest_dir,
        files_processed=files_extracted,
        bytes_processed=bytes_extracted,
        elapsed_seconds=elapsed,
        kdf_description=header.kdf_description,
        cipher_description=header.cipher_description,
    )


def verify_vault(
    vault_path: Path,
    password: str,
    *,
    progress_cb: Optional[ProgressCallback] = None,
    cancel_event: Optional[threading.Event] = None,
) -> OperationResult:
    """Verify password and AES-256-GCM integrity of a vault without extracting."""
    if not password:
        raise ValueError("Password must not be empty.")

    start_time = time.perf_counter()
    header, chunks = _decrypt_to_zip(
        vault_path, password, None, progress_cb, cancel_event
    )
    _emit_progress(progress_cb, "Integrity verified", 1.0, f"{chunks} chunk(s) valid")
    elapsed = time.perf_counter() - start_time

    return OperationResult(
        output_path=None,
        files_processed=chunks,
        bytes_processed=vault_path.stat().st_size,
        elapsed_seconds=elapsed,
        kdf_description=header.kdf_description,
        cipher_description=header.cipher_description,
    )
