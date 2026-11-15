"""Password strength analysis and cryptographically secure password generation."""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordAssessment:
    """Result of evaluating a password's strength."""

    score: int  # 0 to 4
    label: str  # Empty, Very Weak, Weak, Fair, Strong, Very Strong
    entropy_bits: float
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    length_ok: bool
    feedback: str


def evaluate_password(password: str) -> PasswordAssessment:
    """Estimate password entropy and return actionable strength feedback."""
    if not password:
        return PasswordAssessment(
            score=0,
            label="Empty",
            entropy_bits=0.0,
            has_lower=False,
            has_upper=False,
            has_digit=False,
            has_symbol=False,
            length_ok=False,
            feedback="Enter a strong password (12+ characters recommended).",
        )

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    length_ok = len(password) >= 12

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32

    unique_ratio = len(set(password)) / len(password)
    raw_bits = len(password) * math.log2(max(pool_size, 1))
    entropy_bits = raw_bits * (0.5 + 0.5 * unique_ratio)

    if len(password) < 8 or entropy_bits < 36:
        score = 1
        label = "Weak"
    elif entropy_bits < 55:
        score = 2
        label = "Fair"
    elif entropy_bits < 75:
        score = 3
        label = "Strong"
    else:
        score = 4
        label = "Very Strong"

    tips: list[str] = []
    if not length_ok:
        tips.append("use 12+ chars")
    if not has_upper:
        tips.append("add uppercase")
    if not has_lower:
        tips.append("add lowercase")
    if not has_digit:
        tips.append("add digits")
    if not has_symbol:
        tips.append("add symbols")

    feedback = (
        f"~{entropy_bits:.0f} bits"
        + (f" — Tip: {', '.join(tips)}" if tips and score < 4 else " — Good entropy")
    )

    return PasswordAssessment(
        score=score,
        label=label,
        entropy_bits=entropy_bits,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        length_ok=length_ok,
        feedback=feedback,
    )


def generate_strong_password(length: int = 20) -> str:
    """Generate a cryptographically random password with all character classes."""
    length = max(length, 12)
    symbols = "!@#$%^&*()-_=+[]{}:;,.?"
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + symbols

    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(symbols),
    ]
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + rest
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def format_bytes(num_bytes: int) -> str:
    """Format a byte count into a human-readable string."""
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{num_bytes} B"
