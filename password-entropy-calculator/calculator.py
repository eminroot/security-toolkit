#!/usr/bin/env python3
"""
Password Entropy Calculator
Calculates entropy, strength scoring, and provides actionable recommendations.
"""

import math
import re
import string
import sys
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class StrengthResult:
    entropy: float
    strength: str
    score: int
    feedback: List[str]
    charset_bits: float


def analyze_charset(password: str) -> Tuple[int, float]:
    """Analyze character set used and return size + bits per char."""
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 32
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32
    # Extended/special
    if any(ord(c) > 127 for c in password):
        charset_size += 128

    charset_size = max(charset_size, 26)
    bits_per_char = math.log2(charset_size)
    return charset_size, bits_per_char


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy in bits."""
    charset_size, bits_per_char = analyze_charset(password)
    return len(password) * bits_per_char


def check_patterns(password: str) -> List[str]:
    """Check for weak patterns."""
    feedback = []
    pwd_lower = password.lower()

    weak_patterns = [
        (r"^[0-9]+$", "Contains only numbers"),
        (r"^[a-z]+$", "Contains only lowercase"),
        (r"password|123456|qwerty|admin|letmein", "Contains common word"),
        (r"(.)\1{2,}", "Has repeated characters"),
        (r"^[a-zA-Z]+$", "No numbers or symbols"),
        (r"(.)\1", "Has consecutive repeats"),
    ]
    for pattern, msg in weak_patterns:
        if re.search(pattern, pwd_lower):
            feedback.append(f"- {msg}")

    if len(password) < 8:
        feedback.append("- Too short (min 12 recommended)")
    elif len(password) < 12:
        feedback.append("- Consider 12+ characters")

    if not any(c in string.punctuation for c in password):
        feedback.append("- Add special characters")

    return feedback


def evaluate_strength(password: str) -> StrengthResult:
    """Full password evaluation."""
    entropy = calculate_entropy(password)
    feedback = check_patterns(password)

    # Score 0-100
    score = min(100, int(entropy * 2) - len(feedback) * 5)
    score = max(0, score)

    if entropy < 28 or score < 30:
        strength = "Very Weak"
    elif entropy < 36 or score < 50:
        strength = "Weak"
    elif entropy < 48 or score < 70:
        strength = "Fair"
    elif entropy < 60 or score < 85:
        strength = "Strong"
    else:
        strength = "Very Strong"
        feedback.append("+ Good password!")

    _, bits_per_char = analyze_charset(password)
    return StrengthResult(
        entropy=entropy,
        strength=strength,
        score=score,
        feedback=feedback,
        charset_bits=bits_per_char,
    )


def main():
    pwd = sys.argv[1] if len(sys.argv) > 1 else None
    if not pwd:
        try:
            import getpass
            pwd = getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            print("Cancelled")
            sys.exit(0)

    if not pwd:
        print("Error: No password provided")
        sys.exit(1)

    result = evaluate_strength(pwd)

    print("=" * 50)
    print("PASSWORD STRENGTH ANALYSIS")
    print("=" * 50)
    print(f"Length:        {len(pwd)} characters")
    print(f"Entropy:       {result.entropy:.1f} bits")
    print(f"Strength:      {result.strength}")
    print(f"Score:         {result.score}/100")
    print(f"Charset:       ~{result.charset_bits:.1f} bits/char")
    print()
    if result.feedback:
        print("Feedback:")
        for f in result.feedback:
            print(f"  {f}")
    print("=" * 50)


if __name__ == "__main__":
    main()
