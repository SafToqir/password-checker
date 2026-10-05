"""Password strength checker.

Scores a password from 0 (very weak) to 4 (very strong) by estimating its
entropy and penalising common passwords and predictable patterns. Can also
check the Have I Been Pwned breach database using k-anonymity, so the
password itself never leaves your machine.
"""

import argparse
import getpass
import hashlib
import math
import re
import string
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321", "superman",
    "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe", "killer",
    "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313",
    "freedom", "777777", "pass", "maggie", "159753", "aaaaaa", "ginger",
    "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley",
    "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix", "welcome", "admin",
    "password1", "password123", "qwerty123", "login", "passw0rd", "liverpool",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                          "7": "t", "@": "a", "$": "s", "!": "i"})
LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


@dataclass
class Result:
    score: int
    label: str
    entropy_bits: float
    feedback: list = field(default_factory=list)
    breach_count: int | None = None


def charset_size(password: str) -> int:
    """Size of the character pool the password draws from."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    if any(not c.isascii() for c in password):
        size += 100
    return size


def has_sequence(password: str, length: int = 4) -> bool:
    """True if the password contains a run like 'abcd', '4321' or 'asdf'."""
    lower = password.lower()
    sources = [string.ascii_lowercase, string.digits] + KEYBOARD_ROWS
    for source in sources:
        for seq in (source, source[::-1]):
            for i in range(len(seq) - length + 1):
                if seq[i:i + length] in lower:
                    return True
    return False


def has_repeats(password: str) -> bool:
    """True for 3+ identical characters in a row, or a repeated chunk like 'abcabc'."""
    return bool(re.search(r"(.)\1\1", password) or re.search(r"(.{2,})\1", password))


def check_breach(password: str, timeout: float = 5.0) -> int:
    """Return how many times the password appears in known breaches.

    Only the first 5 characters of the SHA-1 hash are sent (k-anonymity), so
    neither the password nor its full hash leaves this machine.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "password-checker-cli"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for line in resp.read().decode().splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
    return 0


def evaluate(password: str, breach_check: bool = False) -> Result:
    feedback = []
    entropy = len(password) * math.log2(charset_size(password)) if password else 0.0

    normalised = password.lower().translate(LEET_MAP)
    if password.lower() in COMMON_PASSWORDS or normalised in COMMON_PASSWORDS:
        feedback.append("This is one of the most common passwords.")
        entropy = min(entropy, 10)
    base_word = re.sub(r"[\d\W_]+$", "", password.lower())
    if base_word != password.lower() and (base_word in COMMON_PASSWORDS or base_word.translate(LEET_MAP) in COMMON_PASSWORDS):
        feedback.append(f"It's built on a common password ('{base_word}') with extra characters added.")
        entropy *= 0.6
    if has_sequence(password):
        feedback.append("Avoid sequences like 'abcd', '1234' or 'qwerty'.")
        entropy *= 0.75
    if has_repeats(password):
        feedback.append("Avoid repeated characters or chunks like 'aaa' or 'abcabc'.")
        entropy *= 0.75
    if re.fullmatch(r"[A-Za-z]+[0-9]{1,4}[!@#$%?.]?", password):
        feedback.append("A word followed by a number or year is one of the first patterns attackers try.")
        entropy *= 0.6
    if len(password) < 12:
        feedback.append("Use at least 12 characters.")
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        feedback.append("Mix upper and lower case letters.")
    if not any(c.isdigit() for c in password):
        feedback.append("Add a number.")
    if not any(c in string.punctuation for c in password):
        feedback.append("Add a symbol.")

    thresholds = [28, 36, 60, 80]  # entropy bits for scores 1-4
    score = sum(entropy >= t for t in thresholds)

    breach_count = None
    if breach_check and password:
        try:
            breach_count = check_breach(password)
        except (urllib.error.URLError, TimeoutError):
            feedback.append("Couldn't reach the breach database, so that check was skipped.")
        else:
            if breach_count:
                feedback.insert(0, f"Found in {breach_count:,} data breaches. Don't use it.")
                score = 0

    return Result(score, LABELS[score], round(entropy, 1), feedback, breach_count)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check how strong a password is.")
    parser.add_argument("--no-breach-check", action="store_true",
                        help="skip the Have I Been Pwned lookup")
    args = parser.parse_args()

    password = getpass.getpass("Password (input hidden): ")
    result = evaluate(password, breach_check=not args.no_breach_check)

    bar = "█" * (result.score + 1) + "░" * (4 - result.score)
    print(f"\nStrength: {bar} {result.label} ({result.entropy_bits} bits)")
    if result.breach_count == 0:
        print("Not found in any known data breaches.")
    for tip in result.feedback:
        print(f"  - {tip}")
    return 0 if result.score >= 3 else 1


if __name__ == "__main__":
    sys.exit(main())
