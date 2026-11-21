"""Shannon-entropy helpers for the generic high-entropy detector.

A long string drawn from a large alphabet (base64, hex, base62) with high
entropy is unlikely to be an English word or a placeholder. Entropy alone
is a weak signal, so the detector in :mod:`secretscan.scanner` only fires
on quoted strings that also look like tokens: no spaces, a mixed alphabet,
and a minimum length.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Quoted strings worth measuring: at least 20 chars, no whitespace inside.
_QUOTED_RE = re.compile(r"""["']([^"'\s]{20,128})["']""")

# Strings made only of these characters are never tokens.
_TRIVIAL_RE = re.compile(r"^(.)\1+$|^(?:0x)?0+$|^[a-z]+$|^[A-Z]+$|^[0-9]+$")

_COMMON_WORDS = frozenset(
    {
        "password", "username", "example", "placeholder", "lorem", "ipsum",
        "dolor", "amet", "secret", "token", "apikey", "changeme",
    }
)


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of *text* in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_token(value: str) -> bool:
    """Heuristic: does *value* look like a generated token rather than prose?

    Requires a mixed alphabet (at least two of lower/upper/digit/symbol),
    no dictionary word dominating the string, and no repeated-character run.
    """
    if _TRIVIAL_RE.match(value):
        return False
    lowered = value.lower()
    if any(word in lowered for word in _COMMON_WORDS):
        return False
    classes = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )
    return classes >= 2


def high_entropy_strings(line: str, min_entropy: float = 4.5) -> list[tuple[int, str, float]]:
    """Find quoted high-entropy strings in *line*.

    Returns ``(column, value, entropy)`` triples, 0-based column of the
    opening quote. Strings already covered by a provider rule are the
    caller's job to filter out.
    """
    found: list[tuple[int, str, float]] = []
    for match in _QUOTED_RE.finditer(line):
        value = match.group(1)
        if not looks_like_token(value):
            continue
        entropy = shannon_entropy(value)
        if entropy >= min_entropy:
            found.append((match.start(), value, entropy))
    return found
