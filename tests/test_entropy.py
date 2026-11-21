"""Entropy helper tests."""

import pytest

from secretscan.entropy import high_entropy_strings, looks_like_token, shannon_entropy


def test_shannon_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    # Two equally likely symbols -> exactly 1 bit per character.
    assert shannon_entropy("abababab") == pytest.approx(1.0)
    # Uniform over 16 hex digits -> 4 bits per character.
    assert shannon_entropy("0123456789abcdef") == pytest.approx(4.0)


def test_looks_like_token_rejects_prose():
    assert not looks_like_token("hello")
    assert not looks_like_token("password")
    assert not looks_like_token("aaaaaaaaaaaaaaaaaaaa")
    assert not looks_like_token("12345678901234567890")
    assert not looks_like_token("my-api-key-placeholder")


def test_looks_like_token_accepts_mixed():
    assert looks_like_token("aB3dE9xQ2mZ8pL4vN7w")
    assert looks_like_token("xK9$mQ2vL8#pR4tY6w")


def test_high_entropy_strings_finds_token():
    line = 'token = "Xk9mQ2vL8pR4tY6wN3bV7cD1fH5jK"'
    found = high_entropy_strings(line)
    assert len(found) == 1
    assert found[0][1] == "Xk9mQ2vL8pR4tY6wN3bV7cD1fH5jK"
    assert found[0][2] >= 4.5


def test_high_entropy_strings_ignores_low_entropy():
    line = 'greeting = "hello world this is a sentence"'
    assert high_entropy_strings(line) == []


def test_high_entropy_strings_respects_threshold():
    line = 'token = "Xk9mQ2vL8pR4tY6wN3bV7cD1fH5jK"'
    assert high_entropy_strings(line, min_entropy=6.0) == []
