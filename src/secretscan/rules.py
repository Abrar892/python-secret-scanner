"""Built-in detection rules.

Each rule is a named, severity-graded regular expression for one class of
credential. Patterns are deliberately anchored to the shape of the real
token (prefix, alphabet, length) so that ordinary words and placeholders
such as ``"your-api-key-here"`` do not match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    """One detection rule.

    Attributes:
        id: Stable machine-readable identifier, e.g. ``"aws-access-key"``.
        name: Human-readable name shown in reports.
        severity: ``"high"``, ``"medium"`` or ``"low"``.
        pattern: Compiled regex with a single group capturing the secret.
        description: Why a match matters and what to do about it.
        examples: Sample values that must match (used by the test-suite).
        non_matches: Sample values that must NOT match.
    """

    id: str
    name: str
    severity: str
    pattern: re.Pattern[str]
    description: str
    examples: tuple[str, ...] = ()
    non_matches: tuple[str, ...] = ()


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def builtin_rules() -> list[Rule]:
    """Return the full built-in rule set, ordered by severity then id."""
    rules = [
        Rule(
            id="aws-access-key",
            name="AWS Access Key ID",
            severity="high",
            pattern=_r(r"\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[0-9A-Z]{16})\b"),
            description="AWS access key ID. Rotate it in IAM and check CloudTrail for use.",
            examples=("AKIAIOSFODNN7EXAMPLE", "ASIAY34FZKBOKM0UTE01"),
            non_matches=("AKIAIOSFODNN7", "akiaiosfodnn7example"),
        ),
        Rule(
            id="aws-secret-key",
            name="AWS Secret Access Key",
            severity="high",
            pattern=_r(r"""(?i)aws_secret_access_key["'\s:=]+([A-Za-z0-9/+=]{40})"""),
            description="AWS secret access key. Rotate it in IAM immediately.",
            examples=('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
                      "aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"),
            non_matches=("aws_secret_access_key = ", "aws_secret_access_key = 'short'"),
        ),
        Rule(
            id="github-pat",
            name="GitHub Personal Access Token",
            severity="high",
            pattern=_r(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
            description="GitHub token. Revoke it at github.com/settings/tokens.",
            examples=("ghp_" + "a" * 36, "github_pat_" + "A1_" * 11),
            non_matches=("ghp_short", "ghp_" + "a" * 10),
        ),
        Rule(
            id="github-oauth",
            name="GitHub OAuth Access Token",
            severity="high",
            pattern=_r(r"\b(gho_[A-Za-z0-9]{36,255})\b"),
            description="GitHub OAuth token. Revoke it at github.com/settings/tokens.",
            examples=("gho_" + "b" * 36,),
            non_matches=("gho_" + "b" * 10,),
        ),
        Rule(
            id="slack-token",
            name="Slack Token",
            severity="high",
            pattern=_r(r"\b(xox[baprs]-[A-Za-z0-9-]{10,48})\b"),
            description="Slack API token. Revoke it in the Slack app settings.",
            examples=("xoxb-abc123def456ghi789",),
            non_matches=("xoxb-short", "xoxz-1234567890"),
        ),
        Rule(
            id="slack-webhook",
            name="Slack Webhook URL",
            severity="high",
            pattern=_r(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24})"),
            description="Slack incoming-webhook URL. Rotate it in the Slack app settings.",
            # Built by concatenation so the literal URL never appears in the
            # source — GitHub's own push protection would otherwise block it.
            examples=(
                "https://hooks.slack.com/services/T" + "A" * 8 + "/B" + "A" * 8 + "/" + "X" * 24,
            ),
            non_matches=("https://hooks.slack.com/services/T00/B00/short",),
        ),
        Rule(
            id="stripe-secret-key",
            name="Stripe Secret Key",
            severity="high",
            pattern=_r(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b"),
            description="Live Stripe secret key. Roll it in the Stripe dashboard.",
            examples=("sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" ,),
            non_matches=("sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc", "sk_live_short"),
        ),
        Rule(
            id="private-key",
            name="Private Key Block",
            severity="high",
            pattern=_r(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            description="Private key material committed to the tree. Remove it and rotate the keypair.",
            examples=("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            non_matches=("-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----"),
        ),
        Rule(
            id="google-api-key",
            name="Google API Key",
            severity="high",
            pattern=_r(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            description="Google Cloud API key. Restrict or delete it in Google Cloud Console.",
            examples=("AIza" + "SyA" * 11 + "12",),
            non_matches=("AIzaSyA", "AIza" + "x" * 20),
        ),
        Rule(
            id="jwt",
            name="JSON Web Token",
            severity="medium",
            pattern=_r(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
            description="JWT bearer token. It may be expired, but treat it as live until proven otherwise.",
            examples=("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",),
            non_matches=("eyJhbGciOiJIUzI1NiJ9", "notajwt"),
        ),
        Rule(
            id="sendgrid-api-key",
            name="SendGrid API Key",
            severity="high",
            pattern=_r(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
            description="SendGrid API key. Delete it in the SendGrid dashboard.",
            examples=("SG." + "a" * 22 + "." + "b" * 43,),
            non_matches=("SG." + "a" * 10 + "." + "b" * 10,),
        ),
        Rule(
            id="twilio-api-key",
            name="Twilio API Key",
            severity="high",
            pattern=_r(r"\b(SK[0-9a-fA-F]{32})\b"),
            description="Twilio API key SID. Revoke it in the Twilio console.",
            examples=("SK" + "0123456789abcdef" * 2,),
            non_matches=("SK" + "0123", "SK" + "g" * 32),
        ),
        Rule(
            id="npm-token",
            name="npm Access Token",
            severity="high",
            pattern=_r(r"\b(npm_[A-Za-z0-9]{36})\b"),
            description="npm access token. Revoke it at npmjs.com/settings/tokens.",
            examples=("npm_" + "c" * 36,),
            non_matches=("npm_" + "c" * 10,),
        ),
        Rule(
            id="pypi-token",
            name="PyPI API Token",
            severity="high",
            pattern=_r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b"),
            description="PyPI API token. Revoke it at pypi.org/manage/account/token.",
            examples=("pypi-AgEIcHlwaS5vcmc" + "A" * 60,),
            non_matches=("pypi-AgEIcHlwaS5vcmc" + "A" * 10,),
        ),
        Rule(
            id="generic-password",
            name="Hardcoded Password Assignment",
            severity="medium",
            pattern=_r(r"""(?i)\b(password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,64})["']"""),
            description="Password assigned in source. Move it to a secret manager or env var.",
            examples=('password = "S3cretP@ssw0rd!"', "passwd: 'hunter2hunter2'"),
            non_matches=('password = ""', 'password = "short"', 'password = os.environ["APP_PASSWORD"]'),
        ),
        Rule(
            id="generic-api-key",
            name="Hardcoded API Key Assignment",
            severity="medium",
            pattern=_r(r"""(?i)\b(api[_-]?key|apikey|client[_-]?secret|access[_-]?token)\s*[:=]\s*["']([^"'\s]{16,128})["']"""),
            description="API key or client secret assigned in source. Move it to env vars.",
            examples=('api_key = "sk-9f2kd83jf92kd83jf92kd83"', 'client_secret: "a1b2c3d4e5f6a1b2c3d4e5f6"'),
            non_matches=('api_key = ""', 'api_key = "placeholder"', 'api_key = os.getenv("API_KEY")'),
        ),
        Rule(
            id="basic-auth-url",
            name="Credentials Embedded in URL",
            severity="high",
            pattern=_r(r"""(?i)\b[a-z][a-z0-9+.-]*://([A-Za-z0-9_.\-]{3,}:[^/@\s]{4,})@"""),
            description="Username and password embedded in a URL. Use a credential store instead.",
            examples=("https://admin:s3cretPass@db.internal.example.com:5432/app",
                      "postgres://user:hunter2hunter@db.example.com/mydb"),
            non_matches=("https://example.com/path", "https://user@example.com/"),
        ),
    ]
    return sorted(rules, key=lambda r: (r.severity != "high", r.id))
