"""SecretScan — fast secret scanner for source trees.

Detects leaked credentials in code and config files using a curated set of
provider-specific patterns plus a Shannon-entropy detector for generic
high-entropy tokens. Zero third-party dependencies.
"""

from .scanner import Finding, ScanResult, Scanner
from .rules import Rule, builtin_rules

__all__ = ["Finding", "ScanResult", "Scanner", "Rule", "builtin_rules"]
__version__ = "1.0.0"
