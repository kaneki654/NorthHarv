"""
engine/card_detector.py

Offline payment-card detection for internet banner data.

Scans raw service banners for accidentally-exposed PAN patterns,
validates candidates with the Luhn algorithm, classifies the card
network from BIN/IIN prefix ranges, and returns *masked* findings
only — no complete card number is retained or returned anywhere.

Public API
----------
scan_banner(banner: str) -> List[CardFinding]
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PAN candidate regex
# ---------------------------------------------------------------------------
# Matches Amex (4-6-5) and standard 16-digit layouts (4-4-4-4),
# with optional single space or hyphen between groups.
# Anchored with negative lookahead/behind to avoid matching inside
# longer digit strings (e.g. Unix timestamps, IP octets in URLs).
_S = r"[ \-]?"   # optional separator

_AMEX = (
    r"3[47]\d{2}" + _S +      # 4 digits
    r"\d{6}" + _S +           # 6 digits
    r"\d{5}"                  # 5 digits  → 15 total
)

_STD16 = (
    # Four-digit first group (the full BIN prefix) followed by three more groups of four.
    # Separators (space or hyphen) are allowed between each group.
    r"(?:"
    r"4\d{3}"                       # Visa        — 4-digit group 1
    r"|5[1-5]\d{2}"                 # MasterCard 51-55
    r"|2[2-7]\d{2}"                 # MasterCard 2221-2720
    r"|6011"                        # Discover 6011
    r"|64\d{2}|65\d{2}"             # Discover 64xx / 65xx
    r"|62\d{2}"                     # UnionPay
    r"|35\d{2}"                     # JCB
    r")"                            # end of group 1 (4 digits)
    + _S + r"\d{4}"                 # group 2
    + _S + r"\d{4}"                 # group 3
    + _S + r"\d{4}"                 # group 4  → 16 digits total
)

_PAN_RE = re.compile(
    r"(?<!\d)"
    r"(" + _AMEX + r"|" + _STD16 + r")"
    r"(?!\d)",
    re.ASCII,
)

# ---------------------------------------------------------------------------
# Expiration date regex: MM/YY — valid months (01-12), year 20-29
# ---------------------------------------------------------------------------
_EXP_RE = re.compile(
    r"\b(0[1-9]|1[0-2])/([2-9][0-9])\b",
    re.ASCII,
)

# ---------------------------------------------------------------------------
# CVV regex: 3-4 digits immediately preceded by a card-security keyword
# (requires keyword context to avoid false-positive 3-digit numbers)
# ---------------------------------------------------------------------------
_CVV_CONTEXT_RE = re.compile(
    r"(?:cvv2?|cvc2?|cv2|cid|security[\s_\-]{0,2}code|card[\s_\-]{0,2}verif\w*)"
    r"[\s:=_\-]{0,10}"
    r"(\d{3,4})\b",
    re.IGNORECASE,
)

# chars each side of a PAN match to search for correlated exp_date / CVV
_CONTEXT_WINDOW = 300

# ---------------------------------------------------------------------------
# Luhn checksum
# ---------------------------------------------------------------------------
def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Offline BIN/IIN classification
# ---------------------------------------------------------------------------
@dataclass
class BINInfo:
    network: str = ""
    issuer: str = ""
    country: str = ""
    funding_type: str = ""   # credit | debit | prepaid


# (lo_6digit_prefix, hi_6digit_prefix, BINInfo)
# Ranges are checked in order; first match wins.
_BIN_RANGES: list[tuple[int, int, BINInfo]] = [
    # American Express
    (340000, 349999, BINInfo("Amex",        "American Express",           "US", "credit")),
    (370000, 379999, BINInfo("Amex",        "American Express",           "US", "credit")),
    # MasterCard 2221-2720 expansion (issued 2017+)
    (222100, 272099, BINInfo("MasterCard",  "MasterCard International",   "US", "credit")),
    # MasterCard classic 51-55
    (510000, 559999, BINInfo("MasterCard",  "MasterCard International",   "US", "credit")),
    # Discover 6011 / 622126-622925 (UnionPay partnership) / 644-649 / 65
    (601100, 601199, BINInfo("Discover",    "Discover Financial",         "US", "credit")),
    (622126, 622925, BINInfo("UnionPay",    "China UnionPay",             "CN", "credit")),
    (640000, 649999, BINInfo("Discover",    "Discover Financial",         "US", "credit")),
    (650000, 659999, BINInfo("Discover",    "Discover Financial",         "US", "credit")),
    # JCB
    (352800, 358999, BINInfo("JCB",         "JCB Co., Ltd.",              "JP", "credit")),
    # UnionPay general
    (620000, 621099, BINInfo("UnionPay",    "China UnionPay",             "CN", "debit")),
    (624000, 626999, BINInfo("UnionPay",    "China UnionPay",             "CN", "debit")),
    (628200, 628899, BINInfo("UnionPay",    "China UnionPay",             "CN", "debit")),
    # Visa (broadest range; keep last so narrower ranges above match first)
    (400000, 499999, BINInfo("Visa",        "Visa International",         "US", "credit")),
]


def _classify_bin(digits: str) -> BINInfo:
    if len(digits) < 6:
        return BINInfo()
    prefix6 = int(digits[:6])
    for lo, hi, info in _BIN_RANGES:
        if lo <= prefix6 <= hi:
            return info
    # Network-only fallback when prefix isn't in the table
    d2 = digits[:2]
    if digits[0] == "4":
        return BINInfo("Visa")
    if d2 in ("51", "52", "53", "54", "55") or digits[:4] in (
            "2221", "2222", "2223", "2224", "2225", "2226", "2227"):
        return BINInfo("MasterCard")
    if d2 in ("34", "37"):
        return BINInfo("Amex")
    if digits[:4] == "6011" or d2 in ("64", "65"):
        return BINInfo("Discover")
    if digits[:2] == "62":
        return BINInfo("UnionPay")
    if digits[:2] == "35":
        return BINInfo("JCB")
    return BINInfo()


# ---------------------------------------------------------------------------
# Masking — BIN6 + asterisks + last4, never expose the full PAN
# ---------------------------------------------------------------------------
def _mask_pan(digits: str) -> str:
    n = len(digits)
    if n <= 10:
        return "*" * n
    return digits[:6] + "*" * (n - 10) + digits[-4:]


# ---------------------------------------------------------------------------
# Noise / false-positive filters
# ---------------------------------------------------------------------------
def _is_noise(digits: str) -> bool:
    """True for obviously synthetic digit strings unlikely to be real PANs."""
    # All identical digits (e.g. "0000000000000000")
    if len(set(digits)) == 1:
        return True
    # Perfectly monotone sequence (e.g. "1234567890123456")
    diffs = [int(digits[i + 1]) - int(digits[i]) for i in range(len(digits) - 1)]
    if len(set(diffs)) == 1:
        return True
    return False


# ---------------------------------------------------------------------------
# Public dataclass + scan function
# ---------------------------------------------------------------------------
@dataclass
class CardFinding:
    masked_pan: str       # e.g. "411111******1111"
    bin_prefix: str       # first 6 digits (the IIN)
    card_network: str     # Visa | MasterCard | Amex | Discover | UnionPay | JCB | ""
    luhn_valid: bool
    issuer: str
    country: str
    funding_type: str     # credit | debit | prepaid | ""
    exp_date_found: bool = field(default=False)   # expiration date found near this PAN
    exp_date_masked: str = field(default="")      # "**/**" when found, "" otherwise
    cvv_found: bool = field(default=False)        # CVV/CVC found near this PAN
    cvv_masked: str = field(default="")           # "***" / "****" when found, "" otherwise


def scan_banner(banner: str) -> List[CardFinding]:
    """
    Scan a raw banner string for PAN patterns.

    Returns a deduplicated list of CardFinding objects.
    No complete card numbers are stored or returned anywhere.
    """
    if not banner:
        return []
    seen: set[str] = set()
    results: list[CardFinding] = []
    try:
        for m in _PAN_RE.finditer(banner):
            raw = m.group(1)
            digits = re.sub(r"[ \-]", "", raw)
            if not (13 <= len(digits) <= 19):
                continue
            if _is_noise(digits):
                continue
            luhn_ok = _luhn_valid(digits)
            bin_info = _classify_bin(digits)
            masked = _mask_pan(digits)
            if masked in seen:
                continue
            seen.add(masked)

            # Correlate exp_date and CVV within the context window around this PAN
            ctx_start = max(0, m.start() - _CONTEXT_WINDOW)
            ctx_end = min(len(banner), m.end() + _CONTEXT_WINDOW)
            ctx = banner[ctx_start:ctx_end]

            exp_found = bool(_EXP_RE.search(ctx))
            exp_masked = "**/**" if exp_found else ""

            cvv_m = _CVV_CONTEXT_RE.search(ctx)
            cvv_found = cvv_m is not None
            cvv_masked = ("*" * len(cvv_m.group(1))) if cvv_m else ""

            results.append(CardFinding(
                masked_pan=masked,
                bin_prefix=digits[:6],
                card_network=bin_info.network,
                luhn_valid=luhn_ok,
                issuer=bin_info.issuer,
                country=bin_info.country,
                funding_type=bin_info.funding_type,
                exp_date_found=exp_found,
                exp_date_masked=exp_masked,
                cvv_found=cvv_found,
                cvv_masked=cvv_masked,
            ))
    except Exception as exc:
        log.debug("card_detector.scan_banner error: %s", exc)
    return results
