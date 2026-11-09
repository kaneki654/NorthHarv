"""
engine/test_card_detector.py

Synthetic-fixture tests for the PCI card detection pipeline.

Uses publicly known test card numbers (Luhn-valid, never real PANs).
Run with: python -m engine.test_card_detector
"""

import sys
import logging
from pathlib import Path

# Allow running from project root or engine/ directory
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from engine.card_detector import scan_banner, _luhn_valid, _mask_pan, _is_noise, _classify_bin
except ImportError:
    from card_detector import scan_banner, _luhn_valid, _mask_pan, _is_noise, _classify_bin

logging.basicConfig(level=logging.DEBUG)

# ---------------------------------------------------------------------------
# Publicly known test card numbers (Luhn-valid; used by payment processors
# for sandbox testing — no real accounts exist on these PANs)
# ---------------------------------------------------------------------------
VALID_CARDS = [
    # (digits, expected_network)
    ("4111111111111111", "Visa"),          # Visa standard test card
    ("4242424242424242", "Visa"),          # Stripe test card
    ("4000000000000002", "Visa"),          # Stripe decline test
    ("5500005555555559", "MasterCard"),    # MasterCard standard test
    ("5105105105105100", "MasterCard"),    # MasterCard alt test
    ("371449635398431",  "Amex"),          # Amex 15-digit test
    ("6011111111111117", "Discover"),      # Discover test card
    ("3566002020360505", "JCB"),           # JCB test card
]

PASS = 0
FAIL = 0


def check(condition: bool, msg: str) -> None:
    global PASS, FAIL
    if condition:
        print(f"  OK  {msg}")
        PASS += 1
    else:
        print(f"  FAIL  {msg}")
        FAIL += 1


# ---------------------------------------------------------------------------
# 1. Luhn algorithm
# ---------------------------------------------------------------------------
print("\n=== Luhn algorithm ===")
for digits, net in VALID_CARDS:
    check(_luhn_valid(digits), f"Luhn valid: {digits[:6]}*** ({net})")

check(not _luhn_valid("4111111111111112"), "Luhn rejects flipped digit")

# ---------------------------------------------------------------------------
# 2. Noise filter
# ---------------------------------------------------------------------------
print("\n=== Noise filter ===")
check(_is_noise("0000000000000000"), "Noise: all-zero (all-identical check)")
check(_is_noise("9999999999999999"), "Noise: all-nine (all-identical check)")
check(_is_noise("1111111111111111"), "Noise: all-one (constant-diff check, diff=0)")
# Note: 1234567890123456 wraps around (9→0 diff=-9), so NOT caught by monotone check
check(not _is_noise("1234567890123456"), "Not noise: wrapping digit sequence (expected)")
check(not _is_noise("4111111111111111"), "Not noise: Visa test card")
check(not _is_noise("5500005555555559"), "Not noise: MasterCard test")

# ---------------------------------------------------------------------------
# 3. Masking — never expose the full PAN
# ---------------------------------------------------------------------------
print("\n=== Masking ===")
masked = _mask_pan("4111111111111111")
check(masked == "411111******1111", f"16-digit mask: {masked}")
masked_amex = _mask_pan("371449635398431")
check(masked_amex == "371449*****8431", f"15-digit Amex mask: {masked_amex}")
check("1111111111" not in masked, "Full PAN not in masked value")

# ---------------------------------------------------------------------------
# 4. BIN/IIN classification
# ---------------------------------------------------------------------------
print("\n=== BIN classification ===")
for digits, expected_net in VALID_CARDS:
    info = _classify_bin(digits)
    check(
        info.network == expected_net,
        f"BIN {digits[:6]}: got {info.network!r}, expected {expected_net!r}",
    )

# ---------------------------------------------------------------------------
# 5. scan_banner — full pipeline
# ---------------------------------------------------------------------------
print("\n=== scan_banner — detection ===")

# 5a. Valid cards embedded in various banner formats
banner_http = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n\r\n"
    "card=4111111111111111 amount=99.00\n"
    "backup: 5500-0055-5555-5559\n"
    "amex: 3714 496353 98431\n"
)
findings = scan_banner(banner_http)
check(len(findings) >= 3, f"Detected {len(findings)}/3 valid cards in banner")

masked_pans = [f.masked_pan for f in findings]
check("411111******1111" in masked_pans, "Visa card found (plain)")
check("550000******5559" in masked_pans, "MasterCard found (hyphen-separated)")
check("371449*****8431" in masked_pans,  "Amex found (space-separated)")

# 5b. All cards should be Luhn valid
check(all(f.luhn_valid for f in findings), "All detected cards pass Luhn")

# 5c. Network classification
nets = {f.card_network for f in findings}
check("Visa" in nets,       "Visa network classified")
check("MasterCard" in nets, "MasterCard network classified")
check("Amex" in nets,       "Amex network classified")

# 5d. Deduplication — same PAN repeated yields one finding
banner_dup = "4111111111111111 4111111111111111 4111111111111111"
dup_findings = scan_banner(banner_dup)
check(len(dup_findings) == 1, f"Dedup: 3x same PAN -> {len(dup_findings)} finding(s)")

# 5e. Noise candidates suppressed
banner_noise = "0000000000000000 1234567890123456 9999999999999999 junk"
noise_findings = scan_banner(banner_noise)
check(len(noise_findings) == 0, f"Noise suppressed: {len(noise_findings)} finding(s)")

# 5f. Empty/None banner
check(scan_banner("") == [], "Empty banner -> no findings")
try:
    check(scan_banner(None) == [], "None banner -> no findings")  # type: ignore[arg-type]
except Exception:
    check(False, "None banner -> should return []")

# 5g. Luhn-invalid PAN detected but marked invalid
banner_bad_luhn = "4111111111111112"
bad_findings = scan_banner(banner_bad_luhn)
if bad_findings:
    check(not bad_findings[0].luhn_valid, "Luhn-invalid PAN detected and marked invalid")
else:
    check(True, "Luhn-invalid PAN not returned (acceptable if filtered)")

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
total = PASS + FAIL
print(f"\n{'='*50}")
print(f"Results: {PASS}/{total} passed, {FAIL} failed")
if FAIL:
    print("FAIL")
    sys.exit(1)
else:
    print("OK")
