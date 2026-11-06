"""
Indian PII Detection and Scrubbing Engine for SATARK Dataset Curation.

Detects, sanitizes, and verifies the absence of personally identifiable information
(PII) in accordance with the Digital Personal Data Protection Act, 2023 (DPDPA).
Covers:
- Indian Mobile & Landline Phone Numbers
- Permanent Account Numbers (PAN)
- Aadhaar Numbers
- Bank Account Numbers
- Debit/Credit Card Numbers
- UPI Virtual Payment Addresses (VPAs)
- Financial Transaction Reference IDs (UTR, RRN, UPI Ref, NEFT Ref)
- Personal Names with Honorifics
- Live Web URLs & Deceptive Domains
- Email Addresses
- Devanagari Numeral Normalization
- Zero-width character anti-evasion
"""

import re
from typing import Dict, Tuple, Any

# Mapping for Devanagari numerals to standard Arabic digits
DEVANAGARI_TO_ASCII = str.maketrans("०१२३४५६७८९", "0123456789")

# 1. Indian Phone Numbers (+91, 10-digit starting 6-9, STD landlines, and masked variants)
PHONE_REGEX = re.compile(
    r'\b(?:\+?91[\-\s]?)?[6-9]\d{9}\b|\b0\d{2,4}[\-\s]?\d{6,8}\b|\b\d{2}[xX*]{5,8}\d{2}\b',
    re.IGNORECASE
)

# 2. Indian Permanent Account Number (PAN): 5 letters + 4 digits + 1 letter (case-insensitive)
PAN_REGEX = re.compile(r'\b[a-zA-Z]{5}[0-9]{4}[a-zA-Z]\b')

# 3. Aadhaar Number: 12 digits or masked variants (e.g., XXXX-XXXX-1234 or 1234 5678 9012 or Aadhaar: 123456789012)
AADHAAR_REGEX = re.compile(
    r'\b\d{4}[\s\-]\d{4}[\s\-]\d{4}\b|\b[xX*]{4}[\s\-][xX*]{4}[\s\-]\d{4}\b|\b(?:aadhaar|uidai|uid)[\s.:#]*([0-9]{12})\b',
    re.IGNORECASE
)

# 4. Payment Card Numbers (16 digits or masked XXXX-XXXX-XXXX-1234)
CARD_REGEX = re.compile(
    r'\b(?:\d{4}[\s\-]){3}\d{4}\b|\b(?:[xX*]{4}[\s\-]){3}\d{4}\b'
)

# 5. Bank Account Sequences (e.g. A/c XX1234, Account No 987654321012, A/c 1092837465)
ACCOUNT_REGEX = re.compile(
    r'\b(?:a/c|acct|account(?:\s*no\.?)?)[\s.:#]*([xX*]*\d{4,18})\b',
    re.IGNORECASE
)

# 6. UPI Virtual Payment Addresses (VPAs)
UPI_REGEX = re.compile(
    r'\b[a-zA-Z0-9.\-_]{2,64}@(oksbi|okhdfcbank|okaxis|okicici|paytm|ybl|ibl|axl|apl|barodampay|upi)\b',
    re.IGNORECASE
)

# 6b. Financial Transaction References (UPI Ref, UTR, RRN, NEFT Ref, IMPS Ref)
REF_REGEX = re.compile(
    r'\b(?:upi\s*ref(?:erence)?|neft\s*ref|imps\s*ref|rtgs\s*ref|rrn|utr|txn\s*ref|ref\s*no\.?|ref\s*id)[\s.:#]*([A-Za-z0-9]{8,18})\b',
    re.IGNORECASE
)

# 7. Personal Names with Indian Honorifics (Mr., Mrs., Ms., Shri, Smt., Dr.)
NAME_HONORIFIC_REGEX = re.compile(
    r'\b(?:mr\.|mrs\.|ms\.|shri|smt\.|dr\.)\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?\b',
    re.IGNORECASE
)

# 8. Web URLs, Deceptive Domains, and Obfuscated Links
URL_REGEX = re.compile(
    r'(?:hxxps?|https?|ftp)://\S+|www\.\S+|\b[a-zA-Z0-9.-]+\.(?:com|in|org|net|xyz|top|site|online|live|click|app|cc|co|info|biz|club|vip)\b(?:/\S*)?',
    re.IGNORECASE
)

# 9. Email Addresses
EMAIL_REGEX = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)


def scrub_text(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Sanitizes raw telecommunication text by replacing sensitive PII entities
    with standardized, safe placeholders.
    Returns:
        scrubbed_text (str): The sanitized text.
        counts (dict): Frequency of scrubbed entities by category.
    """
    if not text or not isinstance(text, str):
        return "", {}

    counts: Dict[str, int] = {}

    # Step 0: Remove invisible zero-width evasion characters
    scrubbed = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', text)

    # Step 1: Scrub Bank Account Numbers
    def sub_acct(m):
        return "A/c <acct>"
    scrubbed, count = ACCOUNT_REGEX.subn(sub_acct, scrubbed)
    if count > 0:
        counts["account"] = count

    # Step 2: Scrub Payment Cards
    scrubbed, count = CARD_REGEX.subn("<card>", scrubbed)
    if count > 0:
        counts["card"] = count

    # Step 3: Scrub Aadhaar Numbers
    scrubbed, count = AADHAAR_REGEX.subn("<aadhaar>", scrubbed)
    if count > 0:
        counts["aadhaar"] = count

    # Step 4: Scrub PAN Cards
    scrubbed, count = PAN_REGEX.subn("<pan>", scrubbed)
    if count > 0:
        counts["pan"] = count

    # Step 5: Scrub UPI VPAs
    scrubbed, count = UPI_REGEX.subn("<upi>", scrubbed)
    if count > 0:
        counts["upi"] = count

    # Step 5b: Scrub Financial Transaction Reference IDs (before phone regex)
    def sub_ref(m):
        return "Ref <ref>"
    scrubbed, count = REF_REGEX.subn(sub_ref, scrubbed)
    if count > 0:
        counts["ref"] = count

    # Step 6: Scrub Email Addresses
    scrubbed, count = EMAIL_REGEX.subn("<email>", scrubbed)
    if count > 0:
        counts["email"] = count

    # Step 7: Scrub URLs
    scrubbed, count = URL_REGEX.subn("<url>", scrubbed)
    if count > 0:
        counts["url"] = count

    # Step 8: Scrub Phone Numbers (including Devanagari numerals normalized)
    # Check if Devanagari digits exist before phone matching
    devanagari_normalized = scrubbed.translate(DEVANAGARI_TO_ASCII)
    if PHONE_REGEX.search(devanagari_normalized) and not PHONE_REGEX.search(scrubbed):
        # Text contained Devanagari phone digits
        scrubbed = PHONE_REGEX.sub("<phone>", devanagari_normalized)
        counts["phone"] = counts.get("phone", 0) + 1
    else:
        scrubbed, count = PHONE_REGEX.subn("<phone>", scrubbed)
        if count > 0:
            counts["phone"] = count

    # Step 9: Scrub Names with Honorifics
    scrubbed, count = NAME_HONORIFIC_REGEX.subn("<name>", scrubbed)
    if count > 0:
        counts["name"] = count

    return scrubbed, counts


def has_unmasked_pii(text: str) -> bool:
    """
    Audits a text string to confirm whether any raw, unmasked PII remains.
    Returns True if unmasked PII is detected, False if fully scrubbed.
    """
    if not text or not isinstance(text, str):
        return False

    normalized_text = text.translate(DEVANAGARI_TO_ASCII)

    # Check for unmasked phone numbers
    if PHONE_REGEX.search(normalized_text):
        return True

    # Check for unmasked PAN
    if PAN_REGEX.search(text):
        return True

    # Check for unmasked Aadhaar
    if AADHAAR_REGEX.search(text):
        return True

    # Check for unmasked Card numbers
    if CARD_REGEX.search(text):
        return True

    # Check for unmasked UPI
    if UPI_REGEX.search(text):
        return True

    # Check for unmasked Email
    if EMAIL_REGEX.search(text):
        return True

    return False


def sanitize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies PII scrubbing and schema field sanitization to a single dataset record.
    """
    cleaned = dict(record)
    raw_text = str(record.get("text", ""))
    scrubbed, _ = scrub_text(raw_text)
    cleaned["text"] = scrubbed
    return cleaned
