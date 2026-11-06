"""
Safety, Robustness, and False-Positive Masking Test Suite for SATARK PII Scrubber (Phase 6B).

Validates:
1. Indian phone number formats (+91, 10-digit, landlines, masked).
2. PAN/Aadhaar-like sequences.
3. UPI IDs and UTR/RRN/IMPS/NEFT financial references.
4. URLs, domains, and obfuscated link patterns.
5. Strict false-positive avoidance:
   - Rupee currency amounts NOT masked as accounts/phones.
   - Durations ("10 minutes", "24 hours") and dates NOT masked as phones.
   - Government/Emergency helplines ("1930", "1800") preserved.
   - Operational OTP digits (4 to 6 digits) NOT masked as phones.
   - Words with 'pan' ('expand', 'company', 'pan-india') NOT masked as <pan>.
   - Words with 'ac' ('action', 'accept', 'contact') NOT corrupted to A/c <acct>.
6. Hindi Devanagari Unicode and Roman Hinglish robustness.
7. Devanagari numeral normalization (e.g. ९८७६५४३२१०).
8. Malformed, adversarial, and zero-width evasion inputs.
9. Scam forensic context preservation.
"""

import unittest
from ml_service.curation.pii_scrubber import (
    scrub_text,
    has_unmasked_pii,
    PHONE_REGEX,
    PAN_REGEX,
    AADHAAR_REGEX,
    CARD_REGEX,
    ACCOUNT_REGEX,
    UPI_REGEX,
    REF_REGEX,
    URL_REGEX
)


class TestPiiScrubberEntityDetection(unittest.TestCase):
    """Test Suite 1: Exact Indian Entity Detection & Masking."""

    def test_phone_number_formats(self):
        samples = [
            ("Call mobile 9876543210 immediately", "<phone>"),
            ("Contact +91 9876543210 for support", "<phone>"),
            ("Reach us at +91-8123456789", "<phone>"),
            ("Landline: 011-23456789", "<phone>"),
            ("Masked phone: 98XXXXXX10", "<phone>"),
            ("Masked phone: 98******10", "<phone>"),
        ]
        for raw, expected in samples:
            scrubbed, _ = scrub_text(raw)
            self.assertIn(expected, scrubbed, f"Failed on phone format: {raw}")

    def test_pan_formats(self):
        # Standard uppercase PAN
        scrubbed1, c1 = scrub_text("Your PAN card ABCDE1234F is required.")
        self.assertNotIn("ABCDE1234F", scrubbed1)
        self.assertIn("<pan>", scrubbed1)

        # Lowercase PAN
        scrubbed2, c2 = scrub_text("Submit pan abcde1234f on portal.")
        self.assertNotIn("abcde1234f", scrubbed2)
        self.assertIn("<pan>", scrubbed2)

    def test_aadhaar_formats(self):
        # 12 digits spaced
        scrubbed1, _ = scrub_text("Aadhaar: 1234 5678 9012 registered.")
        self.assertNotIn("1234 5678 9012", scrubbed1)
        self.assertIn("<aadhaar>", scrubbed1)

        # Masked Aadhaar
        scrubbed2, _ = scrub_text("Aadhaar ending XXXX-XXXX-4921.")
        self.assertNotIn("XXXX-XXXX-4921", scrubbed2)
        self.assertIn("<aadhaar>", scrubbed2)

    def test_upi_and_transaction_references(self):
        # UPI VPA
        scrubbed1, _ = scrub_text("Pay to merchant.pay@oksbi for cashback.")
        self.assertNotIn("merchant.pay@oksbi", scrubbed1)
        self.assertIn("<upi>", scrubbed1)

        # UPI Reference / UTR
        scrubbed2, _ = scrub_text("Debited for UPI Ref 987654321012 on 02-Nov.")
        self.assertNotIn("987654321012", scrubbed2)
        self.assertIn("Ref <ref>", scrubbed2)
        # Verify it was masked as reference, NOT as a phone number
        self.assertNotIn("<phone>", scrubbed2)

    def test_url_and_domain_masking(self):
        samples = [
            "Click http://sbi-verify.xyz/login immediately.",
            "Visit https://bescom.karnataka.gov.in for bill.",
            "Download app at www.secure-banking.top/app.apk",
            "Login to update-kyc.site/portal",
        ]
        for s in samples:
            scrubbed, counts = scrub_text(s)
            self.assertIn("<url>", scrubbed)
            self.assertEqual(counts.get("url"), 1)


class TestPiiScrubberFalsePositiveMasking(unittest.TestCase):
    """Test Suite 2: Strict False-Positive Avoidance (Safety Tests)."""

    def test_currency_amounts_not_masked(self):
        amounts = [
            "Amount debited is INR 15,000 for your order.",
            "Total balance is Rs. 50,000 in your account.",
            "₹2,450.00 deducted via POS swipe.",
            "Cash prize of INR 25,00,000 won in draw.",
        ]
        for a in amounts:
            scrubbed, counts = scrub_text(a)
            # Currency figures must NOT trigger phone or account or pan masking
            self.assertNotIn("<phone>", scrubbed)
            self.assertNotIn("<pan>", scrubbed)

    def test_durations_and_dates_not_masked(self):
        text = "OTP valid for 10 minutes. Generated on 02-Nov-2026 at 9:30 PM. Complete within 24 hours."
        scrubbed, counts = scrub_text(text)
        self.assertIn("10 minutes", scrubbed)
        self.assertIn("24 hours", scrubbed)
        self.assertIn("02-Nov-2026", scrubbed)
        self.assertNotIn("<phone>", scrubbed)

    def test_helpline_and_emergency_numbers_preserved(self):
        text = "Report financial fraud to 1930. For inquiries call toll-free 1800-11-2211."
        scrubbed, counts = scrub_text(text)
        self.assertIn("1930", scrubbed)
        self.assertNotIn("<phone>", scrubbed)

    def test_operational_otp_digits_not_masked_as_phone(self):
        text = "Your login OTP is 584920. Single-use code 391824."
        scrubbed, counts = scrub_text(text)
        self.assertIn("584920", scrubbed)
        self.assertIn("391824", scrubbed)
        self.assertNotIn("<phone>", scrubbed)

    def test_words_containing_pan_not_corrupted(self):
        words = [
            "We plan to expand our business.",
            "Company policy applies pan-india.",
            "Store goods in the pantry room.",
            "The life span of the device is 5 years.",
        ]
        for w in words:
            scrubbed, counts = scrub_text(w)
            self.assertNotIn("<pan>", scrubbed)
            self.assertEqual(scrubbed, w)

    def test_words_containing_ac_not_corrupted(self):
        words = [
            "Immediate legal action will be taken.",
            "We do not accept third-party checks.",
            "Please contact our customer care.",
            "Reach the nearest branch.",
            "Ensure full accountability.",
        ]
        for w in words:
            scrubbed, counts = scrub_text(w)
            self.assertNotIn("A/c <acct>", scrubbed)
            self.assertNotIn("<acct>", scrubbed)
            self.assertEqual(scrubbed, w)


class TestMultilingualAndAdversarialScrubbing(unittest.TestCase):
    """Test Suite 3: Multilingual (Hindi & Hinglish) & Adversarial Inputs."""

    def test_devanagari_numeral_phone_normalization(self):
        # 10-digit Indian phone in Devanagari numerals: ९८७६५४३२१० (9876543210)
        hindi_text = "तुरंत बिजली अधिकारी ९८७६५४३२१० पर कॉल करें।"
        scrubbed, counts = scrub_text(hindi_text)
        self.assertNotIn("९८७६५४३२१०", scrubbed)
        self.assertIn("<phone>", scrubbed)
        self.assertIn("बिजली अधिकारी", scrubbed)

    def test_hindi_unicode_preservation(self):
        hindi_sample = "प्रिय ग्राहक, आपका एसबीआई खाता केवाईसी लंबित होने के कारण आज बंद कर दिया जाएगा।"
        scrubbed, _ = scrub_text(hindi_sample)
        # Pure text with no PII should remain identical
        self.assertEqual(scrubbed, hindi_sample)
        self.assertFalse(has_unmasked_pii(scrubbed))

    def test_roman_hinglish_context_preservation(self):
        hinglish_sample = "Bijli Vibhag Notice: Aaj raat 9:30 PM aapka electricity cut kar diya jayega. Officer 9876543210 ko call karein."
        scrubbed, _ = scrub_text(hinglish_sample)
        self.assertIn("Aaj raat 9:30 PM", scrubbed)
        self.assertIn("electricity cut kar diya jayega", scrubbed)
        self.assertIn("<phone>", scrubbed)
        self.assertNotIn("9876543210", scrubbed)

    def test_zero_width_adversarial_evasion(self):
        # Scam message with zero-width spaces between digits of a phone number
        evasive_phone = "9\u200b8\u200b7\u200b6\u200b5\u200b4\u200b3\u200b2\u200b1\u200b0"
        text = f"Call officer on {evasive_phone} now."
        scrubbed, counts = scrub_text(text)
        self.assertIn("<phone>", scrubbed)
        self.assertNotIn("9", scrubbed)

    def test_empty_and_malformed_inputs(self):
        self.assertEqual(scrub_text("")[0], "")
        self.assertEqual(scrub_text(None)[0], "")
        self.assertEqual(scrub_text("   \n\t  ")[0], "   \n\t  ")
        self.assertFalse(has_unmasked_pii(""))
        self.assertFalse(has_unmasked_pii(None))

    def test_scam_forensic_context_preservation(self):
        # Verify critical forensic keywords are preserved after scrubbing
        phish_msg = "URGENT: Your SBI account suspended due to KYC. Click http://sbi-fake.xyz immediately to verify PAN ABCDE1234F."
        scrubbed, counts = scrub_text(phish_msg)
        # Forensic lures preserved
        self.assertIn("URGENT", scrubbed)
        self.assertIn("suspended", scrubbed)
        self.assertIn("KYC", scrubbed)
        self.assertIn("immediately", scrubbed)
        # PII entities replaced with standardized tokens
        self.assertIn("<url>", scrubbed)
        self.assertIn("<pan>", scrubbed)
        self.assertNotIn("sbi-fake.xyz", scrubbed)
        self.assertNotIn("ABCDE1234F", scrubbed)


if __name__ == "__main__":
    unittest.main()

