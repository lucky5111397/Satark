"""
SATARK Synthetic Dataset Pilot Generator (Phase 6C.1).

Generates a controlled, reproducible 150-record synthetic candidate dataset
for training and evaluating multilingual Indian scam classification models
(XLM-RoBERTa and Hing-BERT).

Key Governance Properties:
- Exact 150 records: 75 BENIGN / 75 SUSPICIOUS.
- Trilingual distribution: 53 English (en), 52 Roman Hinglish (hinglish), 45 Devanagari Hindi (hi).
- Balanced coverage across all 12 canonical categories.
- Purely fictional, generic entities (no real bank, agency, telecom, or utility impersonation).
- Full 15-column schema with truthful governance metadata (reviewer_status: pending_review, reviewed_by: none).
- Deterministic reproducibility via fixed seed.
- Integrated multi-dimensional quality auditing (near-duplicate, PII, contamination, script checks).
"""

import argparse
import csv
import logging
import random
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Set, Any, Optional

# Reconfigure stdout/stderr encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("satark.synthetic_generator")

from ml_service.training.validate_dataset import (
    REQUIRED_COLUMNS,
    GOVERNANCE_COLUMNS,
    CANONICAL_BENIGN,
    CANONICAL_SUSPICIOUS,
    check_contamination,
    ContaminationError
)
from ml_service.training.prepare_dataset import extract_template_fingerprint
from ml_service.curation.pii_scrubber import scrub_text, has_unmasked_pii
from ml_service.curation.templates_expanded import (
    build_expanded_template_catalog,
    EXPANDED_SLOTS,
)

PILOT_STAGING_PATH = Path("ml_service/dataset/pilot_synthetic_corpus_150.csv")
TRAINING_CORPUS_PATH = Path("ml_service/dataset/training_corpus_4500.csv")

# -----------------------------------------------------------------------------
# Fictional & Generic Entity Dictionaries (Zero Real Entity Impersonation)
# -----------------------------------------------------------------------------
FICTIONAL_BANKS_EN = [
    "Bharat Trust Bank", "Apex National Bank", "Janata Commercial Bank",
    "Vikas Union Bank", "City Mercantile Bank", "Pratham Urban Bank",
    "National Heritage Bank", "Kalyan Gramin Bank"
]
FICTIONAL_BANKS_HI = [
    "भारत ट्रस्ट बैंक", "अपेक्स नेशनल बैंक", "जनता कमर्शियल बैंक",
    "विकास यूनियन बैंक", "कल्याण ग्रामीण बैंक", "प्रथम अर्बन बैंक"
]
FICTIONAL_BANKS_HN = [
    "Bharat Trust Bank", "Apex National Bank", "Janata Commercial Bank",
    "Vikas Union Bank", "City Mercantile Bank", "Kalyan Gramin Bank"
]

FICTIONAL_UTILITIES_EN = [
    "City Power Distribution", "Metro Electricity Board", "State Urja Nigam",
    "Regional Power Services", "Metropolitan Gas Utility"
]
FICTIONAL_UTILITIES_HI = [
    "विद्युत वितरण निगम", "नगर बिजली बोर्ड", "राज्य ऊर्जा सेवा", "मेट्रो विद्युत निगम"
]
FICTIONAL_UTILITIES_HN = [
    "Bijli Vibhag", "City Power Board", "Urja Nigam", "State Electricity Department"
]

FICTIONAL_AGENCIES_EN = [
    "National Cyber Security Cell", "Metropolitan Crime Branch",
    "Federal Parcel Investigation Cell", "Central Cyber Verification Bureau"
]
FICTIONAL_AGENCIES_HI = [
    "राष्ट्रीय साइबर सुरक्षा सेल", "महानगर अपराध शाखा",
    "साइबर अपराध निरोधक ब्यूरो", "केंद्रीय पार्सल जांच शाखा"
]
FICTIONAL_AGENCIES_HN = [
    "National Cyber Crime Cell", "Central Investigation Desk",
    "Delhi Crime Division", "Cyber Security Branch"
]

FICTIONAL_TELECOMS_EN = [
    "Wave Mobile Network", "Bharat Connect Postpaid", "AirNet Cellular", "Zeta Postpaid Services"
]
FICTIONAL_TELECOMS_HI = [
    "तरंग मोबाइल नेटवर्क", "भारत कनेक्ट सेलुलर", "वेव टेलीकॉम सेवा"
]
FICTIONAL_TELECOMS_HN = [
    "Wave Mobile Network", "Bharat Connect Postpaid", "AirNet Cellular"
]

FICTIONAL_RETAIL_EN = [
    "Urban Fresh Mart", "Speedy Delivery App", "TrendStyle Apparels", "HomeChef Kitchen", "CinemaPass Bookings"
]
FICTIONAL_RETAIL_HI = [
    "शहरी ताजा बाज़ार", "स्पीड डिलीवरी ऐप", "ट्रेंडस्टाइल वस्त्र", "होमशेफ रसोई"
]
FICTIONAL_RETAIL_HN = [
    "Urban Fresh Mart", "Speedy Delivery App", "TrendStyle Apparels", "HomeChef Kitchen"
]

FICTIONAL_LOTTERIES_EN = [
    "All-India Mega Rewards Contest", "National Consumer Welfare Lucky Draw", "Digital Festival Grand Prize"
]
FICTIONAL_LOTTERIES_HI = [
    "अखिल भारतीय उपभोक्ता लकी ड्रा", "राष्ट्रीय उत्सव महा पुरस्कार", "डिजिटल उपभोक्ता प्रोत्साहन योजना"
]
FICTIONAL_LOTTERIES_HN = [
    "All India Mega Lucky Draw", "National WhatsApp Consumer Contest", "Digital Festival Rewards Draw"
]

FICTIONAL_APPS_EN = [
    "DigiSupport QuickApp", "BharatPay Assist Tool", "SecureToken Helper", "CustomerCare QuickDesk"
]
FICTIONAL_APPS_HI = [
    "डिजिटल सहायता टूल", "त्वरित ग्राहक सहायता ऐप", "सुरक्षित टोकन ऐप"
]
FICTIONAL_APPS_HN = [
    "DigiSupport QuickApp", "BharatPay Assist Tool", "QuickHelp Assist APK"
]


# -----------------------------------------------------------------------------
# Template Grammars & Slot Definitions
# -----------------------------------------------------------------------------

def build_template_catalog() -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    """
    Returns structured template grammars organized by:
    [language][label][category] -> List of distinct template strings.
    """
    return {
        "en": {
            CANONICAL_BENIGN: {
                "otp_negation": [
                    "Security Advisory: {bank} representatives will never call, SMS, or email you requesting your card PIN, CVV, or OTP. Keep your confidential details private.",
                    "Your {bank} NetBanking login OTP is {otp}. Valid for 10 minutes. Never share this OTP or your password with anyone including bank employees.",
                    "{bank} Fraud Prevention: One Time Password for your debit transaction is {otp}. Valid for 5 minutes. If you did not request this, do not disclose this OTP to anyone.",
                    "Customer Awareness Alert from {bank}: Never share sensitive banking credentials, passwords, or single-use verification codes on unverified phone calls.",
                    "{bank} Safety Notice: Your verification code is {otp}. Remember, authentic bank officials never demand OTP over phone. Stay alert."
                ],
                "otp_operational": [
                    "Your {bank} Internet Banking authorization OTP is {otp}. This single-use code is valid for 10 minutes. Enter code on official login screen.",
                    "OTP {otp} for initiating funds transfer of INR 4,500.00 from {bank} A/c <acct>. Valid for 3 minutes for authorized transactions.",
                    "Verification code for {bank} mobile profile security update is {otp}. Valid for 5 minutes. Enter this code only on the verified portal.",
                    "Your one-time passcode for new beneficiary registration at {bank} is {otp}. Code expires in 5 minutes."
                ],
                "bank_transactional": [
                    "Alert: {bank} A/c <acct> debited for INR 2,150.00 on 05-Nov-26 via UPI Ref <ref>. Avail Bal: INR 34,800.00. Report unauthorized transactions to 1930.",
                    "{bank}: Monthly salary of INR 62,500.00 credited to A/c <acct> on 01-Nov-26 via NEFT Ref <ref>. Updated Balance: INR 78,900.00.",
                    "Transaction Notification: INR 2,000.00 withdrawn from ATM using {bank} Debit Card <card> on 03-Nov-26. Avail Bal: INR 19,400.00.",
                    "{bank} Alert: Account <acct> credited with INR 7,800.00 via IMPS Ref <ref> on 04-Nov-26. Net Available Balance: INR 27,200.00.",
                    "Alert: POS purchase of INR 1,420.00 approved on {bank} Debit Card <card> on 05-Nov-26. Avail Bal: INR 25,780.00."
                ],
                "utility_service_notice": [
                    "Dear Consumer, your electricity bill for consumer account <acct> from {utility} of INR 1,280 is due on 14-Nov-26. Pay safely at official portal <url>.",
                    "{utility}: Monthly power consumption bill for consumer meter <acct> is INR 940. Due date 18-Nov-26. Download bill receipt from official website.",
                    "Municipal Water Supply Board: Your quarterly utility dues for connection <acct> amount to INR 650. Payment due by 20-Nov-26 at municipal counter.",
                    "{utility} Advisory: Scheduled grid maintenance will affect local supply in Sector 7 on 08-Nov-26 from 10 AM to 1 PM. Inconvenience regretted."
                ],
                "service_informational": [
                    "Dear Customer, your annual interest certificate for financial year 2025-26 from {bank} is now ready. Download it via official NetBanking portal.",
                    "{bank} Branch Notice: All branches in the district will observe a public holiday on 12-Nov-26. Online digital banking services remain active.",
                    "Customer Service Desk: Your service request Ref <ref> for cheque book dispatch has been processed and dispatched through registered post.",
                    "{bank} Term Deposit Update: Your fixed deposit receipt for A/c <acct> has renewed automatically for 12 months at prevailing interest rates.",
                    "Dear Subscriber, your monthly billing statement for {telecom} postpaid account has been generated and emailed to your registered address."
                ],
                "commercial_promo_ham": [
                    "Weekend Special Offer: Enjoy flat 25% discount on fresh groceries and household essentials this Sunday at {retail}. Use coupon code FRESH25 at counter.",
                    "{retail}: Autumn casual apparel collection now in stock! Visit nearest outlet or browse catalog online at <url> with complimentary home delivery.",
                    "Hungry for delicious meals? Order from curated neighborhood dining outlets on {retail} today and receive flat INR 80 cashback on your meal.",
                    "Cinema Festival: Reserve two movie tickets on {retail} this weekend and receive a 40% discount on the companion ticket. Offer valid till Sunday."
                ]
            },
            CANONICAL_SUSPICIOUS: {
                "kyc_phishing": [
                    "URGENT: Your {bank} netbanking account has been suspended due to pending KYC verification. Click <url> immediately to update your PAN and restore access.",
                    "Final Warning: Your NetBanking portal at {bank} will be permanently blocked within 12 hours. Verify your mobile credentials instantly at <url>.",
                    "{bank} Security Alert: Unauthorized login attempt detected from an unrecognized location. Protect your banking profile immediately at <url>.",
                    "Dear Customer, your debit card at {bank} is deactivated due to outdated identity documents. Restore your active card profile at <url>.",
                    "Urgent Banking Notice: Update your mandatory KYC verification at {bank} before midnight to avoid complete account freeze. Login to verify: <url>."
                ],
                "digital_arrest_impersonation": [
                    "{agency} Notice: An international consignment containing banned narcotics was intercepted under your Aadhaar. Contact officer on <phone> to avoid arrest warrant.",
                    "URGENT LEGAL SUMMONS: {agency} has registered a financial extortion investigation involving your PAN. Connect with Deputy Director on <phone> immediately.",
                    "{agency}: A formal arrest warrant has been prepared against you for money laundering charges. Report on video conference or call investigator on <phone>.",
                    "Confidential Law Enforcement Notice: Contraband materials seized at international logistics terminal linked to your identity. Contact officer on <phone> right away."
                ],
                "electricity_disconnection": [
                    "Electricity Department Warning: Consumer power supply for A/c <acct> will be disconnected tonight at 9:30 PM due to unpaid balance. Call officer on <phone> immediately.",
                    "{utility} Alert: Your residential meter connection is scheduled for immediate disconnection today. Contact line engineer on <phone> to prevent cut-off.",
                    "Urgent Power Notice: Your electric bill payment was flagged as unverified. Grid supply will be disconnected in 2 hours unless verified with officer on <phone>.",
                    "Power Department Alert: Outstanding electric dues detected. Supply severance ordered for tonight. Call billing desk immediately on <phone>.",
                    "{utility} Disconnection Notice: Electric power will be terminated within 3 hours. Avoid heavy reconnection penalty by calling junior engineer on <phone>."
                ],
                "part_time_job_scam": [
                    "Work From Home Opportunity: Earn INR 3,000 to 6,000 daily by rating hotels and reviewing products online! No prior experience needed. Contact HR manager on <url>.",
                    "Part-Time Job Offer: Like online promotional videos and earn INR 250 per task. Instant daily payout to your UPI. Connect with recruitment manager on <phone>.",
                    "Urgent Hiring Notice: Remote digital assistants needed for daily data evaluation tasks. Earn up to INR 45,000 monthly from mobile. Message coordinator on <phone>.",
                    "Earn daily income from home! Simple online freelance assignments with instant daily earnings. Limited slots available. Join recruitment group at <url>."
                ],
                "lottery_advance_fee": [
                    "Congratulations! Your mobile number won cash lottery prize of INR 25,00,000 in {lottery}. Contact claims manager on <phone> to claim your draft.",
                    "Grand Reward Alert: You are selected as 1st prize winner of a luxury sedan car or cash equivalent in {lottery}. Deposit registration charge of INR 9,500 at <url>.",
                    "Winner Announcement: Your SIM card won INR 15,00,000 in festival lucky draw. Send verification code and claim award by contacting official on <phone>.",
                    "Lucky Draw Notification: Claim your approved lucky award of INR 20,00,000 from {lottery}. Call claims desk officer immediately on <phone>."
                ],
                "malicious_apk_qr_scam": [
                    "{bank} Customer Support: Download and install our official security assist tool {app_name} from <url> to resolve your pending transaction refund.",
                    "Customer Refund Portal: Scan the attached payment QR code to claim your pending cash refund of INR 3,850 directly into your bank savings account.",
                    "Payment Helpdesk: To unblock your pending UPI transfer, download the mandatory verification tool {app_name} from <url>.",
                    "Technical Support Desk: Your mobile banking security patch is pending. Download and install update APK immediately from <url> to maintain service."
                ]
            }
        },
        "hinglish": {
            CANONICAL_BENIGN: {
                "otp_negation": [
                    "Security Advisory: {bank} kabhie bhi aapse phone, SMS ya email par password, CVV ya OTP nahi maangta. Apna confidential data safe rakhein.",
                    "Dear Customer, aapka {bank} NetBanking login OTP hai {otp}. Valid for 10 minutes. Kisi ke sath OTP share na karein. Bank kabhie OTP nahi maangta.",
                    "{bank} Fraud Alert: Debit transaction verify karne ke liye OTP {otp} hai. Agar transaction aapne nahi kiya toh kisi ko code na batayein.",
                    "Customer Awareness Alert from {bank}: Apna bank password, UPI PIN ya OTP kisi ajnabi ke sath share na karein. Samajhdar bane, satark rahein.",
                    "{bank} Alert: Online access verification OTP {otp} hai. Asli bank officer kabhie call par OTP nahi maangte. Surakshit rahein."
                ],
                "otp_operational": [
                    "Aapka {bank} NetBanking access OTP {otp} hai. Yeh code agle 10 minutes tak valid hai. Code official login screen par hi enter karein.",
                    "OTP {otp} for initiating payment of INR 3,500.00 from {bank} A/c <acct>. Valid for 3 minutes for single transaction use.",
                    "{bank} security verification code hai {otp}. Profile update complete karne ke liye verified mobile app me use karein.",
                    "{bank}: New beneficiary add karne ke liye OTP {otp} generate hua hai. Valid for 5 minutes."
                ],
                "bank_transactional": [
                    "Alert: {bank} A/c <acct> se INR 1,850.00 debited on 05-Nov-26 for UPI Ref <ref>. Avail Bal: INR 42,100.00. Agar transaction aapne nahi kiya toh 1930 par call karein.",
                    "{bank}: Monthly salary of INR 55,000.00 credited to A/c <acct> on 01-Nov-26 through NEFT Ref <ref>. Total Balance: INR 64,800.00.",
                    "Transaction Alert: INR 1,500.00 ATM se withdraw kiya gaya {bank} card <card> use karke on 04-Nov-26. Current Bal: INR 28,300.00.",
                    "{bank} Alert: Account <acct> me INR 4,200.00 IMPS Ref <ref> se credit hua hai on 03-Nov-26. Available Balance: INR 31,500.00."
                ],
                "utility_service_notice": [
                    "Dear Consumer, aapka {utility} electricity bill consumer ID <acct> ka INR 1,150 due date 12-Nov-26 hai. Official portal <url> se safely pay karein.",
                    "{utility}: Monthly power consumption bill meter <acct> ka INR 820 generate ho gaya hai. Due date 16-Nov-26 se pehle portal se pay karein.",
                    "Municipal Water Supply Desk: Connection <acct> ka quarterly water bill INR 540 due hai. Timely payment ke liye municipal portal check karein.",
                    "{utility} Notice: Feeder line repair ke chalte Sector 9 me 09-Nov-26 ko subah 11 baje se 2 baje tak power supply band rahegi."
                ],
                "service_informational": [
                    "Dear Customer, {bank} annual interest certificate financial year 2025-26 ready hai. Netbanking portal se safely download karein.",
                    "{bank} Branch Notice: Regional festival ke avsar par 11-Nov-26 ko branch band rahegi. Online NetBanking aur ATM services regular chalengi.",
                    "Customer Service Desk: Aapka cheque book request Ref <ref> successfully dispatch ho gaya hai speed post se.",
                    "{bank} Deposit Update: A/c <acct> ki term deposit receipt agle 12 months ke liye standard interest rate par renew ho chuki hai."
                ],
                "commercial_promo_ham": [
                    "Weekend Mega Savings: Fresh grocery aur kitchen items par flat 30% discount paayein is Sunday at {retail}. Code use karein SAVE30.",
                    "{retail}: Casual footwear aur latest winter collection available hai! Nearest store visit karein ya online shop karein at <url>.",
                    "Hungry? Apne favorite restaurant se khana order karein {retail} par aur paayein flat INR 100 off on orders above Rs. 299.",
                    "Movie Treat: Weekend movie ticket book karein {retail} app se aur second ticket par 50% discount enjoy karein. Offer limited time tak.",
                    "{retail}: Festive electronics sale live ho chuki hai! Appliances aur gadgets par extra exchange bonus paane ke liye visit karein <url>."
                ]
            },
            CANONICAL_SUSPICIOUS: {
                "kyc_phishing": [
                    "Dear Customer, aapka {bank} netbanking account blocked ho gaya hai pending Pan card update ki wajah se. Restore karne ke liye link click karein: <url>",
                    "Urgent Alert: Aapka {bank} mobile banking account 24 ghante me permanently suspend ho jayega. Turant document update karein: <url>",
                    "{bank} Warning Notice: Security system me invalid login mila hai. Account block hone se bachane ke liye turant verify karein: <url>",
                    "Dear Consumer, aapka {bank} debit card deactivate kar diya gaya hai KYC pending hone par. Card re-activate karne ke liye click karein: <url>",
                    "{bank} Urgent Message: Aaj raat 12 baje se pehle apna Pan card update karein warna account freeze ho jayega. Login link: <url>"
                ],
                "digital_arrest_impersonation": [
                    "{agency} Notice: Aapke naam se narcotics parcel international customs me pakda gaya hai. Arrest warrant cancel karne ke liye officer ko call karein: <phone>",
                    "Urgent Crime Branch Alert: Financial crime inquiry me aapka Aadhaar number linked mila hai. Turant Deputy Commissioner ko contact karein on <phone>.",
                    "{agency}: Money laundering investigation ke tehat aapke khilaf legal notice jari hua hai. Arrest se bachne ke liye video call par connect karein: <phone>",
                    "Law Enforcement Notice: Illegal courier consignment case me aapka statement required hai. Turant investigating officer se baat karein on <phone>."
                ],
                "electricity_disconnection": [
                    "Bijli Vibhag Notice: Aaj raat 9:30 PM aapka electricity cut kar diya jayega. Bill payment verify karne ke liye officer <phone> par turant call karein.",
                    "{utility} Alert: Consumer A/c <acct> ka electric connection aaj disconnect hone wala hai. Supply cut rokne ke liye engineer <phone> par call karein.",
                    "Urgent Electricity Notice: Bill transaction fail ho chuka hai. Power connection agle 2 ghante me cut kar diya jayega. Officer contact: <phone>.",
                    "State Power Notice: Bill verification pending hone ki wajah se meter line kaatne ka order nikla hai. Call karein helpline on <phone> right away."
                ],
                "part_time_job_scam": [
                    "Part time job alert! YouTube videos like karke daily INR 4,000 earn karein. Join our Telegram channel: <url> for instant daily payout.",
                    "Ghar baithe kamayein daily INR 2,500 to 5,000! Mobile se simple hotel reviews submit karein aur direct UPI payment paayein. WhatsApp on <phone>.",
                    "Work from home opportunity: Online product rating task karke monthly 40,000 INR tak kamayein. No investment needed. Contact HR: <phone>.",
                    "Online freelance job: Daily 2 ghante work karke guaranteed weekly payout paayein. Free registration link: <url>.",
                    "Digital review job: Mobile se short video rating complete karein aur har task ka INR 200 paayein. Join Telegram handle: <url>."
                ],
                "lottery_advance_fee": [
                    "Congratulations! {lottery} me aapka number 25 Lakh INR jeet chuka hai. Lottery manager se baat karne ke liye WhatsApp karein: <phone>",
                    "Grand Prize Notice: Aapne jeeta hai new SUV car ya cash prize in {lottery}. Government tax aur dispatch fee INR 12,500 jama karein: <url>",
                    "Special Lucky Draw: Aapka SIM number festival scheme me INR 10,00,000 jeet gaya hai. Claim approval ke liye call karein: <phone>",
                    "Reward Alert: Aapka approved prize amount INR 20,00,000 transfer ke liye ready hai. Clearance officer ko phone karein on <phone>."
                ],
                "malicious_apk_qr_scam": [
                    "{bank} Customer Support: Pending refund balance receive karne ke liye hamara official mobile assist app {app_name} download karein: <url>",
                    "UPI Refund Desk: Bank refund INR 2,950 collect karne ke liye attached QR code scan karein aur UPI PIN enter karein.",
                    "Account Support: Blocked netbanking unfreeze karne ke liye mandatory security tool {app_name} install karein from <url>.",
                    "{bank} Tech Team: Mobile banking mandatory update APK launch hua hai. Service chalu rakhne ke liye file install karein: <url>"
                ]
            }
        },
        "hi": {
            CANONICAL_BENIGN: {
                "otp_negation": [
                    "सुरक्षा सूचना: {bank} कभी भी फोन, एसएमएस या ईमेल पर पासवर्ड, सीवीवी या ओटीपी नहीं मांगता है। अपनी गोपनीय जानकारी सुरक्षित रखें।",
                    "प्रिय ग्राहक, आपके {bank} खाते का लॉगिन ओटीपी {otp} है। यह 10 मिनट तक वैध है। किसी भी व्यक्ति या बैंक अधिकारी के साथ ओटीपी साझा न करें। सतर्क रहें।",
                    "{bank} धोखाधड़ी रोकथाम: आपके डेबिट लेन-देन हेतु सत्यापन कोड {otp} है। यदि यह आपने नहीं किया है तो किसी को ओटीपी न बताएं और तुरंत 1930 पर रिपोर्ट करें।",
                    "सतर्कता संदेश ({bank}): बैंक कभी भी फोन कॉल पर आपसे पासवर्ड या ओटीपी नहीं मांगता है। अनधिकृत संपर्कों से सतर्क रहें।"
                ],
                "otp_operational": [
                    "आपके {bank} इंटरनेट बैंकिंग का एकमुश्त सत्यापन कोड {otp} है। यह कोड 10 मिनट के लिए वैध है। इसे केवल आधिकारिक लॉगिन पृष्ठ पर दर्ज करें।",
                    "{bank} खाते <acct> से ₹2,500 के धन अंतरण हेतु ओटीपी {otp} है। यह केवल एक बार प्रयोग हेतु 3 मिनट के लिए मान्य है।",
                    "{bank} मोबाइल प्रोफाइल सुरक्षा अद्यतन हेतु ओटीपी {otp} है। सत्यापन पूरा करने हेतु आधिकारिक ऐप में दर्ज करें।",
                    "प्रिय ग्राहक, {bank} खाते में नए लाभार्थी पंजीकरण हेतु ओटीपी {otp} जारी किया गया है। यह कोड 5 मिनट तक मान्य है।"
                ],
                "bank_transactional": [
                    "सूचना: आपके {bank} खाते <acct> से ₹2,450.00 का यूपीआई आहरण दिनांक 05-Nov-26 को किया गया है (Ref <ref>)। शेष राशि: ₹36,200.00। यदि यह आपने नहीं किया तो 1930 पर शिकायत करें।",
                    "{bank}: आपके खाते <acct> में मासिक वेतन ₹58,000.00 एनईएफटी Ref <ref> द्वारा दिनांक 01-Nov-26 को जमा हुआ। कुल शेष राशि: ₹72,500.00।",
                    "लेन-देन सूचना: {bank} डेबिट कार्ड <card> द्वारा एटीएम से ₹2,000 का नकद आहरण दिनांक 04-Nov-26 को किया गया। शेष राशि: ₹24,100.00।",
                    "{bank} सूचना: आपके खाते <acct> में आईएमपीएस Ref <ref> द्वारा ₹3,500 की राशि जमा की गई है। उपलब्ध शेष: ₹27,600.00।"
                ],
                "utility_service_notice": [
                    "{utility}: आपके उपभोक्ता नंबर <acct> का बिजली बिल ₹980 दिनांक 15-Nov-26 तक देय है। भुगतान आधिकारिक वेबसाइट <url> पर सुरक्षित रूप से करें।",
                    "विद्युत वितरण निगम: आपके मीटर नंबर <acct> का मासिक विद्युत उपभोग बिल ₹840 दिनांक 18-Nov-26 तक देय है। आधिकारिक पोर्टल से रसीद प्राप्त करें।",
                    "नगर निगम जल आपूर्ति: आपके जल संयोजन <acct> का त्रैमासिक बिल ₹520 देय है। अंतिम तिथि से पूर्व नागरिक सुविधा केंद्र पर जमा करें।"
                ],
                "service_informational": [
                    "प्रिय ग्राहक, वित्तीय वर्ष 2025-26 हेतु आपका {bank} वार्षिक ब्याज प्रमाणपत्र तैयार है। विवरण देखने हेतु नेटबैंकिंग पोर्टल से डाउनलोड करें।",
                    "{bank} शाखा सूचना: क्षेत्रीय त्योहार के अवसर पर दिनांक 12-Nov-26 को सभी शाखाएं बंद रहेंगी। डिजिटल बैंकिंग सेवाएं सामान्य रूप से जारी रहेंगी।",
                    "ग्राहक सेवा सूचना: आपकी चेकबुक डिस्पैच अनुरोध Ref <ref> को पंजीकृत डाक द्वारा भेज दिया गया है।",
                    "{bank} सावधि जमा सूचना: आपके खाते <acct> की सावधि जमा (FD) रसीद का अगले 12 माह हेतु सामान्य ब्याज दर पर स्वतः नवीनीकरण हो गया है।"
                ],
                "commercial_promo_ham": [
                    "सप्ताहांत विशेष छूट: {retail} पर ताजी सब्जियों एवं किराना सामान पर 25% की विशेष छूट पाएं। कूपन कोड FRESH25 का उपयोग करें।",
                    "{retail}: नए मौसम के परिधानों का संग्रह उपलब्ध है! निकटतम स्टोर पर पधारें अथवा मुफ्त होम डिलीवरी हेतु वेबसाइट <url> देखें।",
                    "स्वादिष्ट भोजन का आनंद लें: {retail} ऐप द्वारा भोजन ऑर्डर करने पर ₹75 की सीधी छूट पाएं। न्यूनतम ऑर्डर ₹249।"
                ]
            },
            CANONICAL_SUSPICIOUS: {
                "kyc_phishing": [
                    "अति आवश्यक सूचना: आपका {bank} खाता केवाईसी सत्यापन अधूरा होने के कारण आज बंद कर दिया जाएगा। खाता चालू रखने हेतु तुरंत क्लिक करें: <url>",
                    "अंतिम चेतावनी: {bank} नेटबैंकिंग सेवा 12 घंटे के भीतर स्थायी रूप से निलंबित कर दी जाएगी। अपनी पहचान तुरंत सत्यापित करें: <url>",
                    "{bank} सुरक्षा संदेश: आपके खाते में संदिग्ध लॉगिन पाया गया है। खाता सुरक्षित रखने हेतु तुरंत अपना पैन कार्ड अद्यतन करें: <url>",
                    "प्रिय ग्राहक, पहचान दस्तावेज पुराने होने के कारण आपका {bank} डेबिट कार्ड निष्क्रिय कर दिया गया है। कार्ड पुनः चालू करने हेतु लिंक देखें: <url>"
                ],
                "digital_arrest_impersonation": [
                    "{agency} नोटिस: आपके आधार कार्ड से जुड़ा एक अवैध पार्सल कस्टम द्वारा जब्त किया गया है। गिरफ्तारी वारंट से बचने हेतु तुरंत इस नंबर पर संपर्क करें: <phone>",
                    "आवश्यक कानूनी सूचना: {agency} द्वारा आपके पैन नंबर पर वित्तीय धोखाधड़ी की जांच दर्ज की गई है। अधिकारी से तुरंत संपर्क करें: <phone>",
                    "{agency}: मनी लॉन्ड्रिंग मामले में आपके विरुद्ध वारंट जारी किया गया है। कानूनी कार्यवाही से बचने हेतु वीडियो कॉल द्वारा जांच अधिकारी से जुड़ें: <phone>",
                    "कानूनी चेतावनी: प्रतिबंधित सामग्री मामले में आपकी संलिप्तता पाई गई है। तुरंत जांच अधिकारी को फोन करें: <phone>"
                ],
                "electricity_disconnection": [
                    "बिजली विभाग चेतावनी: प्रिय उपभोक्ता आज रात 9:30 बजे आपका बिजली कनेक्शन काट दिया जाएगा क्योंकि बिल अपडेट नहीं है। तुरंत बिजली अधिकारी <phone> पर संपर्क करें।",
                    "{utility}: उपभोक्ता संख्या <acct> की विद्युत आपूर्ति आज बकाया बिल के कारण स्थगित की जा रही है। लाइनमैन अधिकारी <phone> पर संपर्क करें।",
                    "आवश्यक विद्युत सूचना: आपका पिछला बिजली बिल अमान्य हो गया है। अगले 2 घंटे में बिजली आपूर्ति रोक दी जाएगी। तुरंत संपर्क करें: <phone>",
                    "ऊर्जा निगम सूचना: बिजली बिल का सत्यापन न होने पर कनेक्शन काटने का आदेश जारी हुआ है। तुरंत विभागीय नंबर <phone> पर बात करें।"
                ],
                "part_time_job_scam": [
                    "घर बैठे रोजाना ₹2,000 से ₹5,000 कमाएं! केवल ऑनलाइन उत्पाद समीक्षा करें और तुरंत दैनिक भुगतान पाएं। संपर्क हेतु टेलीग्राम लिंक पर क्लिक करें: <url>",
                    "पार्ट टाइम नौकरी: यूट्यूब वीडियो लाइक करके प्रतिदिन ₹2,500 तक कमाएं। सीधे बैंक खाते में भुगतान। संपर्क करें: <phone>",
                    "आवश्यक भर्ती: वर्क फ्रॉम होम द्वारा सरल डेटा कार्य करके प्रतिमाह ₹40,000 तक कमाएं। कोई अनुभव आवश्यक नहीं। व्हाट्सएप करें: <phone>",
                    "ऑनलाइन कार्य अवसर: प्रतिदिन 2 घंटे काम करके निश्चित आय प्राप्त करें। पंजीकरण हेतु दिए गए लिंक पर जुड़ें: <url>"
                ],
                "lottery_advance_fee": [
                    "बधाई हो! {lottery} में आपका मोबाइल नंबर ₹25,00,000 जीत चुका है। पुरस्कार राशि प्राप्त करने हेतु दावा अधिकारी <phone> पर संपर्क करें।",
                    "भव्य पुरस्कार सूचना: आपको लकी ड्रा में नई कार या नकद राशि हेतु चुना गया है। पंजीकरण शुल्क ₹9,500 जमा करने हेतु संपर्क करें: <url>",
                    "विशेष लकी ड्रा: आपके सिम नंबर ने त्योहार योजना में ₹15,00,000 जीते हैं। पुरस्कार का चेक प्राप्त करने हेतु तुरंत संपर्क करें: <phone>",
                    "उपभोक्ता ईनाम सूचना: आपकी स्वीकृत लॉटरी राशि ₹20,00,000 ट्रांसफर हेतु तैयार है। तुरंत क्लेम मैनेजर से संपर्क करें: <phone>"
                ],
                "malicious_apk_qr_scam": [
                    "{bank} ग्राहक सहायता: अपने रुके हुए लेन-देन का रिफंड प्राप्त करने हेतु आधिकारिक सहायता टूल {app_name} इंस्टॉल करें: <url>",
                    "यूपीआई रिफंड पोर्टल: खाते में ₹3,250 का रुका हुआ रिफंड प्राप्त करने हेतु संलग्न क्यूआर कोड स्कैन करें और पिन दर्ज करें।",
                    "खाता सहायता केंद्र: ब्लॉक नेटबैंकिंग पुनः शुरू करने हेतु अनिवार्य सुरक्षा एप्लिकेशन {app_name} इस लिंक से डाउनलोड करें: <url>"
                ]
            }
        }
    }


# -----------------------------------------------------------------------------
# Record Generation Logic
# -----------------------------------------------------------------------------

def fill_slots(template: str, lang: str, rng: random.Random) -> str:
    """
    Substitutes fictional entities into template placeholders using the provided RNG.
    """
    if lang == "en":
        bank = rng.choice(FICTIONAL_BANKS_EN)
        utility = rng.choice(FICTIONAL_UTILITIES_EN)
        agency = rng.choice(FICTIONAL_AGENCIES_EN)
        telecom = rng.choice(FICTIONAL_TELECOMS_EN)
        retail = rng.choice(FICTIONAL_RETAIL_EN)
        lottery = rng.choice(FICTIONAL_LOTTERIES_EN)
        app_name = rng.choice(FICTIONAL_APPS_EN)
    elif lang == "hi":
        bank = rng.choice(FICTIONAL_BANKS_HI)
        utility = rng.choice(FICTIONAL_UTILITIES_HI)
        agency = rng.choice(FICTIONAL_AGENCIES_HI)
        telecom = rng.choice(FICTIONAL_TELECOMS_HI)
        retail = rng.choice(FICTIONAL_RETAIL_HI)
        lottery = rng.choice(FICTIONAL_LOTTERIES_HI)
        app_name = rng.choice(FICTIONAL_APPS_HI)
    else:  # hinglish
        bank = rng.choice(FICTIONAL_BANKS_HN)
        utility = rng.choice(FICTIONAL_UTILITIES_HN)
        agency = rng.choice(FICTIONAL_AGENCIES_HN)
        telecom = rng.choice(FICTIONAL_TELECOMS_HN)
        retail = rng.choice(FICTIONAL_RETAIL_HN)
        lottery = rng.choice(FICTIONAL_LOTTERIES_HN)
        app_name = rng.choice(FICTIONAL_APPS_HN)

    otp = f"{rng.randint(100000, 999999)}"

    filled = template.format(
        bank=bank,
        utility=utility,
        agency=agency,
        telecom=telecom,
        retail=retail,
        lottery=lottery,
        app_name=app_name,
        otp=otp
    )
    return filled


def generate_pilot_dataset(seed: int = 42) -> List[Dict[str, str]]:
    """
    Generates exactly 150 candidate records adhering to the Phase 6C.1 specification:
    - 75 BENIGN, 75 SUSPICIOUS
    - 53 English (en), 52 Roman Hinglish (hinglish), 45 Hindi (hi)
    - Full 15-column schema with governance metadata.
    """
    rng = random.Random(seed)
    catalog = build_template_catalog()

    records: List[Dict[str, str]] = []
    seen_texts: Set[str] = set()

    # Quota allocation: [lang][label][category] -> target count
    # English (53 total: 27 BENIGN, 26 SUSPICIOUS)
    # Hinglish (52 total: 26 BENIGN, 26 SUSPICIOUS)
    # Hindi (45 total: 22 BENIGN, 23 SUSPICIOUS)
    quotas = {
        "en": {
            CANONICAL_BENIGN: {
                "otp_negation": 5,
                "otp_operational": 4,
                "bank_transactional": 5,
                "utility_service_notice": 4,
                "service_informational": 5,
                "commercial_promo_ham": 4
            },
            CANONICAL_SUSPICIOUS: {
                "kyc_phishing": 5,
                "digital_arrest_impersonation": 4,
                "electricity_disconnection": 5,
                "part_time_job_scam": 4,
                "lottery_advance_fee": 4,
                "malicious_apk_qr_scam": 4
            }
        },
        "hinglish": {
            CANONICAL_BENIGN: {
                "otp_negation": 5,
                "otp_operational": 4,
                "bank_transactional": 4,
                "utility_service_notice": 4,
                "service_informational": 4,
                "commercial_promo_ham": 5
            },
            CANONICAL_SUSPICIOUS: {
                "kyc_phishing": 5,
                "digital_arrest_impersonation": 4,
                "electricity_disconnection": 4,
                "part_time_job_scam": 5,
                "lottery_advance_fee": 4,
                "malicious_apk_qr_scam": 4
            }
        },
        "hi": {
            CANONICAL_BENIGN: {
                "otp_negation": 4,
                "otp_operational": 4,
                "bank_transactional": 4,
                "utility_service_notice": 3,
                "service_informational": 4,
                "commercial_promo_ham": 3
            },
            CANONICAL_SUSPICIOUS: {
                "kyc_phishing": 4,
                "digital_arrest_impersonation": 4,
                "electricity_disconnection": 4,
                "part_time_job_scam": 4,
                "lottery_advance_fee": 4,
                "malicious_apk_qr_scam": 3
            }
        }
    }

    prefix_map = {"en": "PILOT_EN", "hinglish": "PILOT_HN", "hi": "PILOT_HI"}

    for lang in ("en", "hinglish", "hi"):
        seq_num = 1
        for label in (CANONICAL_BENIGN, CANONICAL_SUSPICIOUS):
            for category, target_count in quotas[lang][label].items():
                templates = catalog[lang][label][category]
                generated_for_category = 0

                # Cycle deterministically through templates and slot variations
                template_idx = 0
                while generated_for_category < target_count:
                    tpl = templates[template_idx % len(templates)]
                    raw_text = fill_slots(tpl, lang, rng)

                    # Scrub PII
                    scrubbed, _ = scrub_text(raw_text)

                    # Check for exact duplicate in this run
                    if scrubbed in seen_texts:
                        template_idx += 1
                        continue

                    seen_texts.add(scrubbed)

                    row_id = f"{prefix_map[lang]}_{seq_num:03d}"
                    seq_num += 1

                    record = {
                        "id": row_id,
                        "text": scrubbed,
                        "label": label,
                        "language": lang,
                        "category": category,
                        "source": "synthetic_pilot_generator",
                        "reviewed_by": "none",
                        "notes": f"Synthetic pilot candidate generated from grammar {category}",
                        "source_id": "SRC-09",
                        "source_url": "https://github.com/satark-detector/satark-dataset-specs",
                        "license": "MIT",
                        "provenance_type": "synthetic",
                        "reviewer_status": "pending_review",
                        "review_timestamp": "none",
                        "label_confidence": "1.0"
                    }
                    records.append(record)
                    generated_for_category += 1
                    template_idx += 1

    return records


# -----------------------------------------------------------------------------
# Quality Control & Auditing Suite
# -----------------------------------------------------------------------------

def compute_token_jaccard(s1: str, s2: str) -> float:
    """Calculates word-level Jaccard similarity between two texts."""
    tokens1 = set(s1.lower().split())
    tokens2 = set(s2.lower().split())
    if not tokens1 or not tokens2:
        return 0.0
    intersection = tokens1.intersection(tokens2)
    union = tokens1.union(tokens2)
    return len(intersection) / len(union)


def audit_pilot_dataset(
    records: List[Dict[str, str]],
    benchmark_file: Optional[Path] = None,
    similarity_threshold: float = 0.85
) -> Dict[str, Any]:
    """
    Executes a multi-dimensional data quality audit on candidate records:
    1. Exact duplicates
    2. Normalized duplicates
    3. Template fingerprint diversity
    4. Near-duplicate / semantic similarity collisions (> 0.85 Jaccard)
    5. Contradictory labels for identical or near-identical texts
    6. Language script validation (Devanagari for hi, Latin for en/hinglish)
    7. PII leakage detection
    8. Benchmark contamination cross-check
    9. Class and language distribution adherence
    """
    audit_results: Dict[str, Any] = {
        "total_records": len(records),
        "exact_duplicates": 0,
        "normalized_duplicates": 0,
        "unique_templates": 0,
        "near_duplicate_pairs": [],
        "pii_violations": 0,
        "script_mismatches": 0,
        "contradictory_labels": 0,
        "benchmark_contamination": 0,
        "class_distribution": {},
        "language_distribution": {},
        "category_distribution": {},
        "verifications": {}
    }

    seen_exact = set()
    seen_normalized = set()
    template_fps = set()
    text_to_label = {}

    devanagari_regex = re.compile(r'[\u0900-\u097F]')

    for idx, r in enumerate(records):
        t = r["text"]
        norm_t = re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', '', t.lower())).strip()
        fp = extract_template_fingerprint(t)
        template_fps.add(fp)

        # 1. Exact Duplicates
        if t in seen_exact:
            audit_results["exact_duplicates"] += 1
        seen_exact.add(t)

        # 2. Normalized Duplicates
        if norm_t in seen_normalized:
            audit_results["normalized_duplicates"] += 1
        seen_normalized.add(norm_t)

        # 3. Contradictory Labels
        if norm_t in text_to_label and text_to_label[norm_t] != r["label"]:
            audit_results["contradictory_labels"] += 1
        text_to_label[norm_t] = r["label"]

        # 4. Script Verification
        has_devanagari = bool(devanagari_regex.search(t))
        if r["language"] == "hi" and not has_devanagari:
            audit_results["script_mismatches"] += 1
        elif r["language"] in ("en", "hinglish") and has_devanagari:
            audit_results["script_mismatches"] += 1

        # 5. PII Audit
        if has_unmasked_pii(t):
            audit_results["pii_violations"] += 1

        # Distributions
        lbl = r["label"]
        lng = r["language"]
        cat = r["category"]
        audit_results["class_distribution"][lbl] = audit_results["class_distribution"].get(lbl, 0) + 1
        audit_results["language_distribution"][lng] = audit_results["language_distribution"].get(lng, 0) + 1
        audit_results["category_distribution"][cat] = audit_results["category_distribution"].get(cat, 0) + 1

    audit_results["unique_templates"] = len(template_fps)

    # 6. Pairwise Near-Duplicate Similarity Check
    n = len(records)
    for i in range(n):
        for j in range(i + 1, n):
            if records[i]["language"] == records[j]["language"]:
                sim = compute_token_jaccard(records[i]["text"], records[j]["text"])
                if sim >= similarity_threshold:
                    audit_results["near_duplicate_pairs"].append({
                        "id1": records[i]["id"],
                        "id2": records[j]["id"],
                        "similarity": round(sim, 3),
                        "text1": records[i]["text"][:60],
                        "text2": records[j]["text"][:60]
                    })

    # 7. Benchmark Contamination Cross-Check
    if benchmark_file and Path(benchmark_file).exists():
        with open(benchmark_file, mode="r", encoding="utf-8-sig") as bf:
            reader = csv.DictReader(bf)
            bench_texts = {re.sub(r'\s+', ' ', row.get("text", "").lower()).strip() for row in reader if "text" in row}
            for r in records:
                cand_norm = re.sub(r'\s+', ' ', r["text"].lower()).strip()
                if cand_norm in bench_texts:
                    audit_results["benchmark_contamination"] += 1

    # Status summary
    audit_results["verifications"]["exact_duplicates"] = "PASS" if audit_results["exact_duplicates"] == 0 else "FAIL"
    audit_results["verifications"]["normalized_duplicates"] = "PASS" if audit_results["normalized_duplicates"] == 0 else "FAIL"
    audit_results["verifications"]["pii_absence"] = "PASS" if audit_results["pii_violations"] == 0 else "FAIL"
    audit_results["verifications"]["script_consistency"] = "PASS" if audit_results["script_mismatches"] == 0 else "FAIL"
    audit_results["verifications"]["benchmark_isolation"] = (
        ("PASS" if audit_results["benchmark_contamination"] == 0 else "FAIL")
        if benchmark_file and Path(benchmark_file).is_file() else "NOT_RUN"
    )
    audit_results["verifications"]["class_balance"] = "PASS" if (
        audit_results["class_distribution"].get(CANONICAL_BENIGN) == 75 and
        audit_results["class_distribution"].get(CANONICAL_SUSPICIOUS) == 75
    ) else "FAIL"
    audit_results["verifications"]["language_balance"] = "PASS" if (
        audit_results["language_distribution"].get("en") == 53 and
        audit_results["language_distribution"].get("hinglish") == 52 and
        audit_results["language_distribution"].get("hi") == 45
    ) else "FAIL"

    # Deep semantic diversity and empirical ground truth are UNVERIFIED without human review
    audit_results["verifications"]["semantic_diversity"] = "UNVERIFIED"
    audit_results["verifications"]["human_ground_truth"] = "UNVERIFIED"

    return audit_results


def write_pilot_csv(records: List[Dict[str, str]], output_path: Path) -> None:
    """Writes the pilot candidate records to the specified destination path."""
    dest = Path(output_path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = REQUIRED_COLUMNS + GOVERNANCE_COLUMNS

    with open(dest, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    logger.info(f"Successfully generated and wrote {len(records)} pilot records to: {dest}")


def write_csv(records: List[Dict[str, str]], output_path: Path) -> None:
    """Writes records to the specified destination path."""
    write_pilot_csv(records, output_path)


# -----------------------------------------------------------------------------
# Full 4,500-Record Training Corpus Generator
# -----------------------------------------------------------------------------

FULL_CORPUS_QUOTAS = {
    "en": {
        CANONICAL_BENIGN: {
            "otp_negation": 131,
            "otp_operational": 131,
            "bank_transactional": 131,
            "utility_service_notice": 131,
            "service_informational": 132,
            "commercial_promo_ham": 132,
        },
        CANONICAL_SUSPICIOUS: {
            "kyc_phishing": 131,
            "digital_arrest_impersonation": 131,
            "electricity_disconnection": 131,
            "part_time_job_scam": 131,
            "lottery_advance_fee": 131,
            "malicious_apk_qr_scam": 132,
        },
    },
    "hinglish": {
        CANONICAL_BENIGN: {
            "otp_negation": 131,
            "otp_operational": 131,
            "bank_transactional": 131,
            "utility_service_notice": 131,
            "service_informational": 131,
            "commercial_promo_ham": 132,
        },
        CANONICAL_SUSPICIOUS: {
            "kyc_phishing": 131,
            "digital_arrest_impersonation": 131,
            "electricity_disconnection": 131,
            "part_time_job_scam": 131,
            "lottery_advance_fee": 132,
            "malicious_apk_qr_scam": 132,
        },
    },
    "hi": {
        CANONICAL_BENIGN: {
            "otp_negation": 112,
            "otp_operational": 112,
            "bank_transactional": 112,
            "utility_service_notice": 113,
            "service_informational": 113,
            "commercial_promo_ham": 113,
        },
        CANONICAL_SUSPICIOUS: {
            "kyc_phishing": 112,
            "digital_arrest_impersonation": 112,
            "electricity_disconnection": 112,
            "part_time_job_scam": 113,
            "lottery_advance_fee": 113,
            "malicious_apk_qr_scam": 113,
        },
    },
}


def fill_expanded_slots(template: str, lang: str, rng: random.Random) -> str:
    """Substitutes fictional entities and parameters into template placeholders."""
    slots_by_lang = EXPANDED_SLOTS.get(lang, EXPANDED_SLOTS["en"])
    slots = {k: rng.choice(v) for k, v in slots_by_lang.items()}
    slots["otp"] = f"{rng.randint(100000, 999999)}"
    return template.format(**slots)


def validate_batch(
    batch_records: List[Dict[str, str]],
    lang: str,
    benchmark_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Validates a generated single-language batch:
    - Verifies script integrity (Devanagari for hi, Latin for en/hinglish).
    - Verifies PII absence using regex scanner.
    - Verifies benchmark isolation against test_set.csv.
    - Verifies zero within-batch exact or normalized duplicates.
    """
    devanagari_regex = re.compile(r'[\u0900-\u097F]')
    batch_audit = {
        "batch_size": len(batch_records),
        "exact_duplicates": 0,
        "normalized_duplicates": 0,
        "pii_violations": 0,
        "script_mismatches": 0,
        "benchmark_contamination": 0,
    }

    seen_exact = set()
    seen_norm = set()

    bench_texts = set()
    if benchmark_file and Path(benchmark_file).exists():
        with open(benchmark_file, mode="r", encoding="utf-8-sig") as bf:
            reader = csv.DictReader(bf)
            bench_texts = {re.sub(r'\s+', ' ', row.get("text", "").lower()).strip() for row in reader if "text" in row}

    for r in batch_records:
        t = r["text"]
        norm_t = re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', '', t.lower())).strip()

        if t in seen_exact:
            batch_audit["exact_duplicates"] += 1
        seen_exact.add(t)

        if norm_t in seen_norm:
            batch_audit["normalized_duplicates"] += 1
        seen_norm.add(norm_t)

        has_devanagari = bool(devanagari_regex.search(t))
        if lang == "hi" and not has_devanagari:
            batch_audit["script_mismatches"] += 1
        elif lang in ("en", "hinglish") and has_devanagari:
            batch_audit["script_mismatches"] += 1

        if has_unmasked_pii(t):
            batch_audit["pii_violations"] += 1

        if bench_texts and norm_t in bench_texts:
            batch_audit["benchmark_contamination"] += 1

    return batch_audit


def generate_batch(
    lang: str,
    target_quotas: Dict[str, Dict[str, int]],
    catalog: Dict[str, Dict[str, Dict[str, List[str]]]],
    rng: random.Random,
    seen_exact_global: Set[str],
    seen_norm_global: Set[str],
    seq_start: int = 1,
    prefix: str = "SYNTH_CORPUS",
) -> Tuple[List[Dict[str, str]], int]:
    """
    Generates an isolated trilingual batch adhering to category quotas,
    deterministic slot selection, PII scrubbing, and within-category Jaccard < 0.85.
    """
    batch_records: List[Dict[str, str]] = []
    seq_num = seq_start

    for label in (CANONICAL_BENIGN, CANONICAL_SUSPICIOUS):
        for category, target_count in target_quotas[label].items():
            tpls = catalog[lang][label][category]
            cat_generated = 0
            tpl_idx = 0
            attempts = 0
            cat_texts: List[str] = []

            while cat_generated < target_count and attempts < target_count * 200:
                attempts += 1
                tpl = tpls[tpl_idx % len(tpls)]
                tpl_idx += 1

                raw_text = fill_expanded_slots(tpl, lang, rng)
                scrubbed, _ = scrub_text(raw_text)

                if scrubbed in seen_exact_global:
                    continue

                norm_text = re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', '', scrubbed.lower())).strip()
                if norm_text in seen_norm_global:
                    continue

                # Jaccard collision check within category
                is_near_dup = False
                for prev in cat_texts:
                    if compute_token_jaccard(scrubbed, prev) >= 0.85:
                        is_near_dup = True
                        break
                if is_near_dup:
                    continue

                seen_exact_global.add(scrubbed)
                seen_norm_global.add(norm_text)
                cat_texts.append(scrubbed)

                row_id = f"{prefix}_{lang.upper()}_{seq_num:04d}"
                seq_num += 1

                record = {
                    "id": row_id,
                    "text": scrubbed,
                    "label": label,
                    "language": lang,
                    "category": category,
                    "source": "synthetic_corpus_generator",
                    "reviewed_by": "none",
                    "notes": f"Synthetic corpus record generated from template {category} with isolated slots",
                    "source_id": "SRC-09",
                    "source_url": "https://github.com/satark-detector/satark-dataset-specs",
                    "license": "MIT",
                    "provenance_type": "synthetic",
                    "reviewer_status": "pending_review",
                    "review_timestamp": "none",
                    "label_confidence": "1.0",
                }
                batch_records.append(record)
                cat_generated += 1

            if cat_generated < target_count:
                raise RuntimeError(
                    f"Quota underfill for {lang} {label} {category}: generated {cat_generated}/{target_count} in {attempts} attempts"
                )

    return batch_records, seq_num


def generate_full_corpus(
    seed: int = 42,
    benchmark_file: Optional[Path] = None,
) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """
    Generates the complete 4,500-record training corpus across 3 verified language batches:
    - Batch 1: English (1,575 records)
    - Batch 2: Roman Hinglish (1,575 records)
    - Batch 3: Devanagari Hindi (1,350 records)
    Validates each batch independently before merging into the unified corpus.
    """
    rng = random.Random(seed)
    catalog = build_expanded_template_catalog()

    seen_exact_global: Set[str] = set()
    seen_norm_global: Set[str] = set()

    corpus_records: List[Dict[str, str]] = []
    batch_audit_reports: Dict[str, Any] = {}

    # Batch 1: English
    logger.info("Generating Batch 1/3: English (1,575 target records)...")
    b1_records, _ = generate_batch(
        "en", FULL_CORPUS_QUOTAS["en"], catalog, rng,
        seen_exact_global, seen_norm_global, seq_start=1
    )
    b1_audit = validate_batch(b1_records, "en", benchmark_file=benchmark_file)
    assert b1_audit["exact_duplicates"] == 0, f"Batch 1 exact duplicates: {b1_audit['exact_duplicates']}"
    assert b1_audit["normalized_duplicates"] == 0, f"Batch 1 norm duplicates: {b1_audit['normalized_duplicates']}"
    assert b1_audit["pii_violations"] == 0, f"Batch 1 PII violations: {b1_audit['pii_violations']}"
    assert b1_audit["script_mismatches"] == 0, f"Batch 1 script mismatches: {b1_audit['script_mismatches']}"
    assert b1_audit["benchmark_contamination"] == 0, f"Batch 1 contamination: {b1_audit['benchmark_contamination']}"
    batch_audit_reports["batch_1_en"] = b1_audit
    corpus_records.extend(b1_records)
    logger.info(f"Batch 1 validated successfully ({len(b1_records)} records).")

    # Batch 2: Hinglish
    logger.info("Generating Batch 2/3: Roman Hinglish (1,575 target records)...")
    b2_records, _ = generate_batch(
        "hinglish", FULL_CORPUS_QUOTAS["hinglish"], catalog, rng,
        seen_exact_global, seen_norm_global, seq_start=1
    )
    b2_audit = validate_batch(b2_records, "hinglish", benchmark_file=benchmark_file)
    assert b2_audit["exact_duplicates"] == 0, f"Batch 2 exact duplicates: {b2_audit['exact_duplicates']}"
    assert b2_audit["normalized_duplicates"] == 0, f"Batch 2 norm duplicates: {b2_audit['normalized_duplicates']}"
    assert b2_audit["pii_violations"] == 0, f"Batch 2 PII violations: {b2_audit['pii_violations']}"
    assert b2_audit["script_mismatches"] == 0, f"Batch 2 script mismatches: {b2_audit['script_mismatches']}"
    assert b2_audit["benchmark_contamination"] == 0, f"Batch 2 contamination: {b2_audit['benchmark_contamination']}"
    batch_audit_reports["batch_2_hinglish"] = b2_audit
    corpus_records.extend(b2_records)
    logger.info(f"Batch 2 validated successfully ({len(b2_records)} records).")

    # Batch 3: Hindi
    logger.info("Generating Batch 3/3: Devanagari Hindi (1,350 target records)...")
    b3_records, _ = generate_batch(
        "hi", FULL_CORPUS_QUOTAS["hi"], catalog, rng,
        seen_exact_global, seen_norm_global, seq_start=1
    )
    b3_audit = validate_batch(b3_records, "hi", benchmark_file=benchmark_file)
    assert b3_audit["exact_duplicates"] == 0, f"Batch 3 exact duplicates: {b3_audit['exact_duplicates']}"
    assert b3_audit["normalized_duplicates"] == 0, f"Batch 3 norm duplicates: {b3_audit['normalized_duplicates']}"
    assert b3_audit["pii_violations"] == 0, f"Batch 3 PII violations: {b3_audit['pii_violations']}"
    assert b3_audit["script_mismatches"] == 0, f"Batch 3 script mismatches: {b3_audit['script_mismatches']}"
    assert b3_audit["benchmark_contamination"] == 0, f"Batch 3 contamination: {b3_audit['benchmark_contamination']}"
    batch_audit_reports["batch_3_hi"] = b3_audit
    corpus_records.extend(b3_records)
    logger.info(f"Batch 3 validated successfully ({len(b3_records)} records).")

    assert len(corpus_records) == 4500, f"Expected 4,500 records, got {len(corpus_records)}"
    return corpus_records, batch_audit_reports


def audit_corpus_dataset(
    records: List[Dict[str, str]],
    benchmark_file: Optional[Path] = None,
    similarity_threshold: float = 0.85
) -> Dict[str, Any]:
    """
    Executes a comprehensive data quality audit across the full 4,500-row corpus:
    1. Exact duplicates
    2. Normalized duplicates
    3. Template fingerprint diversity
    4. Category-level pairwise near-duplicate Jaccard similarity
    5. Contradictory labels for identical or near-identical texts
    6. Language script validation (Devanagari for hi, Latin for en/hinglish)
    7. PII leakage detection
    8. Benchmark contamination cross-check
    9. Class, language, and category distributions
    """
    audit_results: Dict[str, Any] = {
        "total_records": len(records),
        "exact_duplicates": 0,
        "normalized_duplicates": 0,
        "unique_templates": 0,
        "near_duplicate_pairs": [],
        "pii_violations": 0,
        "script_mismatches": 0,
        "contradictory_labels": 0,
        "benchmark_contamination": 0,
        "class_distribution": {},
        "language_distribution": {},
        "category_distribution": {},
        "verifications": {}
    }

    seen_exact = set()
    seen_normalized = set()
    template_fps = set()
    text_to_label = {}

    devanagari_regex = re.compile(r'[\u0900-\u097F]')
    by_category_lang: Dict[Tuple[str, str], List[Dict[str, str]]] = {}

    for r in records:
        t = r["text"]
        norm_t = re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', '', t.lower())).strip()
        fp = extract_template_fingerprint(t)
        template_fps.add(fp)

        # 1. Exact Duplicates
        if t in seen_exact:
            audit_results["exact_duplicates"] += 1
        seen_exact.add(t)

        # 2. Normalized Duplicates
        if norm_t in seen_normalized:
            audit_results["normalized_duplicates"] += 1
        seen_normalized.add(norm_t)

        # 3. Contradictory Labels
        if norm_t in text_to_label and text_to_label[norm_t] != r["label"]:
            audit_results["contradictory_labels"] += 1
        text_to_label[norm_t] = r["label"]

        # 4. Script Verification
        has_devanagari = bool(devanagari_regex.search(t))
        if r["language"] == "hi" and not has_devanagari:
            audit_results["script_mismatches"] += 1
        elif r["language"] in ("en", "hinglish") and has_devanagari:
            audit_results["script_mismatches"] += 1

        # 5. PII Audit
        if has_unmasked_pii(t):
            audit_results["pii_violations"] += 1

        # Distributions
        lbl = r["label"]
        lng = r["language"]
        cat = r["category"]
        audit_results["class_distribution"][lbl] = audit_results["class_distribution"].get(lbl, 0) + 1
        audit_results["language_distribution"][lng] = audit_results["language_distribution"].get(lng, 0) + 1
        audit_results["category_distribution"][cat] = audit_results["category_distribution"].get(cat, 0) + 1

        key = (lng, cat)
        by_category_lang.setdefault(key, []).append(r)

    audit_results["unique_templates"] = len(template_fps)

    # 6. Pairwise Near-Duplicate Similarity Check (within same category & language)
    for (lng, cat), recs in by_category_lang.items():
        n = len(recs)
        for i in range(n):
            for j in range(i + 1, n):
                sim = compute_token_jaccard(recs[i]["text"], recs[j]["text"])
                if sim >= similarity_threshold:
                    audit_results["near_duplicate_pairs"].append({
                        "id1": recs[i]["id"],
                        "id2": recs[j]["id"],
                        "similarity": round(sim, 3),
                        "text1": recs[i]["text"][:60],
                        "text2": recs[j]["text"][:60]
                    })

    # 7. Benchmark Contamination Cross-Check
    if benchmark_file and Path(benchmark_file).exists():
        with open(benchmark_file, mode="r", encoding="utf-8-sig") as bf:
            reader = csv.DictReader(bf)
            bench_texts = {re.sub(r'\s+', ' ', row.get("text", "").lower()).strip() for row in reader if "text" in row}
            for r in records:
                cand_norm = re.sub(r'\s+', ' ', r["text"].lower()).strip()
                if cand_norm in bench_texts:
                    audit_results["benchmark_contamination"] += 1

    # Status summary
    audit_results["verifications"]["exact_duplicates"] = "PASS" if audit_results["exact_duplicates"] == 0 else "FAIL"
    audit_results["verifications"]["normalized_duplicates"] = "PASS" if audit_results["normalized_duplicates"] == 0 else "FAIL"
    audit_results["verifications"]["pii_absence"] = "PASS" if audit_results["pii_violations"] == 0 else "FAIL"
    audit_results["verifications"]["script_consistency"] = "PASS" if audit_results["script_mismatches"] == 0 else "FAIL"
    audit_results["verifications"]["benchmark_isolation"] = (
        ("PASS" if audit_results["benchmark_contamination"] == 0 else "FAIL")
        if benchmark_file and Path(benchmark_file).is_file() else "NOT_RUN"
    )
    audit_results["verifications"]["class_balance"] = "PASS" if (
        audit_results["class_distribution"].get(CANONICAL_BENIGN) == 2250 and
        audit_results["class_distribution"].get(CANONICAL_SUSPICIOUS) == 2250
    ) else "FAIL"
    audit_results["verifications"]["language_balance"] = "PASS" if (
        audit_results["language_distribution"].get("en") == 1575 and
        audit_results["language_distribution"].get("hinglish") == 1575 and
        audit_results["language_distribution"].get("hi") == 1350
    ) else "FAIL"
    audit_results["verifications"]["category_coverage"] = "PASS" if len(audit_results["category_distribution"]) == 12 else "FAIL"
    audit_results["verifications"]["template_fingerprints"] = "PASS" if audit_results["unique_templates"] >= 720 else "FAIL"

    # Deep semantic diversity and empirical ground truth are UNVERIFIED without human review
    audit_results["verifications"]["semantic_diversity"] = "UNVERIFIED"
    audit_results["verifications"]["human_ground_truth"] = "UNVERIFIED"

    return audit_results


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="SATARK Synthetic Dataset Generator (Pilot and Full Corpus)")
    parser.add_argument("--mode", type=str, choices=["pilot", "full"], default="full", help="Generation mode: pilot (150 rows) or full (4500 rows).")
    parser.add_argument("--rows", type=int, default=None, help="Explicit target row count (150 or 4500). Overrides mode if given.")
    parser.add_argument("--output", type=str, default=None, help="Output CSV path.")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for deterministic generation.")
    parser.add_argument("--benchmark", type=str, default=None, help="Optional benchmark CSV for an explicitly authorized contamination check. Not read by default.")
    return parser.parse_args(argv)


def main():
    args = parse_args()

    mode = args.mode
    if args.rows == 150:
        mode = "pilot"
    elif args.rows == 4500:
        mode = "full"

    benchmark_p = Path(args.benchmark) if args.benchmark else None

    if mode == "pilot":
        output_p = Path(args.output) if args.output else PILOT_STAGING_PATH
        logger.info(f"Generating SATARK Pilot Dataset (150 rows, seed={args.seed})...")
        records = generate_pilot_dataset(seed=args.seed)
        audit = audit_pilot_dataset(records, benchmark_file=benchmark_p)
    else:
        output_p = Path(args.output) if args.output else TRAINING_CORPUS_PATH
        logger.info(f"Generating SATARK Full Training Corpus (4,500 rows, seed={args.seed})...")
        records, batch_audits = generate_full_corpus(seed=args.seed, benchmark_file=benchmark_p)
        audit = audit_corpus_dataset(records, benchmark_file=benchmark_p)

    write_csv(records, output_p)

    print("\n" + "=" * 70)
    print(f"SATARK SYNTHETIC DATASET GENERATION AUDIT REPORT ({mode.upper()})")
    print("=" * 70)
    print(f"Total Candidate Records : {audit['total_records']}")
    print(f"Exact Duplicates        : {audit['exact_duplicates']}")
    print(f"Normalized Duplicates   : {audit['normalized_duplicates']}")
    print(f"Unique Template Hashes  : {audit['unique_templates']}")
    print(f"Near-Duplicate Pairs    : {len(audit['near_duplicate_pairs'])}")
    print(f"PII Violations Detected : {audit['pii_violations']}")
    print(f"Script Mismatches       : {audit['script_mismatches']}")
    print(f"Benchmark Contamination : {audit['benchmark_contamination']}")
    print(f"Class Balance           : {audit['class_distribution']}")
    print(f"Language Breakdown      : {audit['language_distribution']}")
    print(f"Category Coverage (12)  : {audit['category_distribution']}")
    print("-" * 70)
    print("VERIFICATION CHECK RESULTS:")
    for check_name, status in audit["verifications"].items():
        print(f"  [{status}] {check_name}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

