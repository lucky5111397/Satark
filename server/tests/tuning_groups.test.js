import { describe, it, expect } from 'vitest';
import { analyzeMessage } from '../detection/analyzeMessage.js';

describe('Tuning Iterations (server/tests/tuning_groups.test.js)', () => {
  describe('Group 8: Genuine KYC Branch Reminder vs Phishing', () => {
    // 3 Invented Genuine Look-Alike Negatives (must NOT trigger KYC_LURE)
    it('negative 1: genuine English branch KYC reminder without URLs or OTP requests stays clear', () => {
      const text = 'ICICI Alert: Your periodic KYC update is due for A/c 9918. Please visit your nearest branch with original identity documents.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('KYC_LURE');
    });

    it('negative 2: genuine Hinglish branch KYC reminder without URLs or OTP requests stays clear', () => {
      const text = 'Canara Bank: Aapka account KYC re-verification pending hai. Kripya apni home branch me visit karein document verify karvane ke liye.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('KYC_LURE');
    });

    it('negative 3: genuine customer KYC advisory referencing physical branch visit stays clear', () => {
      const text = 'PNB Customer Notice: Update your KYC records by visiting any Punjab National Bank branch. Bank officials never ask for OTP or passwords.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('KYC_LURE');
    });

    // 3 Invented Positive Scam Messages (must STAY flagged, suppression must NOT apply)
    it('positive 1: scam with branch mention PLUS suspicious URL stays flagged', () => {
      const text = 'ICICI Alert: Your KYC update is due. Visit your nearest branch or update immediately at http://icici-verify-kyc.xyz';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('positive 2: scam with branch mention PLUS OTP request stays flagged', () => {
      const text = 'Bank Notice: KYC is expired. Visit nearest branch or share OTP 827102 with executive to complete verification.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.score).toBeGreaterThanOrEqual(3);
      expect(res.indicators.map(i => i.ruleId)).toContain('OTP_REQUEST');
    });

    it('positive 3: scam with branch mention PLUS urgency and deceptive link stays flagged', () => {
      const text = 'Urgent: Aapka bank KYC expire ho gaya. Branch visit karein ya turant link se karein http://update-kyc-fast.top/login';
      const res = analyzeMessage(text);
      expect(res.category).toBe('Suspicious');
      expect(res.score).toBeGreaterThanOrEqual(4);
    });
  });

  describe('Group 7: Independent Cause URL Scoring Tier (+4 for 2+ strong causes)', () => {
    // Genuine URLs: official domains, gov.in, nic.in, subdomains, www, paths, uppercase, trailing dots -> +0
    it('negative 1: official gov.in domain with trailing dot and path adds +0 risk score', () => {
      const text = 'Tax assessment notice: Check your official filing at https://eportal.incometax.gov.in/iec/foservices/.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.urlEvidence[0].flags).toEqual([]);
    });

    it('negative 2: uppercase gov.in URL with www and path adds +0 risk score', () => {
      const text = 'Government scholarship: Register online at HTTP://WWW.SCHOLARSHIPS.GOV.IN/APPLICATION';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
    });

    it('negative 3: official online banking portal with subdomain adds +0 risk score', () => {
      const text = 'SBI Alert: Monthly statement generated for account XX1029. Download securely from https://retail.onlinesbi.sbi/retail/login.htm';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
    });

    // Positive Multi-Flag URLs: 2+ independent causes (brand_lookalike + suspicious_tld) -> +4 (Suspicious)
    it('positive 1: brand lookalike on suspicious TLD (.xyz) scores +4 (Suspicious)', () => {
      const text = 'Important notice: Update your account details at https://hdfcbank-login.xyz/verify';
      const res = analyzeMessage(text);
      expect(res.category).toBe('Suspicious');
      expect(res.score).toBeGreaterThanOrEqual(4);
    });

    it('positive 2: SBI brand lookalike on suspicious TLD (.xyz) scores +4 (Suspicious)', () => {
      const text = 'Security alert: Unusual login detected from new device. Verify at http://sbi-portal.xyz/login';
      const res = analyzeMessage(text);
      expect(res.category).toBe('Suspicious');
      expect(res.score).toBeGreaterThanOrEqual(4);
    });

    it('positive 3: Punycode domain on suspicious TLD scores +4 (Suspicious)', () => {
      const text = 'Bank update: Access your portal at https://xn--sb-yqa.top/auth';
      const res = analyzeMessage(text);
      expect(res.category).toBe('Suspicious');
      expect(res.score).toBeGreaterThanOrEqual(4);
    });
  });

  describe('Group 3: OTP Wordings, Synonyms & Bounded SOV Grammar', () => {
    // 3 Invented Genuine Look-Alike Negatives with Negation Guards (must stay score 0)
    it('negative 1: genuine verification code delivery with "Do not share it with anyone" stays clear', () => {
      const text = 'Your verification code is 581029 for online banking access. Do not share it with anyone.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('OTP_REQUEST');
    });

    it('negative 2: genuine secret code delivery with "Never share this code" stays clear', () => {
      const text = 'Your secret code for Axis mobile login is 9482. Never share this code on phone or SMS. Bank kabhi otp nahi maangta.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('OTP_REQUEST');
    });

    it('negative 3: transaction OTP alert with "Kisi ke saath share na karein" stays clear', () => {
      const text = 'Transaction alert: OTP 839201 generated for Rs 1,450 purchase at Amazon. Kisi ke saath share na karein.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('OTP_REQUEST');
    });

    // 3 Invented Positive Scam Messages (must trigger OTP_REQUEST)
    it('positive 1: Hinglish SOV grammar with OTP, digits and batayein triggers OTP_REQUEST', () => {
      const text = 'Payment hold: To release your transaction, OTP 392019 hamare call center executive ko batayein.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('OTP_REQUEST');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('positive 2: English request with "tell" and "verification code" triggers OTP_REQUEST', () => {
      const text = 'A suspicious charge occurred on your card. To cancel this order, tell the representative your verification code 491028 immediately.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('OTP_REQUEST');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('positive 3: Gerund form "by sharing the OTP" triggers OTP_REQUEST', () => {
      const text = 'Refund approved: Claim your Rs 2,500 cashback by sharing the OTP sent to your registered mobile number.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('OTP_REQUEST');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Group 1: New Rule SENSITIVE_INFO_REQUEST (weight 3)', () => {
    // 3 Invented Genuine Look-Alike Negatives (must stay score 0)
    it('negative 1: SIM activation confirmation without credential solicitations stays clear', () => {
      const text = 'Telecom Alert: Your new 5G SIM card has been activated successfully on your existing mobile number. Welcome to Airtel.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
    });

    it('negative 2: PAN-Aadhaar linking portal reminder without SMS reply requests stays clear', () => {
      const text = 'Bank Advisory: Link your PAN and Aadhaar on the official income tax portal at incometax.gov.in before the deadline.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
    });

    it('negative 3: e-Aadhaar status confirmation stays clear', () => {
      const text = 'Aadhaar Services: Your e-Aadhaar download request was processed successfully. Ref: AD-92819.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
    });

    // 3 Invented Positive Scam Messages (must trigger SENSITIVE_INFO_REQUEST)
    it('positive 1: demanding 20-digit SIM number via SMS triggers SENSITIVE_INFO_REQUEST', () => {
      const text = 'Mobile network warning: To prevent SIM disconnection, send your 20-digit SIM number and date of birth immediately.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('positive 2: asking user to reply with Aadhaar number triggers SENSITIVE_INFO_REQUEST', () => {
      const text = 'Bank KYC requirement: Reply with your 12-digit Aadhaar number and PAN details to unlock online transactions.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('positive 3: Hinglish asking for card number and Aadhaar via reply karein triggers SENSITIVE_INFO_REQUEST', () => {
      const text = 'Card department: Naya debit card activate karne ke liye apna 16-digit card number aur registered Aadhaar reply karein.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Group 2: New Rule ADVANCE_FEE (weight 3)', () => {
    // 3 Invented Genuine Look-Alike Negatives (must stay score 0)
    it('negative 1: statement notification of annual card fee billed stays clear', () => {
      const text = 'Credit Card Statement: An annual membership fee of Rs 750 has been debited to your card ending in 4018.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
    });

    it('negative 2: courier notice of shipment cleared for delivery stays clear', () => {
      const text = 'Consignment Update: Your shipment #84920 has been cleared for transit and dispatched for local delivery.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
    });

    it('negative 3: admission receipt for charge already paid stays clear', () => {
      const text = 'University Admission: Application submitted successfully. Entrance exam processing fee of Rs 400 was received on 28-Oct.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
    });

    // 3 Invented Positive Scam Messages (must trigger ADVANCE_FEE)
    it('positive 1: loan agreement fee required before disbursal triggers ADVANCE_FEE', () => {
      const text = 'Personal Loan Desk: Pre-approved loan of Rs 5 Lakh ready. One-time agreement fee Rs 1,200 must be cleared before disbursal.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('positive 2: customs duty payment demanded to release parcel triggers ADVANCE_FEE', () => {
      const text = 'Air Cargo Alert: International parcel held at customs. Pay customs duty Rs 3,450 to release shipment immediately.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('positive 3: courier processing fee demanded to activate delivery triggers ADVANCE_FEE', () => {
      const text = 'Courier Clearance: Consignment tracking CR-9201 is on hold. Clear processing fee Rs 650 to activate delivery.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      expect(res.score).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Group 6: New Rule UNSOLICITED_REFUND (weight 2)', () => {
    // 3 Invented Genuine Look-Alike Negatives (must stay score 0)
    it('negative 1: genuine e-commerce return refund processed stays clear', () => {
      const text = 'Flipkart: Refund of Rs 899 for your returned item has been processed to your original payment method. Ref #RT9182.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
    });

    it('negative 2: genuine tax assessment refund already credited stays clear', () => {
      const text = 'Tax Notification: Assessment refund of Rs 4,120 has been directly credited to your pre-validated bank account ending in 8192.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
    });

    it('negative 3: genuine gas subsidy already credited stays clear', () => {
      const text = 'Bharat Gas: DBT subsidy of Rs 275 for cylinder booking Ref #91823 has been credited to your bank account on 24-Oct.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
    });

    // 3 Invented Positive Scam Messages (must trigger UNSOLICITED_REFUND)
    it('positive 1: tax excess refund requiring bank details submission triggers UNSOLICITED_REFUND', () => {
      const text = 'Tax Alert: Excess TDS refund of Rs 14,200 approved. Submit verified bank details for direct credit immediately.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });

    it('positive 2: Hinglish DBT subsidy pending asking to verify and claim triggers UNSOLICITED_REFUND', () => {
      const text = 'Yojana Portal: Aapka DBT gas subsidy Rs 750 pending hai. Bank a/c verify karke claim karein.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });

    it('positive 3: mistaken credit demanding to return excess amount triggers UNSOLICITED_REFUND', () => {
      const text = 'Payment Desk: Rs 15,000 was mistakenly credited to your account. Return the excess amount to avoid legal dispute.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Group 4: Utility Disconnection Threats in FEAR (weight stays 2)', () => {
    // 3 Invented Genuine Look-Alike Negatives (must stay score 0)
    it('negative 1: genuine scheduled maintenance power interruption stays clear', () => {
      const text = 'Tata Power: Scheduled maintenance in Sector 4 on 28-Oct from 10am to 2pm. Power supply will be temporarily interrupted. Inconvenience regretted.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('FEAR');
    });

    it('negative 2: genuine water pipeline repair notice stays clear', () => {
      const text = 'Jal Board: Routine pipeline repair work in progress. Water supply will be resumed by 6 PM today.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('FEAR');
    });

    it('negative 3: genuine network maintenance notice stays clear', () => {
      const text = 'Network Notice: Planned system upgrade scheduled tonight between 1 AM and 4 AM. Services may experience brief downtime.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('FEAR');
    });

    // 3 Invented Positive Scam Messages (must trigger FEAR)
    it('positive 1: Hinglish supply band threat triggers FEAR', () => {
      const text = 'Electricity Alert: Meter connection #94829 has overdue balance. Aaj raat 10 baje supply band kar di jayegi.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('FEAR');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });

    it('positive 2: English power cut threat triggers FEAR', () => {
      const text = 'Utility Notice: Electricity bill unpaid for customer #38192. Power cut tonight unless dues are cleared.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('FEAR');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });

    it('positive 3: Hinglish bijli cut threat triggers FEAR', () => {
      const text = 'Notice: Bill pending for CA 482910. Kal subah bijli cut kar di jayegi.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('FEAR');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Group 5: Extend IMPERSONATION (weight stays 2)', () => {
    // 3 Invented Genuine Look-Alike Negatives (must stay score 0)
    it('negative 1: genuine security alert advisory stays clear', () => {
      const text = 'Security Alert: Never share your password or PIN with anyone. Axis Bank values your security.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
    });

    it('negative 2: genuine IT security patch notice stays clear', () => {
      const text = 'IT Security Notice: Mandatory operating system security patch scheduled for installation tonight. Ref: SEC-2026-91.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
    });

    it('negative 3: genuine police community advisory stays clear', () => {
      const text = 'City Police Advisory: Be cautious of unknown callers offering high-return investment schemes. Report suspicious calls at 1930.';
      const res = analyzeMessage(text);
      expect(res.category).toBe('No known red flags found');
      expect(res.score).toBe(0);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
    });

    // 3 Invented Positive Scam Messages (must trigger IMPERSONATION)
    it('positive 1: fake security dept warning triggers IMPERSONATION', () => {
      const text = 'Security Dept: An unauthorized transaction was flagged on your debit card. Contact officer at desk immediately.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('IMPERSONATION');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });

    it('positive 2: fake cyber crime cell complaint notice triggers IMPERSONATION', () => {
      const text = 'Cyber Crime Cell: A formal cyber harassment complaint has been registered under your mobile number. Contact investigating unit immediately.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('IMPERSONATION');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });

    it('positive 3: fake clearance desk message triggers IMPERSONATION', () => {
      const text = 'Notice: Inbound overseas parcel #91820 is held at cargo. Contact our clearance desk immediately to regularize documents.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).toContain('IMPERSONATION');
      expect(res.score).toBeGreaterThanOrEqual(2);
    });
  });
});
