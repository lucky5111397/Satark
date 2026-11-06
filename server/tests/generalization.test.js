import { describe, it, expect } from 'vitest';
import { analyzeMessage } from '../detection/analyzeMessage.js';

describe('Generalization & Paraphrase Regression Suite (server/tests/generalization.test.js)', () => {
  describe('Fix 1: UNSOLICITED_REFUND Within-Sentence Generalization', () => {
    // 5 Paraphrased Positives from Part 0
    it('pos 1: tax overpayment discrepancy audit requesting verified banking profile', () => {
      const text = 'Revenue Assessment Unit: Discrepancy audit shows tax overpayment of Rs 12,400. Submit verified banking profile within 24 hours to receive refund.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
    });

    it('pos 2: domestic subsidy voucher release requesting bank details to claim', () => {
      const text = 'National Gas Corporation: Unclaimed domestic subsidy voucher Rs 920 is waiting for release. Verify bank details to claim.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
    });

    it('pos 3: accidental UPI transfer requesting immediate return of extra money', () => {
      const text = 'Payment Transfer Desk: By mistake I sent Rs 4,500 to your UPI ID instead of my vendor. Please refund the extra money immediately.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
    });

    it('pos 4: housing installment DBT pending requesting account verification to claim', () => {
      const text = 'Pradhan Mantri Awas DBT: Rs 25,000 housing installment pending hai. Account verify karke amount claim karein.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
    });

    it('pos 5: electricity surcharge refund approved requesting savings account verification', () => {
      const text = 'Electricity Bill Relief Cell: Last month extra meter surcharge Rs 850 refund approved. Verify your savings account to get credit.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
    });

    // 5 Genuine Look-Alikes from Part 0 (must NOT trigger UNSOLICITED_REFUND)
    it('gen 1: IRCTC cancelled ticket refund already credited', () => {
      const text = 'IRCTC Refund: Rs 1,420 for cancelled PNR 2819401829 has been refunded to your original payment mode on 29-Oct.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 2: Flipkart return refund processed notification', () => {
      const text = 'Flipkart: Refund of Rs 899 for returned item has been processed and will reflect in your account within 2 business days.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 3: Indian Oil LPG cylinder subsidy transferred to registered bank', () => {
      const text = 'Indian Oil Indane: Cylinder subsidy of Rs 280 for booking #84910 has been transferred to your registered bank a/c.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 4: Income tax official refund notification does not trigger UNSOLICITED_REFUND', () => {
      const text = 'Income Tax Department: Refund of Rs 4,320 for AY 2025-26 has been credited via direct deposit to account ending XX4910.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
    });

    it('gen 5: Swiggy wallet refund notification', () => {
      const text = 'Swiggy Support: Order #SW-8910 cancelled by restaurant. Rs 340 refund credited to Swiggy Money wallet balance.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
      expect(res.category).toBe('No known red flags found');
    });
  });

  describe('Fix 2: ADVANCE_FEE Precondition Generalization', () => {
    // 5 Paraphrased Positives from Part 0
    it('pos 1: statutory documentation charge demanded before loan disbursement', () => {
      const text = 'Federal Finance Ltd: Pre-approved small business credit facility of Rs 3,50,000 sanctioned. Deposit statutory documentation charge Rs 1,450 to proceed with fund disbursement.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
    });

    it('pos 2: transit insurance release fee for held parcel', () => {
      const text = 'Gateway Air Freight: Inbound overseas parcel #PK-7821 is held at international cargo terminal. Pay transit insurance release fee Rs 1,200 to dispatch.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
    });

    it('pos 3: agreement stamp fee required to release credit line', () => {
      const text = 'SmartCredit Seva: Aapka instant collateral-free loan Rs 80,000 approve hua. Agreement stamp fee Rs 490 jama karein to release your credit line.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
    });

    it('pos 4: customs tariff payment required before handover', () => {
      const text = 'Express Logistics Hub: Shipment AW8901 requires customs tariff payment of Rs 950 before package handover can be completed.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
    });

    it('pos 5: file processing charge required for loan disbursal', () => {
      const text = 'Gramin Vikas Finance: Aapka tractor subsidy loan approve ho gaya. Disbursal lene ke liye file processing charge Rs 750 jama karein.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
    });

    // 5 Genuine Look-Alikes from Part 0 (must NOT trigger ADVANCE_FEE)
    it('gen 1: bank locker maintenance charge already deducted', () => {
      const text = 'HDFC Bank Alert: Monthly locker maintenance charge Rs 1,500 plus GST has been deducted from your savings account XX4819.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 2: debit card annual fee already debited', () => {
      const text = 'Canara Bank: Annual debit card maintenance fee of Rs 250 has been debited from your A/c XX9102. Ref: ACM/82910.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 3: courier delivery invoice available', () => {
      const text = 'Blue Dart: Shipment BD48102 delivered successfully. Official invoice and freight receipt available at bluedart.com.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 4: home loan annual fee summary available for download', () => {
      const text = 'SBI Home Loan: Interest certificate and annual processing summary for financial year 2025-26 is ready for download on net banking.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 5: utility security deposit credited to ledger', () => {
      const text = 'Delhi Electricity Board: Security deposit of Rs 1,200 has been credited to your consumer ledger upon meter upgrade.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
    });
  });

  describe('Fix 3: JOB_FEE Context Requirement & Completed Deposit Guard', () => {
    it('genuine utility security deposit credit must NOT trigger JOB_FEE', () => {
      const text = 'Delhi Electricity Board: Security deposit of Rs 1,200 has been credited to your consumer ledger upon meter upgrade.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('JOB_FEE');
      expect(res.category).toBe('No known red flags found');
    });

    it('genuine rental security deposit receipt does not trigger JOB_FEE', () => {
      const text = 'Housing Society: Security deposit of Rs 25,000 was received and credited to maintenance escrow account.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('JOB_FEE');
      expect(res.category).toBe('No known red flags found');
    });

    it('scam demanding security deposit for employment still triggers JOB_FEE', () => {
      const text = 'Online Typing Jobs: Earn Rs 2,000 daily. Pay refundable security deposit Rs 499 to activate your account.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('JOB_FEE');
    });
  });

  describe('Fix 4: SENSITIVE_INFO_REQUEST Negation Guards for Aadhaar and PAN', () => {
    // 5 Paraphrased Positives from Part 0
    it('pos 1: SIM porting cancellation requesting SIM serial and Aadhaar', () => {
      const text = 'Telecom Service Desk: Porting request initiated. To cancel cancellation, reply with your 20-digit SIM serial and Aadhaar card.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
    });

    it('pos 2: BSNL verification requesting PAN number by reply', () => {
      const text = 'BSNL Customer Verification: Submit your PAN number and date of birth by SMS reply to prevent mobile connection disconnection.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
    });

    it('pos 3: Card activation requesting 16-digit debit card number', () => {
      const text = 'Card Activation Support: For enabling contactless payments, send your 16-digit debit card number and expiry year.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
    });

    it('pos 4: 5G upgrade verification requesting SIM number and Aadhaar via reply', () => {
      const text = 'Vodafone Idea Desk: 5G upgrade verification pending. Apna SIM number aur registered Aadhaar number is message pe reply karein.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
    });

    it('pos 5: Security update requesting 12-digit Aadhaar number', () => {
      const text = 'Bank Verification Unit: Security update required. Provide your 12-digit Aadhaar number and registered mobile number to continue service.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
    });

    // 5 Genuine Look-Alikes from Part 0
    it('gen 1: branch in-person PAN submission does not trigger SENSITIVE_INFO_REQUEST', () => {
      const text = 'Axis Bank: Your physical PAN document copy is required for account re-KYC. Please visit your nearest branch with original identity proofs.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 2: bank security advisory explicitly saying never share Aadhaar or PAN stays clear', () => {
      const text = 'SBI Advisory: Never share your Aadhaar number, PAN details, or card credentials with unknown callers. SBI never requests private data via SMS.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 3: biometric authentication notification does not trigger SENSITIVE_INFO_REQUEST', () => {
      const text = 'UIDAI: Aadhaar authentication was successful for biometric verification at E-Seva Kendra counter on 30-Oct.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 4: telecom e-bill password convention does not trigger SENSITIVE_INFO_REQUEST', () => {
      const text = 'Airtel: Your e-bill for billing cycle Oct 2026 is generated. Password to open the PDF statement is your first 4 letters followed by birth year.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
      expect(res.category).toBe('No known red flags found');
    });

    it('gen 5: policy premium receipt does not trigger SENSITIVE_INFO_REQUEST', () => {
      const text = 'HDFC Life: Policy premium receipt for policy ending XX8491 generated. Official summary available.';
      const res = analyzeMessage(text);
      expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
      expect(res.category).toBe('No known red flags found');
    });

    it('adversarial check: message with negation guard in sentence 1 but real data demand in sentence 2 MUST STILL BE FLAGGED', () => {
      const text = 'Security tip: Never share your net banking password. Nayi SIM activate karne ke liye apna 20-digit SIM number aur Aadhaar number reply karein.';
      const res = analyzeMessage(text);
      expect(['Caution', 'Suspicious']).toContain(res.category);
      expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
    });
  });

  describe('Fresh Paraphrase Validation Suite (Completely New Phrasing & Brands)', () => {
    describe('Rule 1: UNSOLICITED_REFUND (Fresh Set)', () => {
      it('pos 1: portal notification excess road tax update profile to claim refund', () => {
        const text = 'Portal Notification: Excess road tax of Rs 2,400 identified. Update your banking profile to claim your refund.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      });

      it('pos 2: PM Kisan Yojna installment pending confirm bank details', () => {
        const text = 'PM Kisan Yojna: Aapki 18th installment transfer pending hai. Subsidy pane ke liye bank details confirm karein.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      });

      it('pos 3: payment alert accidental transfer refund extra money', () => {
        const text = 'Payment Alert: Galti se Rs 4,500 aapke UPI account me transfer ho gaya. Please refund the extra money immediately.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      });

      it('pos 4: electricity bill overpayment rebate submit bank details to claim', () => {
        const text = 'Electricity Bill Audit: Overpayment rebate of Rs 850 ready. Submit bank details to claim.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      });

      it('pos 5: merchant services extra charge reversed confirm bank account to receive', () => {
        const text = 'Merchant Services: Rs 1,120 extra charge reversed. Confirm bank account details to receive refund.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('UNSOLICITED_REFUND');
      });

      it('gen 1: IRCTC cancelled PNR refund credited', () => {
        const text = 'IRCTC Refund: Rs 780 for cancelled PNR 28491024 has been credited to your original payment method.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 2: Amazon India return refund processed notification', () => {
        const text = 'Amazon India: Refund of Rs 1,299 for returned item has been processed and will reflect in your account within 3-5 days.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 3: Bharat Petroleum LPG subsidy credited to registered bank', () => {
        const text = 'Bharat Petroleum: LPG subsidy Rs 240.50 credited in your registered bank account for cylinder refilled on 28-Oct.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 4: Tata Power overpayment adjustment credited to consumer ledger', () => {
        const text = 'Tata Power: Overpayment adjustment of Rs 310 credited to your consumer ledger. Your net payable is Rs 0.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 5: Zomato wallet refund credited notification', () => {
        const text = 'Zomato: Refund of Rs 340 for missing food items has been credited to your Zomato Money wallet.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('UNSOLICITED_REFUND');
        expect(res.category).toBe('No known red flags found');
      });
    });

    describe('Rule 2: ADVANCE_FEE (Fresh Set)', () => {
      it('pos 1: container clearance fee required to release consignment', () => {
        const text = 'Global Cargo: Held container #GC9918 requires statutory clearance fee Rs 1,800 to release consignment.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      });

      it('pos 2: business loan documentation charge pay karein to release disbursal', () => {
        const text = 'FastLoan Seva: Pre-approved business loan Rs 5,00,000 ready. Documentation charge Rs 1,200 pay karein to release disbursal.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      });

      it('pos 3: handling duty required before delivery dispatch', () => {
        const text = 'FedEx Logistics: Airway bill 81920 held at airport hub. Pay handling duty Rs 650 before delivery dispatch.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      });

      it('pos 4: agreement stamp charge jama karein to take loan disbursal', () => {
        const text = 'Pradhan Mantri Mudra Loan: Aapka loan pass ho gaya. Disbursal lene ke liye agreement stamp charge Rs 990 jama karein.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      });

      it('pos 5: transit insurance charge must be cleared before parcel handover', () => {
        const text = 'SpeedPost International: Transit insurance charge Rs 420 must be cleared before parcel handover.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('ADVANCE_FEE');
      });

      it('gen 1: ICICI locker fee debited from savings account', () => {
        const text = 'ICICI Bank: Annual locker maintenance fee Rs 2,000 plus GST has been debited from your savings account XX1029.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 2: SBI debit card maintenance deducted', () => {
        const text = 'State Bank of India: Debit card annual maintenance charge Rs 177 has been deducted from your account XX5512.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 3: DHL delivered package invoice available for download', () => {
        const text = 'DHL Express: Package DH82910 delivered. Official tax receipt and invoice is available for download at dhl.com.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 4: PNB housing loan documentation statement ready for download', () => {
        const text = 'Punjab National Bank: Housing loan documentation statement and interest certificate ready for download.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 5: Adani Gas security deposit credited to billing account', () => {
        const text = 'Adani Gas: Security deposit adjustment of Rs 500 has been credited to your piped natural gas billing account.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('ADVANCE_FEE');
        expect(res.category).toBe('No known red flags found');
      });
    });

    describe('Rule 3: JOB_FEE (Fresh Set)', () => {
      it('pos 1: data entry job pay refundable security deposit to receive assignment', () => {
        const text = 'Work From Home Opportunity: Part-time data entry job. Pay refundable security deposit Rs 600 to receive assignment.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('JOB_FEE');
      });

      it('pos 2: typing tasks registration fee to begin', () => {
        const text = 'Typing Task India: Earn Rs 1,500 daily typing documents. Pehle registration fee 299 jama karein to begin.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('JOB_FEE');
      });

      it('pos 3: YouTube video review joining fee required before portal login', () => {
        const text = 'YouTube Video Reviewer: Daily earning Rs 2,500. Joining fee Rs 499 required before portal login is issued.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('JOB_FEE');
      });

      it('pos 4: proofreading deposit security deposit to activate employee ID', () => {
        const text = 'Freelance Proofreading: Guaranteed work from home. Deposit security deposit Rs 750 to activate employee ID.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('JOB_FEE');
      });

      it('pos 5: online survey jobs pehle paise bhejein for kit dispatch', () => {
        const text = 'Online Survey Jobs: High daily payout. Pehle paise bhejein Rs 350 for kit dispatch.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('JOB_FEE');
      });

      it('gen 1: electricity meter security deposit credited to consumer account', () => {
        const text = 'Torrent Power: Meter security deposit of Rs 1,500 has been credited to your consumer account.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('JOB_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 2: rental security deposit received and credited to maintenance account', () => {
        const text = 'Apartment Residents Welfare: Rental security deposit Rs 30,000 was received and credited to society maintenance account.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('JOB_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 3: genuine corporate onboarding schedule emailed', () => {
        const text = 'Infosys HR: Welcome to the team! Your onboarding schedule and employee portal login details have been emailed.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('JOB_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 4: genuine interview schedule notice', () => {
        const text = 'TCS Careers: Your interview for System Engineer is scheduled on Friday at 11 AM via Microsoft Teams.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('JOB_FEE');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 5: broadband modem security deposit credited to final settlement', () => {
        const text = 'BSNL Broadband: Refundable security deposit for FTTH modem credited to final settlement statement.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('JOB_FEE');
        expect(res.category).toBe('No known red flags found');
      });
    });

    describe('Rule 4: SENSITIVE_INFO_REQUEST (Fresh Set)', () => {
      it('pos 1: SIM swap reply with 20-digit SIM serial and Aadhaar', () => {
        const text = 'Telecom Service Desk: SIM swap initiated. If you did not request this, reply with your 20-digit SIM serial and Aadhaar card.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      });

      it('pos 2: prepaid line verification provide 12-digit Aadhaar number', () => {
        const text = 'Airtel Customer Unit: Verification pending for active prepaid line. Provide your 12-digit Aadhaar number and registered mobile.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      });

      it('pos 3: bank card operations reply with 16-digit debit card number', () => {
        const text = 'Bank Card Operations: To activate international transactions on your card, reply with 16-digit debit card number.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      });

      it('pos 4: SIM re-verification apna PAN card number SMS reply karein', () => {
        const text = 'Mobile Service Center: SIM mandatory re-verification. Apna PAN card number aur date of birth SMS reply karein.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      });

      it('pos 5: identity registry send Aadhaar number by reply', () => {
        const text = 'National Identity Registry: Update your record. Send your Aadhaar number and registered address by reply.';
        const res = analyzeMessage(text);
        expect(['Caution', 'Suspicious']).toContain(res.category);
        expect(res.indicators.map(i => i.ruleId)).toContain('SENSITIVE_INFO_REQUEST');
      });

      it('gen 1: HDFC Bank advisory never share Aadhaar or PAN details', () => {
        const text = 'HDFC Bank Security Advisory: Never share your Aadhaar number, PAN details, or card credentials with anyone. Bank staff will never ask for them.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 2: PNB alert do not disclose PAN card number over SMS', () => {
        const text = 'Punjab National Bank Alert: Do not disclose your PAN card number or banking credentials over the phone or SMS.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 3: Canara Bank bank kabhi bhi aapka Aadhaar number nahi maangta', () => {
        const text = 'Canara Bank: Bank kabhi bhi aapka Aadhaar number ya PAN card details SMS pe nahi maangta. Satark rahein.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 4: UIDAI Aadhaar authentication successful notification', () => {
        const text = 'UIDAI Notification: Your Aadhaar authentication was successful for telecom e-KYC on 30-Oct-2026.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 5: Axis Bank tax re-KYC visit home branch with original physical PAN', () => {
        const text = 'Axis Bank: For tax re-KYC, please visit your home branch with original physical PAN document. Do not send via SMS.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('SENSITIVE_INFO_REQUEST');
        expect(res.category).toBe('No known red flags found');
      });
    });

    describe('Rule 5: IMPERSONATION Context-Only Evaluation (Fresh Set)', () => {
      it('gen 1: genuine Income Tax Department return processed stays clear', () => {
        const text = 'Income Tax Department: Your revised return for AY 2025-26 has been processed successfully. Summary available on e-filing portal.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 2: genuine courier company package arrival notification stays clear', () => {
        const text = 'Blue Dart Courier Company: Your package has arrived at the local facility and will be out for delivery tomorrow.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 3: genuine bank manager locker renewal approval stays clear', () => {
        const text = 'State Bank of India: Your bank manager Sharma has approved your locker access renewal request.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 4: genuine Cyber Crime Cell advisory stays clear', () => {
        const text = 'Cyber Crime Cell Advisory: Beware of unknown investment calls. Call 1930 to report suspicious cyber activities.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
        expect(res.category).toBe('No known red flags found');
      });

      it('gen 5: genuine TRAI advisory stays clear', () => {
        const text = 'TRAI Public Advisory: Telecom service providers do not disconnect numbers without prior written notices.';
        const res = analyzeMessage(text);
        expect(res.indicators.map(i => i.ruleId)).not.toContain('IMPERSONATION');
        expect(res.category).toBe('No known red flags found');
      });
    });
  });
});
