/**
 * Invented sample messages for Satark analyzer.
 * All phone numbers, accounts, and domains are fictitious.
 */

export const SAMPLE_MESSAGES = [
  {
    id: 'kyc',
    label: 'KYC scam',
    dotColor: 'bg-red-500',
    category: 'Suspicious',
    text: 'Dear customer, aapka YONO account block ho jayega. Turant kyc update karein aur OTP bhejein: http://sbi-kyc-verify.xyz/update',
    url: 'http://sbi-kyc-verify.xyz/update'
  },
  {
    id: 'job',
    label: 'Job-fee scam',
    dotColor: 'bg-amber-500',
    category: 'Suspicious',
    text: 'Congratulations! Selected for Telegram work from home job. Daily earning Rs 4,500. Pehle registration fee Rs 499 bhejein to start onboarding.',
    url: ''
  },
  {
    id: 'bank',
    label: 'Genuine bank alert',
    dotColor: 'bg-teal-700',
    category: 'No known red flags found',
    text: 'Rs 2,450.00 debited from A/c XX1092 on 28-OCT-26 via UPI Ref 92837192. Do not share OTP with anyone. Bank kabhi OTP nahi maangta.',
    url: ''
  },
  {
    id: 'hindi_kyc',
    label: 'केवाईसी धोखाधड़ी (Hindi)',
    dotColor: 'bg-red-500',
    category: 'Suspicious',
    text: 'भारतीय स्टेट बैंक: आपका खाता आज निलंबित कर दिया जाएगा। तुरंत केवाईसी अपडेट करें और अपना ओटीपी भेजें: http://sbi-kyc-update.xyz',
    url: 'http://sbi-kyc-update.xyz'
  }
];

