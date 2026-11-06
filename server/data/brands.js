/**
 * Brand identifiers and official-domain whitelist.
 * 
 * Source: docs/rules_spec.md Section 6.3
 * If a URL contains a monitored brand name but does NOT resolve to an official domain,
 * it is flagged as `brand_lookalike`.
 */

export const OFFICIAL_DOMAINS = [
  'sbi.co.in',
  'onlinesbi.sbi',
  'hdfcbank.com',
  'icicibank.com',
  'paytm.com',
  'rbi.org.in',
  'npci.org.in',
  'incometax.gov.in',
  'uidai.gov.in'
];

export const MONITORED_BRANDS = [
  'sbi',
  'onlinesbi',
  'hdfc',
  'icici',
  'paytm',
  'rbi',
  'npci',
  'uidai',
  'yono'
];

