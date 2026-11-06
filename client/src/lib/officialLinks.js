/**
 * Official civic links allowlist and verification.
 * 
 * Rules:
 * - Only approved official government portals are allowed.
 * - Rejects non-HTTPS schemes, subdomains, lookalikes, or arbitrary URLs.
 */

export const HELPLINE_1930_TEL = 'tel:1930';

export const ALLOWED_OFFICIAL_URLS = new Set([
  'https://cybercrime.gov.in',
  'https://sancharsaathi.gov.in/sfc'
]);

export function isOfficialLink(url) {
  if (typeof url !== 'string' || !url) return false;
  return ALLOWED_OFFICIAL_URLS.has(url.trim());
}

export function getOfficialLinks() {
  return [
    {
      title: 'National Cyber Crime Reporting Portal (Helpline 1930)',
      url: 'https://cybercrime.gov.in',
      description: 'Report financial cyber fraud immediately to freeze illicit account transactions.'
    },
    {
      title: 'Chakshu • Sanchar Saathi (DoT)',
      url: 'https://sancharsaathi.gov.in/sfc',
      description: 'Report suspected fraudulent SMS headers, WhatsApp spam, or calling numbers.'
    }
  ];
}

