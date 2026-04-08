// Known malicious / high-risk ASNs
// These are frequently associated with bulk scanning, botnets, and attack infrastructure
export const MALICIOUS_ASNS = new Set([
  'AS14061',  // DigitalOcean — frequently abused for VPS attacks
  'AS16276',  // OVH — commonly used in botnets
  'AS24940',  // Hetzner — cheap VPS, high abuse rate
  'AS20473',  // Vultr
  'AS9009',   // M247 — often used for anonymous scanning
  'AS62240',  // Clouvider
  'AS204957', // Green Floid — bulletproof hosting
  'AS209588', // Flyservers — known bad actor
  'AS174',    // Cogent — transit, sometimes abused
  'AS3356',   // Level3/Lumen
  'AS4134',   // China Telecom
  'AS4766',   // Korea Telecom
  'AS4837',   // China Unicom
  'AS9808',   // China Mobile
  'AS58461',  // China Telecom
  'AS7922',   // Comcast (large, not malicious, but high volume scanning)
])

// Check if an ASN is in the flagged list
export function isMaliciousAsn(asn) {
  if (!asn) return false
  return MALICIOUS_ASNS.has(asn.toUpperCase().trim())
}

// ASN risk labels
export const ASN_RISK_LABELS = {
  'AS14061': 'VPS Infrastructure (DigitalOcean)',
  'AS16276': 'VPS Infrastructure (OVH)',
  'AS24940': 'VPS Infrastructure (Hetzner)',
  'AS20473': 'VPS Infrastructure (Vultr)',
  'AS9009':  'Anonymous Transit (M247)',
  'AS4134':  'National ISP (China Telecom)',
  'AS4766':  'National ISP (Korea Telecom)',
  'AS4837':  'National ISP (China Unicom)',
  'AS9808':  'National ISP (China Mobile)',
}
