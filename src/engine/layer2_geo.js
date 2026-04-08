import { getCachedGeo, setCachedGeo, hasCachedGeo } from '../utils/geoCache.js'

const GEO_LIMIT = 900 // ipapi.co free tier is 1000/day, cap at 900
const BATCH_SIZE = 10 // 10 parallel requests at a time

/**
 * Fetch geo data for a single IP
 * Primary: ipapi.co, Fallback: ip-api.com
 */
async function fetchGeoForIP(ip) {
  // Primary: ipapi.co
  try {
    const res = await fetch(`https://ipapi.co/${ip}/json/`, {
      headers: { 'Accept': 'application/json' },
    })
    if (res.ok) {
      const data = await res.json()
      if (!data.error) {
        return {
          ip,
          country_name: data.country_name || 'Unknown',
          city: data.city || 'Unknown',
          latitude: data.latitude || null,
          longitude: data.longitude || null,
          org: data.org || '',
          asn: data.asn || '',
          proxy: data.proxy || false,
          hosting: data.hosting || false,
          tor: data.tor || false,
        }
      }
    }
  } catch {
    // Fall through to fallback
  }

  // Fallback: ip-api.com
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon,org,as,proxy,hosting`)
    if (res.ok) {
      const data = await res.json()
      if (data.status === 'success') {
        // Extract ASN from "AS12345 SomeName" format
        const asnMatch = (data.as || '').match(/^(AS\d+)/)
        return {
          ip,
          country_name: data.country || 'Unknown',
          city: data.city || 'Unknown',
          latitude: data.lat || null,
          longitude: data.lon || null,
          org: data.org || data.as || '',
          asn: asnMatch ? asnMatch[1] : '',
          proxy: data.proxy || false,
          hosting: data.hosting || false,
          tor: false,
        }
      }
    }
  } catch {
    // Both failed
  }

  // Return null placeholder if both APIs failed
  return {
    ip,
    country_name: 'Unknown',
    city: 'Unknown',
    latitude: null,
    longitude: null,
    org: '',
    asn: '',
    proxy: false,
    hosting: false,
    tor: false,
  }
}

/**
 * Layer 2 Phase 2 — Geo Enrichment
 * Fetches geo data for unique IPs in batches of 10 parallel requests.
 *
 * @param {string[]} uniqueIPs - all unique IP addresses found in logs
 * @param {Function} onProgress - callback(current, total) for progress updates
 * @param {boolean} useMockData - if true, skip API calls (Demo Mode)
 * @param {object} mockGeoData - { ip: geoData } for demo mode
 * @returns {object} geoData map { ip: geoData }
 */
export async function enrichGeoData(uniqueIPs, onProgress, useMockData = false, mockGeoData = {}) {
  const result = {}
  let limited = false

  // If demo mode, use mock data directly
  if (useMockData) {
    for (const ip of uniqueIPs) {
      if (mockGeoData[ip]) {
        setCachedGeo(ip, mockGeoData[ip])
        result[ip] = mockGeoData[ip]
      }
    }
    if (onProgress) onProgress(uniqueIPs.length, uniqueIPs.length)
    return { geoData: result, limited: false }
  }

  // Filter to IPs not yet cached
  const toFetch = uniqueIPs.filter(ip => !hasCachedGeo(ip))

  // Apply rate limit cap
  let ipsToProcess = toFetch
  if (toFetch.length > GEO_LIMIT) {
    ipsToProcess = toFetch.slice(0, GEO_LIMIT)
    limited = true
  }

  // Load already-cached IPs into result
  for (const ip of uniqueIPs) {
    if (hasCachedGeo(ip)) {
      result[ip] = getCachedGeo(ip)
    }
  }

  // Batch fetch: 10 parallel requests at a time
  let completed = 0
  for (let i = 0; i < ipsToProcess.length; i += BATCH_SIZE) {
    const batch = ipsToProcess.slice(i, i + BATCH_SIZE)
    const batchResults = await Promise.all(batch.map(fetchGeoForIP))

    for (const geoData of batchResults) {
      setCachedGeo(geoData.ip, geoData)
      result[geoData.ip] = geoData
    }

    completed += batch.length
    if (onProgress) {
      onProgress(completed + (uniqueIPs.length - toFetch.length), uniqueIPs.length)
    }
  }

  return { geoData: result, limited }
}
