// In-memory geolocation cache — Map<ip, geoData>
// Deliberately NOT using sessionStorage to avoid stale cache issues between analyses
const geoCache = new Map()

/**
 * Get cached geo data for an IP
 * @param {string} ip
 * @returns {object|null}
 */
export function getCachedGeo(ip) {
  return geoCache.get(ip) || null
}

/**
 * Set geo data for an IP in cache
 * @param {string} ip
 * @param {object} data
 */
export function setCachedGeo(ip, data) {
  geoCache.set(ip, data)
}

/**
 * Check if an IP has cached geo data
 * @param {string} ip
 * @returns {boolean}
 */
export function hasCachedGeo(ip) {
  return geoCache.has(ip)
}

/**
 * Get all cached geo data as a plain object
 * @returns {object}
 */
export function getAllCachedGeo() {
  const result = {}
  geoCache.forEach((val, key) => {
    result[key] = val
  })
  return result
}

/**
 * Clear the entire cache (called on reset)
 */
export function clearGeoCache() {
  geoCache.clear()
}

/**
 * Get current cache size
 * @returns {number}
 */
export function getGeoCacheSize() {
  return geoCache.size
}
