/**
 * Layer 2 Phase 3 — IP Rotation Detection (Post-Geo)
 * Runs after all geo data is fetched.
 * Scenarios: A=ASN brute force, B=coordinated anonymized, C=geo-velocity anomaly
 */

/**
 * Haversine formula — distance in km between two lat/lon points
 * IMPORTANT: uses radians, not degrees
 */
export function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371 // Earth radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180
  const dLon = (lon2 - lon1) * Math.PI / 180
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) ** 2
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
}

/**
 * Get a human-friendly city + country label from geo data
 */
function geoLabel(geoData) {
  if (!geoData) return 'Unknown Location'
  const city = geoData.city !== 'Unknown' ? geoData.city : ''
  const country = geoData.country_name !== 'Unknown' ? geoData.country_name : ''
  return [city, country].filter(Boolean).join(', ') || 'Unknown Location'
}

/**
 * Get endpoint (strip query params)
 */
function getEndpoint(path) {
  return path.split('?')[0]
}

/**
 * Run Layer 2 Phase 3 — IP Rotation Detection
 * @param {Array} layer1Results
 * @param {Array} layer2BehavioralResults
 * @param {object} geoData - { ip: geoData } from enrichGeoData
 * @returns {Array} rotation events
 */
export function runLayer2Rotation(layer1Results, layer2BehavioralResults, geoData) {
  const events = []
  const allLayerEvents = [...layer1Results, ...layer2BehavioralResults]

  // Build a map: endpoint → [IPs that attacked it]
  const endpointAttackers = {}
  for (const event of layer1Results) {
    const ep = getEndpoint(event.path || '')
    if (!ep) continue
    if (!endpointAttackers[ep]) endpointAttackers[ep] = new Set()
    endpointAttackers[ep].add(event.ip)
  }
  // Also include behavioral events
  for (const event of layer2BehavioralResults) {
    if (!event.affectedEndpoint || !event.involvedIPs) continue
    const ep = getEndpoint(event.affectedEndpoint)
    if (!endpointAttackers[ep]) endpointAttackers[ep] = new Set()
    event.involvedIPs.forEach(ip => endpointAttackers[ep].add(ip))
  }

  // ──────────────────────────────────────────────
  // SCENARIO A: ASN-Level Brute Force
  // 5+ different IPs from same ASN targeting same endpoint
  // ──────────────────────────────────────────────
  for (const [endpoint, attackers] of Object.entries(endpointAttackers)) {
    // Group attackers by ASN
    const asnGroups = {}
    for (const ip of attackers) {
      const geo = geoData[ip]
      const asn = geo?.asn || 'UNKNOWN'
      const org = geo?.org || asn
      if (!asnGroups[asn]) asnGroups[asn] = { org, ips: [] }
      asnGroups[asn].ips.push(ip)
    }

    for (const [asn, data] of Object.entries(asnGroups)) {
      if (asn === 'UNKNOWN') continue
      if (data.ips.length >= 5) {
        events.push({
          type: 'ASN_LEVEL_BRUTE_FORCE',
          severity: 'HIGH',
          affectedEndpoint: endpoint,
          involvedIPs: data.ips,
          asnName: data.org,
          asn,
          evidence: `${data.ips.length} unique IPs from ${data.org} (${asn}) targeting ${endpoint} — coordinated ASN-level attack`,
        })
      }
    }
  }

  // ──────────────────────────────────────────────
  // SCENARIO B: Coordinated Anonymized Attack
  // >60% of attacking IPs are proxy/hosting/tor
  // ──────────────────────────────────────────────
  for (const [endpoint, attackers] of Object.entries(endpointAttackers)) {
    const attackerList = [...attackers]
    if (attackerList.length < 5) continue

    const anonymized = attackerList.filter(ip => {
      const geo = geoData[ip]
      return geo && (geo.proxy || geo.hosting || geo.tor)
    })

    const pct = anonymized.length / attackerList.length
    if (pct > 0.6) {
      events.push({
        type: 'COORDINATED_ANONYMIZED_ATTACK',
        severity: 'CRITICAL',
        affectedEndpoint: endpoint,
        involvedIPs: attackerList,
        anonymizedIPs: anonymized,
        anonymizedPercentage: pct,
        evidence: `${(pct * 100).toFixed(1)}% of attacking IPs on ${endpoint} are anonymized (proxy/hosting/Tor) — ${anonymized.length}/${attackerList.length} IPs. Coordinated multi-hop proxy attack.`,
      })
    }
  }

  // ──────────────────────────────────────────────
  // SCENARIO C: Geo-Velocity Anomaly ⭐
  // Two consecutive requests to same endpoint from physically impossible travel distance
  // Speed > 300 km/s (faster than any physical transport)
  // ──────────────────────────────────────────────
  const GEO_VELOCITY_THRESHOLD = 300 // km/s — faster than this is physically impossible

  for (const [endpoint, attackers] of Object.entries(endpointAttackers)) {
    // Get all events on this endpoint, sorted by time
    const endpointEvents = layer1Results
      .filter(e => getEndpoint(e.path || '') === endpoint)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

    if (endpointEvents.length < 2) continue

    for (let i = 1; i < endpointEvents.length; i++) {
      const prev = endpointEvents[i - 1]
      const curr = endpointEvents[i]

      if (prev.ip === curr.ip) continue // Same IP, not interesting

      const geo1 = geoData[prev.ip]
      const geo2 = geoData[curr.ip]

      if (!geo1?.latitude || !geo1?.longitude || !geo2?.latitude || !geo2?.longitude) continue

      const distKm = haversineDistance(geo1.latitude, geo1.longitude, geo2.latitude, geo2.longitude)
      if (distKm < 100) continue // Not far enough apart to be interesting

      const timeDeltaMs = new Date(curr.timestamp) - new Date(prev.timestamp)
      const timeDeltaSeconds = timeDeltaMs / 1000

      if (timeDeltaSeconds <= 0) continue

      const speedKmPerSecond = distKm / timeDeltaSeconds

      if (speedKmPerSecond > GEO_VELOCITY_THRESHOLD) {
        const label1 = geoLabel(geo1)
        const label2 = geoLabel(geo2)

        events.push({
          type: 'GEO_VELOCITY_ANOMALY',
          severity: 'CRITICAL',
          affectedEndpoint: endpoint,
          involvedIPs: [prev.ip, curr.ip],
          geoVelocityDetails: {
            ip1: prev.ip,
            location1: { label: label1, lat: geo1.latitude, lon: geo1.longitude, timestamp: prev.timestamp },
            ip2: curr.ip,
            location2: { label: label2, lat: geo2.latitude, lon: geo2.longitude, timestamp: curr.timestamp },
            distanceKm: Math.round(distKm),
            timeDeltaSeconds: Math.round(timeDeltaSeconds),
            speedKmPerSecond: Math.round(speedKmPerSecond),
            humanReadable: `${label1} → ${label2} in ${Math.round(timeDeltaSeconds)}s — physically impossible single user`,
          },
          evidence: `${label1} → ${label2} in ${Math.round(timeDeltaSeconds)}s (${Math.round(distKm).toLocaleString()} km at ${Math.round(speedKmPerSecond).toLocaleString()} km/s) — physically impossible`,
        })

        // Only report the first anomaly per endpoint to avoid spam
        break
      }
    }
  }

  return events
}

/**
 * Extract all geo-velocity anomaly details for the map arcs
 * @param {Array} rotationEvents
 * @returns {Array}
 */
export function getGeoVelocityArcs(rotationEvents) {
  return rotationEvents
    .filter(e => e.type === 'GEO_VELOCITY_ANOMALY' && e.geoVelocityDetails)
    .map(e => e.geoVelocityDetails)
}
