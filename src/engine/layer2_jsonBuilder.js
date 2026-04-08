import { getMitreMapping, getMitreSummary } from '../utils/mitreMapping.js'
import { getAnalysisPeriod, getUniqueIPs } from './logParser.js'

/**
 * Layer 2 JSON Builder
 * Creates a clean, structured JSON object from all detection output.
 * This is the single input sent to Claude for CERT-In evidence generation.
 *
 * @param {Array} parsedLogs - all parsed log entries
 * @param {Array} layer1Results - signature detection results
 * @param {Array} layer2Results - behavioral + rotation results (combined)
 * @param {object} geoData - { ip: geoData }
 * @returns {object} structured JSON summary
 */
export function buildLayer2Json(parsedLogs, layer1Results, layer2Results, geoData) {
  const allEvents = [...layer1Results, ...layer2Results]
  const { start, end, durationMinutes } = getAnalysisPeriod(parsedLogs)
  const uniqueIPs = getUniqueIPs(parsedLogs)

  // Severity breakdown
  const severityBreakdown = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const event of allEvents) {
    if (severityBreakdown[event.severity] !== undefined) {
      severityBreakdown[event.severity]++
    }
  }

  // Unique affected endpoints
  const endpointSet = new Set()
  for (const event of layer1Results) {
    if (event.path) endpointSet.add(event.path.split('?')[0])
  }
  for (const event of layer2Results) {
    if (event.affectedEndpoint) endpointSet.add(event.affectedEndpoint)
  }

  // Sort all events by timestamp
  const detectedEvents = [...layer1Results]
    .filter(e => e.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    .map(event => {
      const mitre = getMitreMapping(event.type)
      const geo = geoData[event.ip]
      return {
        timestamp: event.timestamp,
        type: event.type,
        severity: event.severity,
        sourceIP: event.ip,
        targetPath: event.path,
        evidence: event.evidence,
        geoInfo: geo ? {
          country: geo.country_name,
          city: geo.city,
          asn: geo.asn,
          proxy: geo.proxy,
          hosting: geo.hosting,
          tor: geo.tor,
        } : null,
        mitreId: mitre.id,
        mitreName: mitre.name,
      }
    })

  // IP rotation summary
  const distributedEvents = layer2Results.filter(e => e.type === 'DISTRIBUTED_ATTACK')
  const maxDiversityEvent = distributedEvents.reduce((max, e) =>
    (!max || e.ipDiversityRate > max.ipDiversityRate) ? e : max, null)

  // ASN clusters from all attacking IPs
  const asnGroups = {}
  const attackingIPs = new Set(layer1Results.map(e => e.ip))
  for (const ip of attackingIPs) {
    const geo = geoData[ip]
    if (!geo?.asn) continue
    if (!asnGroups[geo.asn]) asnGroups[geo.asn] = { asn: geo.asn, org: geo.org || geo.asn, ipCount: 0 }
    asnGroups[geo.asn].ipCount++
  }
  const asnClusters = Object.values(asnGroups)
    .sort((a, b) => b.ipCount - a.ipCount)
    .slice(0, 10)

  // Anonymized IP count
  const anonymizedIPs = [...attackingIPs].filter(ip => {
    const geo = geoData[ip]
    return geo && (geo.proxy || geo.hosting || geo.tor)
  })

  // Geo-velocity anomalies
  const geoVelocityAnomalies = layer2Results
    .filter(e => e.type === 'GEO_VELOCITY_ANOMALY' && e.geoVelocityDetails)
    .map(e => ({
      endpoint: e.affectedEndpoint,
      ...e.geoVelocityDetails,
    }))

  // MITRE summary
  const mitreTechniquesSummary = getMitreSummary(allEvents)

  // Top attacking IPs
  const ipCounts = {}
  for (const entry of parsedLogs) {
    ipCounts[entry.ip] = (ipCounts[entry.ip] || 0) + 1
  }
  const topAttackers = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => {
      const geo = geoData[ip]
      return {
        ip,
        requestCount: count,
        country: geo?.country_name || 'Unknown',
        asn: geo?.asn || '',
        proxy: geo?.proxy || false,
        tor: geo?.tor || false,
      }
    })

  return {
    analysisWindow: { start, end, durationMinutes },
    totalRequestsAnalyzed: parsedLogs.length,
    uniqueSourceIPs: uniqueIPs.length,
    affectedEndpoints: [...endpointSet].slice(0, 20),
    severityBreakdown,
    detectedEvents: detectedEvents.slice(0, 200), // Limit to avoid oversized Claude payload
    topAttackers,
    ipRotationSummary: {
      ipDiversityRate: maxDiversityEvent?.ipDiversityRate || 0,
      affectedEndpoint: maxDiversityEvent?.affectedEndpoint || null,
      uniqueAttackingIPs: attackingIPs.size,
      asnClusters,
      anonymizedIPCount: anonymizedIPs.length,
      anonymizedPercentage: attackingIPs.size > 0
        ? (anonymizedIPs.length / attackingIPs.size) * 100
        : 0,
    },
    geoVelocityAnomalies,
    mitreTechniquesSummary,
  }
}
