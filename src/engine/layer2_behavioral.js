/**
 * Layer 2 Phase 1 — Pure Behavioral Analysis
 * All checks are synchronous (no API calls).
 * Runs on the full parsed log dataset.
 */

/**
 * Helper: group entries by IP
 */
function groupByIP(entries) {
  const groups = {}
  for (const entry of entries) {
    if (!groups[entry.ip]) groups[entry.ip] = []
    groups[entry.ip].push(entry)
  }
  return groups
}

/**
 * Helper: group entries by endpoint (path without query string)
 */
function getEndpoint(path) {
  return path.split('?')[0]
}

/**
 * Helper: get 1-minute bucket key from timestamp
 */
function getMinuteBucket(timestamp) {
  const d = new Date(timestamp)
  return `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${d.getUTCMinutes()}`
}

/**
 * Helper: get 5-minute bucket key
 */
function get5MinBucket(timestamp) {
  const d = new Date(timestamp)
  const fiveMinBlock = Math.floor(d.getUTCMinutes() / 5)
  return `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${fiveMinBlock}`
}

/**
 * Helper: get 1-second bucket key
 */
function getSecondBucket(timestamp) {
  const d = new Date(timestamp)
  return `${Math.floor(d.getTime() / 1000)}`
}

/**
 * Check if IPs form an arithmetic sequence (e.g. x.x.1.1, x.x.1.2, x.x.1.3)
 */
function detectSequentialIPs(ips) {
  // Convert IPs to numbers, look for arithmetic sequences of 5+
  const ipNums = ips
    .map(ip => {
      const parts = ip.split('.').map(Number)
      if (parts.length !== 4 || parts.some(isNaN)) return null
      return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    })
    .filter(n => n !== null)
    .sort((a, b) => a - b)

  const sequences = []
  let seqStart = 0

  for (let i = 1; i < ipNums.length; i++) {
    if (ipNums[i] - ipNums[i - 1] === 1) {
      if (i - seqStart >= 4) {
        sequences.push({ start: ipNums[seqStart], end: ipNums[i], length: i - seqStart + 1 })
      }
    } else {
      seqStart = i
    }
  }

  return sequences
}

/**
 * Run Layer 2 Phase 1 — Behavioral Analysis
 * @param {Array} parsedLogs - all parsed log entries
 * @param {Array} layer1Results - results from Layer 1
 * @returns {Array} behavioral events
 */
export function runLayer2Behavioral(parsedLogs, layer1Results) {
  const events = []
  if (!parsedLogs.length) return events

  const byIP = groupByIP(parsedLogs)
  const allIPs = Object.keys(byIP)

  // ──────────────────────────────────────────────
  // CHECK 1: Per-IP Request Volume
  // ──────────────────────────────────────────────
  for (const [ip, entries] of Object.entries(byIP)) {
    const count = entries.length
    let severity = null
    if (count >= 1000) severity = 'CRITICAL'
    else if (count >= 500) severity = 'HIGH'
    else if (count >= 100) severity = 'MEDIUM'

    if (severity) {
      events.push({
        type: 'HIGH_VOLUME_SOURCE',
        severity,
        affectedEndpoint: null,
        involvedIPs: [ip],
        evidence: `IP ${ip} made ${count.toLocaleString()} requests — excessive volume indicates automated activity`,
        requestCount: count,
      })
    }
  }

  // ──────────────────────────────────────────────
  // CHECK 2: IP Diversity Rate per Endpoint (5-min sliding window)
  // ──────────────────────────────────────────────
  // Build map: endpoint → { bucket → Set<IPs> }
  const endpointBuckets = {}
  for (const entry of parsedLogs) {
    const endpoint = getEndpoint(entry.path)
    const bucket = get5MinBucket(entry.timestamp)
    if (!endpointBuckets[endpoint]) endpointBuckets[endpoint] = {}
    if (!endpointBuckets[endpoint][bucket]) endpointBuckets[endpoint][bucket] = { ips: new Set(), total: 0 }
    endpointBuckets[endpoint][bucket].ips.add(entry.ip)
    endpointBuckets[endpoint][bucket].total++
  }

  for (const [endpoint, buckets] of Object.entries(endpointBuckets)) {
    for (const [bucket, data] of Object.entries(buckets)) {
      if (data.total < 10) continue // Not enough traffic
      const rate = data.ips.size / data.total
      if (rate > 0.8) {
        events.push({
          type: 'DISTRIBUTED_ATTACK',
          severity: 'HIGH',
          affectedEndpoint: endpoint,
          involvedIPs: [...data.ips],
          ipDiversityRate: rate,
          evidence: `IP diversity rate ${(rate * 100).toFixed(1)}% on ${endpoint} — ${data.ips.size} unique IPs in ${data.total} requests (5-min window)`,
        })
      }
    }
  }

  // ──────────────────────────────────────────────
  // CHECK 3: Single IP Multi-Attack (3+ different Layer 1 types)
  // ──────────────────────────────────────────────
  const ipAttackTypes = {}
  for (const event of layer1Results) {
    if (!ipAttackTypes[event.ip]) ipAttackTypes[event.ip] = new Set()
    ipAttackTypes[event.ip].add(event.type)
  }

  for (const [ip, types] of Object.entries(ipAttackTypes)) {
    if (types.size >= 3) {
      events.push({
        type: 'MULTI_VECTOR_ATTACKER',
        severity: 'CRITICAL',
        affectedEndpoint: null,
        involvedIPs: [ip],
        evidence: `IP ${ip} used ${types.size} distinct attack vectors: ${[...types].join(', ')}`,
        attackVectors: [...types],
      })
    }
  }

  // ──────────────────────────────────────────────
  // CHECK 4: New IP Burst Detection (1-min buckets)
  // ──────────────────────────────────────────────
  const minuteBuckets = {}
  const seenIPs = new Set()

  // Sort entries by time
  const sorted = [...parsedLogs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

  for (const entry of sorted) {
    const bucket = getMinuteBucket(entry.timestamp)
    if (!minuteBuckets[bucket]) minuteBuckets[bucket] = new Set()
    if (!seenIPs.has(entry.ip)) {
      minuteBuckets[bucket].add(entry.ip)
      seenIPs.add(entry.ip)
    }
  }

  const bucketCounts = Object.entries(minuteBuckets).map(([b, ips]) => ({ bucket: b, count: ips.size }))
  if (bucketCounts.length > 2) {
    const avg = bucketCounts.reduce((s, b) => s + b.count, 0) / bucketCounts.length
    for (const { bucket, count } of bucketCounts) {
      if (count > avg * 3 && count >= 5) {
        events.push({
          type: 'BOTNET_ACTIVATION',
          severity: 'HIGH',
          affectedEndpoint: null,
          involvedIPs: [...minuteBuckets[bucket]],
          evidence: `${count} new unique IPs appeared in a 1-minute window — ${(count / avg).toFixed(1)}x the average (${avg.toFixed(1)} new IPs/min). Possible botnet activation.`,
          burstWindow: bucket,
          newIPCount: count,
          averageNewIPs: avg,
        })
      }
    }
  }

  // ──────────────────────────────────────────────
  // CHECK 5: Sequential IP Pattern
  // ──────────────────────────────────────────────
  const sequences = detectSequentialIPs(allIPs)
  for (const seq of sequences) {
    // Convert back to IP strings
    const seqIPs = allIPs.filter(ip => {
      const parts = ip.split('.').map(Number)
      const num = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
      return num >= seq.start && num <= seq.end
    })
    events.push({
      type: 'SCRIPTED_RANGE_SCAN',
      severity: 'HIGH',
      affectedEndpoint: null,
      involvedIPs: seqIPs,
      evidence: `${seq.length} IPs in arithmetic sequence detected — strongly indicates scripted IP range scanning`,
      sequenceLength: seq.length,
    })
  }

  // ──────────────────────────────────────────────
  // CHECK 6: Intra-Log Baseline Anomaly
  // ──────────────────────────────────────────────
  // "Normal" endpoints = hit by 10+ unique IPs with 2xx status
  const endpointIPsSuccess = {}
  for (const entry of parsedLogs) {
    if (entry.statusCode >= 200 && entry.statusCode < 300) {
      const ep = getEndpoint(entry.path)
      if (!endpointIPsSuccess[ep]) endpointIPsSuccess[ep] = new Set()
      endpointIPsSuccess[ep].add(entry.ip)
    }
  }

  const normalEndpoints = new Set(
    Object.entries(endpointIPsSuccess)
      .filter(([, ips]) => ips.size >= 10)
      .map(([ep]) => ep)
  )

  if (normalEndpoints.size > 0) {
    // Flag IPs that exclusively hit non-normal endpoints
    for (const [ip, entries] of Object.entries(byIP)) {
      const hitEndpoints = new Set(entries.map(e => getEndpoint(e.path)))
      const hitsNormal = [...hitEndpoints].some(ep => normalEndpoints.has(ep))
      if (!hitsNormal && hitEndpoints.size >= 3) {
        events.push({
          type: 'ANOMALOUS_BEHAVIOR_PATTERN',
          severity: 'MEDIUM',
          affectedEndpoint: null,
          involvedIPs: [ip],
          evidence: `IP ${ip} exclusively targeted ${hitEndpoints.size} non-baseline endpoints with no access to normal traffic patterns — suspicious behavior`,
          suspiciousEndpoints: [...hitEndpoints].slice(0, 10),
        })
      }
    }
  }

  // ──────────────────────────────────────────────
  // CHECK 7: Temporal Endpoint Grouping (same endpoint, same second)
  // ──────────────────────────────────────────────
  // Map: endpoint:secondBucket → Set<IPs>
  const secondGroups = {}
  for (const entry of parsedLogs) {
    const key = `${getEndpoint(entry.path)}::${getSecondBucket(entry.timestamp)}`
    if (!secondGroups[key]) secondGroups[key] = { ips: new Set(), endpoint: getEndpoint(entry.path) }
    secondGroups[key].ips.add(entry.ip)
  }

  for (const [, data] of Object.entries(secondGroups)) {
    if (data.ips.size >= 5) {
      events.push({
        type: 'COORDINATED_ATTACK',
        severity: 'CRITICAL',
        affectedEndpoint: data.endpoint,
        involvedIPs: [...data.ips],
        evidence: `${data.ips.size} distinct IPs hit ${data.endpoint} within the same 1-second window — coordinated attack pattern`,
      })
    }
  }

  return events
}

/**
 * Compute the maximum IP diversity rate across all detected events
 * Used as the "hero metric" in the Overview tab
 * @param {Array} layer2Events
 * @returns {number} 0-1
 */
export function getMaxIPDiversityRate(layer2Events) {
  const distributed = layer2Events.filter(e => e.type === 'DISTRIBUTED_ATTACK' && e.ipDiversityRate)
  if (!distributed.length) return 0
  return Math.max(...distributed.map(e => e.ipDiversityRate))
}
