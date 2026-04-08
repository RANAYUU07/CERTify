// MITRE ATT&CK lookup table — maps detection types to technique IDs and names
const MITRE_MAP = {
  SQL_INJECTION:                { id: 'T1190',    name: 'Exploit Public-Facing Application' },
  PATH_TRAVERSAL:               { id: 'T1083',    name: 'File and Directory Discovery' },
  XSS:                          { id: 'T1059.007',name: 'JavaScript' },
  COMMAND_INJECTION:            { id: 'T1059',    name: 'Command and Scripting Interpreter' },
  SCANNER:                      { id: 'T1595',    name: 'Active Scanning' },
  HONEYPOT:                     { id: 'T1083',    name: 'File and Directory Discovery' },
  HIGH_VOLUME_SOURCE:           { id: 'T1110',    name: 'Brute Force' },
  DISTRIBUTED_ATTACK:           { id: 'T1595',    name: 'Active Scanning' },
  MULTI_VECTOR_ATTACKER:        { id: 'T1595.002',name: 'Vulnerability Scanning' },
  BOTNET_ACTIVATION:            { id: 'T1583.005',name: 'Botnet' },
  SCRIPTED_RANGE_SCAN:          { id: 'T1595.001',name: 'Scanning IP Blocks' },
  ANOMALOUS_BEHAVIOR_PATTERN:   { id: 'T1090',    name: 'Proxy' },
  COORDINATED_ATTACK:           { id: 'T1110.003',name: 'Password Spraying' },
  ASN_LEVEL_BRUTE_FORCE:        { id: 'T1110.003',name: 'Password Spraying' },
  COORDINATED_ANONYMIZED_ATTACK:{ id: 'T1090.003',name: 'Multi-hop Proxy' },
  GEO_VELOCITY_ANOMALY:         { id: 'T1090',    name: 'Proxy' },
}

/**
 * Get MITRE ATT&CK mapping for a detection type
 * @param {string} detectionType
 * @returns {{ id: string, name: string }}
 */
export function getMitreMapping(detectionType) {
  return MITRE_MAP[detectionType] || { id: 'T1592', name: 'Gather Victim Host Information' }
}

/**
 * Get all unique MITRE techniques from a list of events
 * @param {Array} events
 * @returns {Array<{ id, name, count }>}
 */
export function getMitreSummary(events) {
  const counts = {}
  events.forEach(event => {
    const mapping = getMitreMapping(event.type)
    const key = mapping.id
    if (!counts[key]) counts[key] = { id: mapping.id, name: mapping.name, count: 0 }
    counts[key].count++
  })
  return Object.values(counts).sort((a, b) => b.count - a.count)
}
