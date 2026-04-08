import {
  SQL_INJECTION_PATTERNS,
  PATH_TRAVERSAL_PATTERNS,
  XSS_PATTERNS,
  COMMAND_INJECTION_PATTERNS,
  MALICIOUS_USER_AGENTS,
} from '../constants/signatures.js'
import { isDecoyEndpoint } from '../constants/decoyEndpoints.js'

/**
 * Test a string against an array of regex patterns
 */
function matchesAny(str, patterns) {
  if (!str) return null
  for (const pattern of patterns) {
    if (pattern.test(str)) return pattern.toString()
  }
  return null
}

/**
 * Determine severity for signature-based events
 */
function getSeverity(type, entry) {
  if (type === 'HONEYPOT') return 'HIGH'
  if (type === 'COMMAND_INJECTION') return 'CRITICAL'
  if (type === 'SQL_INJECTION') return entry.path.toLowerCase().includes('union') ? 'HIGH' : 'MEDIUM'
  if (type === 'PATH_TRAVERSAL') return 'HIGH'
  if (type === 'XSS') return 'MEDIUM'
  if (type === 'SCANNER') return 'HIGH'
  return 'MEDIUM'
}

/**
 * Layer 1 — Signature-Based Detection
 * Runs synchronously on every log entry.
 * @param {Array} parsedLogs - output of logParser.parseLogFile
 * @returns {Array} layer1Events
 */
export function runLayer1(parsedLogs) {
  const events = []

  for (const entry of parsedLogs) {
    const { ip, timestamp, path, rawPath, userAgent, rawLog } = entry
    const searchStr = `${path} ${rawPath || ''}`

    // Check honeypot first (highest priority)
    if (isDecoyEndpoint(path)) {
      events.push({
        type: 'HONEYPOT',
        severity: 'HIGH',
        ip,
        timestamp,
        path,
        evidence: `Decoy endpoint accessed: ${path}`,
        rawLog,
      })
      continue // Don't double-count
    }

    // SQL Injection
    const sqlMatch = matchesAny(searchStr, SQL_INJECTION_PATTERNS)
    if (sqlMatch) {
      events.push({
        type: 'SQL_INJECTION',
        severity: getSeverity('SQL_INJECTION', entry),
        ip,
        timestamp,
        path,
        evidence: `SQL injection pattern detected in request path`,
        rawLog,
      })
    }

    // Path Traversal
    const pathMatch = matchesAny(searchStr, PATH_TRAVERSAL_PATTERNS)
    if (pathMatch) {
      events.push({
        type: 'PATH_TRAVERSAL',
        severity: 'HIGH',
        ip,
        timestamp,
        path,
        evidence: `Path traversal attempt detected: ${path}`,
        rawLog,
      })
    }

    // XSS
    const xssMatch = matchesAny(searchStr, XSS_PATTERNS)
    if (xssMatch) {
      events.push({
        type: 'XSS',
        severity: 'MEDIUM',
        ip,
        timestamp,
        path,
        evidence: `Cross-site scripting payload detected in request`,
        rawLog,
      })
    }

    // Command Injection
    const cmdMatch = matchesAny(searchStr, COMMAND_INJECTION_PATTERNS)
    if (cmdMatch) {
      events.push({
        type: 'COMMAND_INJECTION',
        severity: 'CRITICAL',
        ip,
        timestamp,
        path,
        evidence: `Command injection pattern detected in request path`,
        rawLog,
      })
    }

    // Scanner / malicious User-Agent
    if (userAgent) {
      const uaMatch = matchesAny(userAgent, MALICIOUS_USER_AGENTS)
      if (uaMatch) {
        events.push({
          type: 'SCANNER',
          severity: 'HIGH',
          ip,
          timestamp,
          path,
          evidence: `Malicious scanner User-Agent detected: ${userAgent.slice(0, 80)}`,
          rawLog,
        })
      }

      // Empty User-Agent
      if (userAgent.trim() === '') {
        events.push({
          type: 'SCANNER',
          severity: 'MEDIUM',
          ip,
          timestamp,
          path,
          evidence: 'Empty User-Agent string — automated tool or scanner',
          rawLog,
        })
      }
    }
  }

  return events
}
