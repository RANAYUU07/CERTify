/**
 * CERTify Log Parser
 * Supports Apache Combined Log Format and Nginx default format
 * Auto-detects format from first non-empty line
 */

// Apache Combined Log Format:
// 1.2.3.4 - - [15/Jan/2024:02:34:21 +0000] "GET /path HTTP/1.1" 200 512 "http://ref.com" "Mozilla/5.0"
const APACHE_REGEX = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\S+)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?/

// Nginx default format:
// 1.2.3.4 - - [15/Jan/2024:02:34:21 +0000] "GET /path HTTP/1.1" 200 512 "-" "Mozilla/5.0"
// (same as Apache Combined — shares the regex)

// Month abbreviation map for timestamp parsing
const MONTHS = {
  Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
  Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12',
}

/**
 * Parse Apache/Nginx combined log format timestamp to ISO 8601
 * Input: "15/Jan/2024:02:34:21 +0000"
 * Output: "2024-01-15T02:34:21Z"
 */
function parseTimestamp(raw) {
  try {
    // Format: DD/Mon/YYYY:HH:MM:SS +ZZZZ
    const match = raw.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})/)
    if (!match) return null
    const [, day, mon, year, hh, mm, ss, tz] = match
    const month = MONTHS[mon] || '01'
    const tzHours = tz.slice(0, 3)
    const tzMins = tz.slice(3)
    const tzOffset = `${tzHours}:${tzMins}`
    return `${year}-${month}-${day}T${hh}:${mm}:${ss}${tzOffset}`
  } catch {
    return null
  }
}

/**
 * Decode URL-encoded characters in a path
 */
function decodePathSafe(path) {
  try {
    return decodeURIComponent(path)
  } catch {
    return path
  }
}

/**
 * Parse a single log line
 * @param {string} line
 * @param {number} lineNum
 * @returns {object|null} parsed log entry or null if malformed
 */
function parseLine(line, lineNum) {
  const trimmed = line.trim()
  if (!trimmed) return null

  const match = trimmed.match(APACHE_REGEX)
  if (!match) return null

  const [, ip, timestampRaw, method, pathRaw, statusCodeStr, responseSizeStr, referer, userAgent] = match

  const statusCode = parseInt(statusCodeStr, 10)
  const responseSize = responseSizeStr === '-' ? 0 : parseInt(responseSizeStr, 10)
  const path = decodePathSafe(pathRaw)
  const timestamp = parseTimestamp(timestampRaw)

  if (!ip || !timestamp || !method || !path) return null

  return {
    ip,
    timestamp,
    method: method.toUpperCase(),
    path,
    rawPath: pathRaw, // Keep original for signature matching on encoded versions
    statusCode: isNaN(statusCode) ? 0 : statusCode,
    responseSize: isNaN(responseSize) ? 0 : responseSize,
    userAgent: userAgent || '',
    referer: referer === '-' ? '' : (referer || ''),
    rawLog: line,
    lineNum,
  }
}

/**
 * Parse an entire log file content string
 * @param {string} content - raw file content
 * @returns {{ entries: Array, warnings: Array, malformedCount: number }}
 */
export function parseLogFile(content) {
  const lines = content.split('\n')
  const entries = []
  const warnings = []
  let malformedCount = 0

  lines.forEach((line, idx) => {
    if (!line.trim()) return

    const entry = parseLine(line, idx + 1)
    if (entry) {
      entries.push(entry)
    } else {
      malformedCount++
      if (malformedCount <= 5) {
        warnings.push(`Line ${idx + 1}: Could not parse — "${line.slice(0, 80)}..."`)
      }
    }
  })

  // Sort by timestamp ascending
  entries.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

  return { entries, warnings, malformedCount }
}

/**
 * Get analysis period from parsed entries
 * @param {Array} entries
 * @returns {{ start: string, end: string, durationMinutes: number }}
 */
export function getAnalysisPeriod(entries) {
  if (!entries.length) return { start: null, end: null, durationMinutes: 0 }
  const start = entries[0].timestamp
  const end = entries[entries.length - 1].timestamp
  const durationMs = new Date(end) - new Date(start)
  const durationMinutes = Math.round(durationMs / 60000)
  return { start, end, durationMinutes }
}

/**
 * Get unique IPs from parsed entries
 * @param {Array} entries
 * @returns {string[]}
 */
export function getUniqueIPs(entries) {
  return [...new Set(entries.map(e => e.ip))]
}
