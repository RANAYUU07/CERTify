import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'

// Color palette (RGB arrays)
const COLORS = {
  black:     [9, 9, 11],
  white:     [250, 250, 250],
  accent:    [223, 225, 4],
  critical:  [255, 23, 68],
  high:      [255, 109, 0],
  medium:    [234, 179, 8],
  low:       [161, 161, 170],
  muted:     [39, 39, 42],
  border:    [63, 63, 70],
}

const SEVERITY_COLORS = {
  CRITICAL: COLORS.critical,
  HIGH:     COLORS.high,
  MEDIUM:   COLORS.medium,
  LOW:      COLORS.low,
}

/**
 * Generate a CERT-In compliant incident ID
 */
function generateIncidentId() {
  const now = new Date()
  const yyyymmdd = now.toISOString().slice(0, 10).replace(/-/g, '')
  const rand = Math.random().toString(36).slice(2, 6).toUpperCase()
  return `CERT-${yyyymmdd}-${rand}`
}

/**
 * Format a timestamp for display
 */
function formatTimestamp(ts) {
  if (!ts) return 'N/A'
  try {
    return new Date(ts).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST'
  } catch {
    return ts
  }
}

/**
 * Add a section header
 */
function addSectionHeader(doc, title, y) {
  doc.setFillColor(...COLORS.accent)
  doc.rect(14, y, 182, 8, 'F')
  doc.setTextColor(...COLORS.black)
  doc.setFontSize(10)
  doc.setFont('helvetica', 'bold')
  doc.text(title.toUpperCase(), 16, y + 5.5)
  doc.setTextColor(...COLORS.white)
  return y + 12
}

/**
 * Generate and download CERT-In PDF report
 * @param {object} options
 */
export function generateCERTInReport({
  orgName,
  fileName,
  parsedLogs,
  layer1Results,
  layer2Results,
  geoData,
  mitreSummary,
  attackNarrative,
  layer2JsonSummary,
  confirmedFindings = {},
}) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const incidentId = generateIncidentId()
  const allEvents = [...layer1Results, ...layer2Results]
  const { start, end } = layer2JsonSummary?.analysisWindow || {}
  const severityBreakdown = layer2JsonSummary?.severityBreakdown || {}

  let y = 14

  // ─────────────────────────────────
  // SECTION 1: HEADER
  // ─────────────────────────────────
  doc.setFillColor(...COLORS.black)
  doc.rect(0, 0, 210, 40, 'F')

  doc.setTextColor(...COLORS.accent)
  doc.setFontSize(22)
  doc.setFont('helvetica', 'bold')
  doc.text('CERTIFY', 14, 16)

  doc.setTextColor(...COLORS.white)
  doc.setFontSize(9)
  doc.setFont('helvetica', 'normal')
  doc.text('CERT-In Incident Report', 14, 23)

  doc.setFontSize(8)
  doc.text(`Organization: ${orgName || 'Not Specified'}`, 14, 30)
  doc.text(`Incident ID: ${incidentId}`, 14, 35)
  doc.text(`Generated: ${formatTimestamp(new Date().toISOString())}`, 100, 30)
  doc.text(`Log File: ${fileName || 'Unknown'}`, 100, 35)

  y = 46

  // Analysis period
  doc.setTextColor(...COLORS.white)
  doc.setFillColor(...COLORS.muted)
  doc.rect(14, y, 182, 12, 'F')
  doc.setFontSize(8)
  doc.text(`Analysis Period: ${formatTimestamp(start)} — ${formatTimestamp(end)}`, 16, y + 5)
  doc.text(`Duration: ${layer2JsonSummary?.analysisWindow?.durationMinutes || 0} minutes`, 16, y + 10)
  y += 16

  // ─────────────────────────────────
  // SECTION 2: EXECUTIVE SUMMARY
  // ─────────────────────────────────
  y = addSectionHeader(doc, '1. Executive Summary', y)

  doc.setTextColor(...COLORS.white)
  doc.setFontSize(8)

  // Stats row
  const stats = [
    ['Total Requests', (parsedLogs?.length || 0).toLocaleString()],
    ['Unique Source IPs', (layer2JsonSummary?.uniqueSourceIPs || 0).toString()],
    ['Total Threats Detected', allEvents.length.toString()],
    ['CRITICAL Events', (severityBreakdown.CRITICAL || 0).toString()],
    ['HIGH Events', (severityBreakdown.HIGH || 0).toString()],
    ['MEDIUM Events', (severityBreakdown.MEDIUM || 0).toString()],
  ]

  autoTable(doc, {
    startY: y,
    body: stats,
    theme: 'plain',
    styles: { fontSize: 8, textColor: COLORS.white, fillColor: COLORS.muted, cellPadding: 2 },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 60 },
      1: { textColor: COLORS.accent, fontStyle: 'bold', cellWidth: 40 },
    },
    margin: { left: 14, right: 14 },
    tableWidth: 182,
  })

  y = doc.lastAutoTable.finalY + 6

  // AI narrative
  if (attackNarrative) {
    doc.setFontSize(8)
    doc.setTextColor(...COLORS.white)
    const lines = doc.splitTextToSize(attackNarrative, 180)
    doc.text(lines, 14, y)
    y += lines.length * 4 + 4
  }

  // Verification Summary
  const verifiedCount = Object.values(confirmedFindings).filter(Boolean).length
  const totalFindings = layer1Results.length + layer2Results.length
  
  doc.setFillColor(...COLORS.muted)
  doc.rect(14, y, 182, 12, 'F')
  doc.setFontSize(8)
  doc.setTextColor(...COLORS.accent)
  doc.setFont('helvetica', 'bold')
  doc.text(`ANALYST VERIFICATION: ${verifiedCount} of ${totalFindings} findings verified by human analyst`, 16, y + 7.5)
  y += 18

  // ─────────────────────────────────
  // SECTION 3: INCIDENT DETAILS TABLE
  // ─────────────────────────────────
  if (y > 240) { doc.addPage(); y = 14 }
  y = addSectionHeader(doc, '2. Incident Details', y)

  const tableRows = layer1Results.slice(0, 80).map(event => {
    const mitre = layer2JsonSummary?.mitreTechniquesSummary?.find(m => {
      // Get MITRE for this type
      return true
    })
    return [
      event.severity,
      event.type.replace(/_/g, ' '),
      event.ip,
      (event.path || '').slice(0, 40),
      formatTimestamp(event.timestamp).slice(0, 20),
      event.evidence?.slice(0, 60) || '',
    ]
  })

  autoTable(doc, {
    startY: y,
    head: [['SEVERITY', 'TYPE', 'SOURCE IP', 'PATH', 'VERIFIED']],
    body: layer1Results.slice(0, 50).map(event => {
      const id = `l1-${event.timestamp}-${event.ip}`
      return [
        event.severity,
        event.type.replace(/_/g, ' '),
        event.ip,
        (event.path || '').slice(0, 40),
        confirmedFindings[id] ? 'VERIFIED ✓' : 'PENDING'
      ]
    }),
    theme: 'plain',
    styles: { fontSize: 6, textColor: COLORS.white, fillColor: COLORS.muted, cellPadding: 1.5 },
    headStyles: { fillColor: COLORS.border, textColor: COLORS.white, fontStyle: 'bold', fontSize: 7 },
    bodyStyles: { fillColor: COLORS.muted },
    alternateRowStyles: { fillColor: [30, 30, 33] },
    didParseCell: (data) => {
      if (data.column.index === 0 && data.section === 'body') {
        const sev = data.cell.raw
        data.cell.styles.textColor = SEVERITY_COLORS[sev] || COLORS.white
        data.cell.styles.fontStyle = 'bold'
      }
    },
    margin: { left: 14, right: 14 },
    columnStyles: {
      0: { cellWidth: 22 },
      1: { cellWidth: 38 },
      2: { cellWidth: 30 },
      3: { cellWidth: 62 },
      4: { cellWidth: 30, halign: 'center' },
    },
  })
  y = doc.lastAutoTable.finalY + 8

  // ─────────────────────────────────
  // SECTION 4: IP ANALYSIS
  // ─────────────────────────────────
  if (y > 220) { doc.addPage(); y = 14 }
  y = addSectionHeader(doc, '3. IP Analysis', y)

  const topAttackers = (layer2JsonSummary?.topAttackers || []).slice(0, 15)
  autoTable(doc, {
    startY: y,
    head: [['IP ADDRESS', 'COUNTRY', 'ASN', 'REQUESTS', 'PROXY', 'TOR']],
    body: topAttackers.map(a => [
      a.ip, a.country || 'Unknown', a.asn || 'N/A',
      a.requestCount?.toLocaleString() || '0',
      a.proxy ? 'YES' : 'No',
      a.tor ? 'YES' : 'No',
    ]),
    theme: 'plain',
    styles: { fontSize: 7, textColor: COLORS.white, fillColor: COLORS.muted, cellPadding: 2 },
    headStyles: { fillColor: COLORS.border, textColor: COLORS.white, fontStyle: 'bold' },
    didParseCell: (data) => {
      if (data.column.index >= 4 && data.section === 'body' && data.cell.raw === 'YES') {
        data.cell.styles.textColor = COLORS.critical
        data.cell.styles.fontStyle = 'bold'
      }
    },
    margin: { left: 14, right: 14 },
  })
  y = doc.lastAutoTable.finalY + 4

  // Disclaimer
  doc.setFontSize(7)
  doc.setTextColor(...COLORS.low)
  doc.setFont('helvetica', 'italic')
  doc.text('* IP geolocation data is indicative only. Proxy, VPN, or Tor usage may mask the true origin of attacks.', 14, y)
  doc.setFont('helvetica', 'normal')
  y += 8

  // ─────────────────────────────────
  // SECTION 5: GEO-VELOCITY ANOMALIES
  // ─────────────────────────────────
  const geoAnoms = layer2JsonSummary?.geoVelocityAnomalies || []
  if (geoAnoms.length > 0) {
    if (y > 220) { doc.addPage(); y = 14 }
    y = addSectionHeader(doc, '4. Geo-Velocity Anomalies', y)
    for (const anom of geoAnoms) {
      doc.setFontSize(8)
      doc.setTextColor(...COLORS.critical)
      doc.text(`⚠ ${anom.humanReadable || anom.location1?.label + ' → ' + anom.location2?.label}`, 14, y)
      y += 5
      doc.setTextColor(...COLORS.white)
      doc.text(`Distance: ${anom.distanceKm?.toLocaleString() || '?'} km | Time: ${anom.timeDeltaSeconds || '?'}s | Speed: ${anom.speedKmPerSecond?.toLocaleString() || '?'} km/s`, 16, y)
      y += 8
    }
  }

  // ─────────────────────────────────
  // SECTION 6: MITRE ATT&CK SUMMARY
  // ─────────────────────────────────
  if (y > 220) { doc.addPage(); y = 14 }
  y = addSectionHeader(doc, '5. MITRE ATT&CK Summary', y)

  autoTable(doc, {
    startY: y,
    head: [['TECHNIQUE ID', 'TECHNIQUE NAME', 'OCCURRENCES']],
    body: (layer2JsonSummary?.mitreTechniquesSummary || []).map(m => [m.id, m.name, m.count.toString()]),
    theme: 'plain',
    styles: { fontSize: 8, textColor: COLORS.white, fillColor: COLORS.muted, cellPadding: 2 },
    headStyles: { fillColor: COLORS.border, textColor: COLORS.white, fontStyle: 'bold' },
    columnStyles: {
      0: { textColor: COLORS.accent, fontStyle: 'bold', cellWidth: 30 },
      1: { cellWidth: 110 },
      2: { cellWidth: 30, halign: 'right', fontStyle: 'bold' },
    },
    margin: { left: 14, right: 14 },
  })
  y = doc.lastAutoTable.finalY + 8

  // ─────────────────────────────────
  // SECTION 7: RECOMMENDATIONS
  // ─────────────────────────────────
  if (y > 200) { doc.addPage(); y = 14 }
  y = addSectionHeader(doc, '6. Recommendations', y)

  const attackTypes = new Set(layer1Results.map(e => e.type))
  const recommendations = []

  if (attackTypes.has('SQL_INJECTION')) {
    recommendations.push('Implement WAF rules blocking SQL injection patterns; use parameterized queries in all database calls')
  }
  if (attackTypes.has('PATH_TRAVERSAL')) {
    recommendations.push('Validate and sanitize all file path inputs; implement chroot jails for file access operations')
  }
  if (attackTypes.has('XSS')) {
    recommendations.push('Implement Content Security Policy (CSP) headers; encode all user-supplied output')
  }
  if (attackTypes.has('COMMAND_INJECTION')) {
    recommendations.push('Avoid shell command execution with user input; use safe APIs for OS operations')
  }
  if (attackTypes.has('HONEYPOT') || attackTypes.has('SCANNER')) {
    recommendations.push('Block identified scanner IPs at perimeter firewall; implement rate limiting and geo-blocking for known attack regions')
  }
  if (layer2Results.some(e => e.type === 'GEO_VELOCITY_ANOMALY')) {
    recommendations.push('Implement impossible travel detection in authentication systems; consider multi-factor authentication')
  }
  recommendations.push('Report this incident to CERT-In within 6 hours as mandated by IT Amendment Rules 2022')
  recommendations.push('Preserve all server logs for forensic analysis; do not rotate logs until investigation is complete')
  recommendations.push('Conduct a post-incident review and update incident response playbooks')

  doc.setFontSize(8)
  doc.setTextColor(...COLORS.white)
  recommendations.forEach((rec, i) => {
    if (y > 270) { doc.addPage(); y = 14 }
    const lines = doc.splitTextToSize(`${i + 1}. ${rec}`, 178)
    doc.text(lines, 14, y)
    y += lines.length * 4 + 2
  })

  y += 6

  // ─────────────────────────────────
  // SECTION 8: FOOTER
  // ─────────────────────────────────
  const pageCount = doc.internal.getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFillColor(...COLORS.muted)
    doc.rect(0, 285, 210, 12, 'F')
    doc.setFontSize(7)
    doc.setTextColor(...COLORS.low)
    doc.text('Generated by CERTify — Client-side log analysis tool', 14, 291)
    doc.text('CERT-In Portal: https://www.cert-in.org.in', 14, 295)
    doc.setTextColor(...COLORS.accent)
    doc.text(`Page ${i} of ${pageCount}`, 190, 291, { align: 'right' })
    doc.text(incidentId, 190, 295, { align: 'right' })
  }

  // Download
  const safeOrg = (orgName || 'Report').replace(/[^a-z0-9]/gi, '_').slice(0, 30)
  const dateStr = new Date().toISOString().slice(0, 10)
  doc.save(`CERTify_${safeOrg}_${dateStr}.pdf`)

  return incidentId
}
