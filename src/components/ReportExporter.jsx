import { useState } from 'react'
import useCertifyStore from '../store/certifyStore'

export default function ReportExporter() {
  const { exportReport, layer2JsonSummary, layer1Results, layer2Results, attackNarrative, mitreMappings, rawLogs } = useCertifyStore()
  const [orgName, setOrgName] = useState('')
  const [downloadedId, setDownloadedId] = useState(null)

  const allEvents = [...layer1Results, ...layer2Results]
  const severity = layer2JsonSummary?.severityBreakdown || {}

  const handleExport = () => {
    if (!orgName.trim()) return
    const id = exportReport(orgName)
    if (id) setDownloadedId(id)
  }

  const REPORT_SECTIONS = [
    'Header — Org name, Incident ID, analysis period',
    'Executive Summary — threat counts, AI narrative',
    'Incident Details — all flagged events with MITRE tags',
    'IP Analysis — top attackers, ASN distribution',
    'Geo-Velocity Anomalies — impossible travel sequences',
    'MITRE ATT&CK Summary — technique breakdown',
    'Recommendations — tailored by attack types detected',
    'Footer — CERT-In portal link, CERTify branding',
  ]

  return (
    <div className="px-6 md:px-12 py-10 min-h-[calc(100vh-130px)]">
      {/* Header */}
      <div className="mb-12">
        <h2 className="text-2xl md:text-4xl font-bold uppercase tracking-tighter">
          EXPORT <span className="text-accent">REPORT</span>
        </h2>
        <p className="text-muted-foreground text-sm mt-1">
          Generate a CERT-In compliant PDF incident report
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
        {/* Left: Input */}
        <div>
          {/* Org name */}
          <div className="mb-10">
            <label htmlFor="org-name" className="block text-xs uppercase tracking-widest text-muted-foreground mb-3">
              YOUR ORGANIZATION NAME
            </label>
            <input
              id="org-name"
              type="text"
              value={orgName}
              onChange={e => setOrgName(e.target.value)}
              placeholder="ORGANIZATION NAME"
              className="w-full h-16 bg-transparent border-b-2 border-border focus:border-accent text-2xl md:text-3xl font-bold uppercase tracking-tighter text-foreground py-2 px-0 outline-none placeholder:text-muted placeholder:font-normal placeholder:normal-case"
              onKeyDown={e => { if (e.key === 'Enter') handleExport() }}
            />
          </div>

          {/* Summary stats */}
          <div className="space-y-3 mb-10 border-2 border-border p-6">
            <p className="text-xs uppercase tracking-widest text-muted-foreground mb-4 font-bold">REPORT WILL INCLUDE</p>
            {[
              { label: 'Total requests analyzed', value: rawLogs.length.toLocaleString() },
              { label: 'Unique source IPs', value: layer2JsonSummary?.uniqueSourceIPs?.toString() || '0' },
              { label: 'Threats detected', value: layer1Results.length.toString() },
              { label: 'CRITICAL events', value: (severity.CRITICAL || 0).toString() },
              { label: 'HIGH events', value: (severity.HIGH || 0).toString() },
              { label: 'MITRE techniques', value: mitreMappings.length.toString() },
              { label: 'Geo-velocity anomalies', value: layer2Results.filter(e => e.type === 'GEO_VELOCITY_ANOMALY').length.toString() },
              { label: 'AI narrative', value: attackNarrative ? '✓ Included' : '— Generate in AI Copilot tab' },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between items-center border-b border-border pb-2">
                <span className="text-sm text-muted-foreground uppercase tracking-wider">{label}</span>
                <span className="text-sm font-bold text-foreground font-mono">{value}</span>
              </div>
            ))}
          </div>

          {/* Download button */}
          {!downloadedId ? (
            <button
              onClick={handleExport}
              disabled={!orgName.trim()}
              className="w-full bg-accent text-accent-foreground h-20 text-xl md:text-2xl font-bold uppercase tracking-tighter hover:scale-[1.02] active:scale-95 transition-all duration-200 disabled:opacity-40 disabled:pointer-events-none"
            >
              ↓ DOWNLOAD CERT-IN REPORT (PDF)
            </button>
          ) : (
            <div>
              <div className="border-2 border-accent bg-accent/5 p-8 mb-4 text-center">
                <p className="text-2xl font-bold uppercase tracking-tighter text-accent mb-2">REPORT DOWNLOADED ✓</p>
                <p className="font-mono text-sm text-muted-foreground">Incident ID: {downloadedId}</p>
              </div>
              <button
                onClick={() => {
                  setDownloadedId(null)
                  handleExport()
                }}
                className="w-full border-2 border-border h-14 font-bold uppercase tracking-widest text-sm text-foreground hover:bg-foreground hover:text-background transition-all duration-200"
              >
                ↓ DOWNLOAD AGAIN
              </button>
            </div>
          )}

          {!orgName.trim() && (
            <p className="text-xs text-muted-foreground uppercase tracking-widest mt-3 text-center">
              Enter organization name to enable download
            </p>
          )}
        </div>

        {/* Right: Report preview */}
        <div>
          <h3 className="text-xl font-bold uppercase tracking-tighter mb-6">
            REPORT <span className="text-accent">SECTIONS</span>
          </h3>
          <div className="space-y-0 border-2 border-border">
            {REPORT_SECTIONS.map((section, i) => (
              <div
                key={i}
                className="flex items-start gap-4 px-6 py-4 border-b border-border last:border-b-0 group hover:bg-muted/30 transition-colors"
              >
                <span className="text-accent font-bold text-xl flex-shrink-0">✓</span>
                <div>
                  <span className="text-sm font-bold text-foreground uppercase tracking-wider">
                    {section.split('—')[0].trim()}
                  </span>
                  <span className="text-xs text-muted-foreground ml-2 hidden md:inline">
                    — {section.split('—').slice(1).join('—').trim()}
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 border-2 border-border p-6 bg-muted/20">
            <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-2">ABOUT THIS REPORT</p>
            <p className="text-sm text-muted-foreground leading-relaxed">
              This report is generated entirely in your browser using jsPDF. 
              No log data is uploaded to any server. The PDF is formatted 
              to meet CERT-In reporting guidelines under the IT Amendment Rules 2022.
            </p>
            <p className="text-xs text-muted-foreground mt-3 italic">
              File: CERTify_{orgName ? orgName.replace(/[^a-z0-9]/gi, '_').slice(0, 20) : 'Organization'}_{new Date().toISOString().slice(0, 10)}.pdf
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
