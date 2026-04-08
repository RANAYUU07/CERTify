import { useState } from 'react'
import useCertifyStore from '../store/certifyStore'

const SEVERITY_STYLES = {
  CRITICAL: { text: 'text-severity-critical', bg: 'bg-severity-critical/10', border: 'border-severity-critical', dot: 'bg-severity-critical' },
  HIGH:     { text: 'text-severity-high',     bg: 'bg-severity-high/10',     border: 'border-severity-high',     dot: 'bg-severity-high' },
  MEDIUM:   { text: 'text-accent',            bg: 'bg-accent/10',            border: 'border-accent',            dot: 'bg-accent' },
  LOW:      { text: 'text-muted-foreground',  bg: 'bg-muted/50',             border: 'border-border',            dot: 'bg-muted-foreground' },
}

function SeverityBadge({ severity }) {
  const s = SEVERITY_STYLES[severity] || SEVERITY_STYLES.LOW
  return (
    <span className={`inline-flex items-center gap-1.5 border px-2 py-0.5 text-xs font-bold uppercase tracking-widest ${s.text} ${s.border} ${s.bg}`}>
      <span className={`w-1.5 h-1.5 ${s.dot}`} />
      {severity}
    </span>
  )
}

function MitreBadge({ mitreId, mitreName }) {
  if (!mitreId) return null
  return (
    <span className="inline-flex items-center gap-1 border border-accent/30 bg-accent/10 px-2 py-0.5 text-xs font-mono text-accent">
      {mitreId}
    </span>
  )
}

function ExpandedRow({ event }) {
  return (
    <td colSpan={6} className="bg-muted/30 border-t border-border">
      <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-2">Evidence</p>
          <p className="text-accent font-semibold text-sm">{event.evidence}</p>
          {event.mitreId && (
            <div className="mt-3">
              <span className="text-xs uppercase tracking-widest text-muted-foreground mr-2">MITRE:</span>
              <span className="font-mono text-accent text-sm">{event.mitreId}</span>
              <span className="text-muted-foreground text-sm ml-2">— {event.mitreName}</span>
            </div>
          )}
        </div>
        <div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground mb-2">Raw Log</p>
          <p className="font-mono text-xs text-muted-foreground break-all bg-background p-3 border border-border">
            {event.rawLog}
          </p>
        </div>
      </div>
    </td>
  )
}

export default function DetectionResults() {
  const {
    layer1Results, layer2Results, layer2JsonSummary,
    rawLogs, ipDiversityRate, mitreMappings, geoData,
    geoLimited,
  } = useCertifyStore()

  const [subTab, setSubTab] = useState('overview')
  const [expandedRow, setExpandedRow] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [typeFilter, setTypeFilter] = useState('ALL')

  const allEvents = [...layer1Results, ...layer2Results]
  const severity = layer2JsonSummary?.severityBreakdown || {}

  // IP request counts for top attackers
  const ipCounts = {}
  for (const entry of rawLogs) {
    ipCounts[entry.ip] = (ipCounts[entry.ip] || 0) + 1
  }
  const topIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)

  // Attack type breakdown from layer1
  const typeCounts = {}
  for (const e of layer1Results) {
    typeCounts[e.type] = (typeCounts[e.type] || 0) + 1
  }
  const typeBreakdown = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])
  const maxTypeCount = typeBreakdown[0]?.[1] || 1

  const l1WithMitre = layer1Results.map(e => e)


  const filteredEvents = layer1Results.filter(e => {
    if (severityFilter !== 'ALL' && e.severity !== severityFilter) return false
    if (typeFilter !== 'ALL' && e.type !== typeFilter) return false
    return true
  })

  // Marquee stats
  const marqueeStats = [
    { num: rawLogs.length.toLocaleString(), label: 'REQUESTS ANALYZED' },
    { num: layer2JsonSummary?.uniqueSourceIPs?.toString() || '0', label: 'UNIQUE IPs' },
    { num: layer1Results.length.toString(), label: 'THREATS DETECTED' },
    { num: (severity.CRITICAL || 0).toString(), label: 'CRITICAL EVENTS' },
    { num: Object.keys(geoData).length.toString(), label: 'IPs GEOLOCATED' },
    { num: mitreMappings.length.toString(), label: 'MITRE TECHNIQUES' },
  ]

  return (
    <div className="min-h-[calc(100vh-64px)]">
      {/* Stats marquee */}
      <div className="border-b-2 border-border bg-background py-0 overflow-hidden shrink-0">
        <div className="animate-marquee-fast h-24 items-center">
          {[...marqueeStats, ...marqueeStats].map((stat, idx) => (
            <span key={idx} className="inline-flex items-baseline gap-3 px-12">
              <span className="text-[2.5rem] md:text-[3.5rem] font-bold text-foreground leading-none">{stat.num}</span>
              <span className="text-xs tracking-widest text-muted-foreground uppercase">{stat.label}</span>
              <span className="text-accent text-2xl ml-6">·</span>
            </span>
          ))}
        </div>
      </div>

      {/* Sub-tabs */}
      <div className="border-b-2 border-border bg-background flex">
        {['overview', 'events'].map(tab => (
          <button
            key={tab}
            onClick={() => setSubTab(tab)}
            className={`px-6 py-4 text-sm font-bold uppercase tracking-widest transition-all duration-200 border-r border-border ${
              subTab === tab
                ? 'text-accent border-b-2 border-b-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* ── OVERVIEW TAB ── */}
      {subTab === 'overview' && (
        <div className="px-6 md:px-12 py-10">

          {geoLimited && (
            <div className="border-2 border-severity-high bg-severity-high/10 p-4 mb-8 flex items-center gap-3">
              <span className="text-severity-high font-bold text-sm uppercase tracking-wider">⚠ GEO LIMIT REACHED</span>
              <span className="text-muted-foreground text-sm">Geolocation limited to first 900 unique IPs due to API quota.</span>
            </div>
          )}

          {/* Severity + IP Diversity Rate grid */}
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-px bg-border mb-1">
            {[
              { label: 'CRITICAL', count: severity.CRITICAL || 0, color: 'text-severity-critical', hoverText: 'group-hover:text-severity-critical' },
              { label: 'HIGH',     count: severity.HIGH || 0,     color: 'text-severity-high',     hoverText: 'group-hover:text-severity-high' },
              { label: 'MEDIUM',   count: severity.MEDIUM || 0,   color: 'text-accent',            hoverText: 'group-hover:text-accent' },
              { label: 'LOW',      count: severity.LOW || 0,      color: 'text-muted-foreground',  hoverText: 'group-hover:text-muted-foreground' },
              null, // IP diversity slot
            ].map((item, idx) => {
              if (!item) {
                // IP Diversity Rate — hero metric
                const rate = ipDiversityRate
                const pct = (rate * 100).toFixed(1)
                return (
                  <div key="diversity" className="bg-background p-6 md:p-8 group cursor-default hover:bg-accent transition-all duration-300 col-span-2 lg:col-span-1">
                    <div className="text-[3rem] md:text-[4rem] font-bold leading-none text-accent group-hover:text-accent-foreground transition-colors duration-300">
                      {pct}%
                    </div>
                    <div className="text-xs tracking-widest uppercase text-foreground group-hover:text-accent-foreground mt-2 font-bold transition-colors duration-300">
                      DISTRIBUTED ATTACK SCORE
                    </div>
                    <div className="text-xs tracking-widest text-muted-foreground group-hover:text-accent-foreground/70 mt-1 uppercase transition-colors duration-300">
                      IP Diversity Rate
                    </div>
                    <div className="mt-3 h-1 bg-border group-hover:bg-accent-foreground/20 transition-colors duration-300">
                      <div className="h-full bg-accent group-hover:bg-accent-foreground transition-colors duration-300" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                )
              }
              return (
                <div key={item.label} className="bg-background p-6 md:p-8 group cursor-default hover:bg-accent transition-all duration-300">
                  <div className={`text-[3rem] md:text-[4rem] font-bold leading-none ${item.color} group-hover:text-accent-foreground transition-colors duration-300`}>
                    {item.count}
                  </div>
                  <div className="text-xs tracking-widest uppercase text-muted-foreground group-hover:text-accent-foreground mt-2 transition-colors duration-300">
                    {item.label}
                  </div>
                </div>
              )
            })}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-10">
            {/* Top attackers */}
            <div>
              <h3 className="text-2xl md:text-3xl font-bold uppercase tracking-tighter mb-6">
                TOP <span className="text-accent">ATTACKERS</span>
              </h3>
              <table className="w-full border-2 border-border">
                <thead>
                  <tr className="bg-muted border-b border-border">
                    <th className="text-left text-xs uppercase tracking-widest text-muted-foreground px-4 py-3 font-bold">#</th>
                    <th className="text-left text-xs uppercase tracking-widest text-muted-foreground px-4 py-3 font-bold">IP ADDRESS</th>
                    <th className="text-left text-xs uppercase tracking-widest text-muted-foreground px-4 py-3 font-bold">COUNTRY</th>
                    <th className="text-right text-xs uppercase tracking-widest text-muted-foreground px-4 py-3 font-bold">REQUESTS</th>
                  </tr>
                </thead>
                <tbody>
                  {topIPs.map(([ip, count], i) => {
                    const geo = geoData[ip]
                    return (
                      <tr key={ip} className="border-b border-border hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-3 text-muted-foreground font-mono text-sm">{i + 1}</td>
                        <td className="px-4 py-3 font-mono font-bold text-foreground text-sm">{ip}</td>
                        <td className="px-4 py-3 text-muted-foreground text-sm">{geo?.country_name || '—'}</td>
                        <td className="px-4 py-3 text-right font-bold text-foreground text-sm">{count.toLocaleString()}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Attack type breakdown */}
            <div>
              <h3 className="text-2xl md:text-3xl font-bold uppercase tracking-tighter mb-6">
                ATTACK <span className="text-accent">TYPES</span>
              </h3>
              <div className="space-y-4">
                {typeBreakdown.map(([type, count]) => (
                  <div key={type}>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs uppercase tracking-widest text-foreground font-bold">{type.replace(/_/g, ' ')}</span>
                      <span className="font-mono font-bold text-accent text-sm">{count}</span>
                    </div>
                    <div className="h-2 bg-border">
                      <div
                        className="h-full bg-accent transition-all duration-500"
                        style={{ width: `${(count / maxTypeCount) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── EVENTS TAB ── */}
      {subTab === 'events' && (
        <div className="px-6 md:px-12 py-10">
          {/* Filters */}
          <div className="flex flex-wrap gap-3 mb-8 border-b-2 border-border pb-6">
            <div className="flex gap-2 flex-wrap">
              <span className="text-xs uppercase tracking-widest text-muted-foreground self-center mr-2">SEVERITY:</span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`border-2 px-3 h-9 text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
                    severityFilter === sev
                      ? 'bg-accent text-accent-foreground border-accent'
                      : 'border-border text-muted-foreground hover:text-foreground hover:border-foreground'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Events count */}
          <p className="text-sm text-muted-foreground uppercase tracking-widest mb-4">
            Showing {filteredEvents.length} of {layer1Results.length} events
          </p>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full border-2 border-border min-w-[800px]">
              <thead>
                <tr className="bg-muted border-b border-border">
                  {['SEVERITY', 'TYPE', 'SOURCE IP', 'PATH', 'TIMESTAMP', 'MITRE'].map(h => (
                    <th key={h} className="text-left text-xs uppercase tracking-widest text-muted-foreground px-4 py-3 font-bold whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredEvents.slice(0, 200).map((event, idx) => {
                  const isExpanded = expandedRow === idx
                  const mitreEntry = mitreMappings.find(m => m.name) // simplified
                  return [
                    <tr
                      key={`row-${idx}`}
                      className="border-b border-border hover:bg-muted/30 transition-colors cursor-pointer"
                      onClick={() => setExpandedRow(isExpanded ? null : idx)}
                    >
                      <td className="px-4 py-3">
                        <SeverityBadge severity={event.severity} />
                      </td>
                      <td className="px-4 py-3 text-sm font-bold uppercase tracking-wider text-foreground">
                        {event.type.replace(/_/g, ' ')}
                      </td>
                      <td className="px-4 py-3 font-mono text-sm text-foreground">{event.ip}</td>
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground max-w-[200px] truncate">
                        {event.path}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                        {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '—'}
                      </td>
                      <td className="px-4 py-3">
                        {/* MITRE tag — just show T number from event type */}
                        <span className="font-mono text-xs text-accent bg-accent/10 border border-accent/30 px-2 py-0.5">
                          {event.type === 'SQL_INJECTION' ? 'T1190' :
                           event.type === 'PATH_TRAVERSAL' ? 'T1083' :
                           event.type === 'XSS' ? 'T1059.007' :
                           event.type === 'COMMAND_INJECTION' ? 'T1059' :
                           event.type === 'SCANNER' ? 'T1595' :
                           event.type === 'HONEYPOT' ? 'T1083' : 'T1592'}
                        </span>
                      </td>
                    </tr>,
                    isExpanded && (
                      <tr key={`expanded-${idx}`}>
                        <ExpandedRow event={event} />
                      </tr>
                    ),
                  ]
                })}
              </tbody>
            </table>
          </div>

          {filteredEvents.length > 200 && (
            <p className="text-sm text-muted-foreground mt-4 uppercase tracking-widest">
              Showing top 200 events. Export PDF for complete list.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
