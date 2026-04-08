import { useState } from 'react'
import useCertifyStore from '../store/certifyStore'

const TYPE_LABELS = {
  SQL_INJECTION: 'SQL Injection',
  XSS: 'Cross-Site Scripting',
  PATH_TRAVERSAL: 'Path Traversal',
  COMMAND_INJECTION: 'Command Injection',
  SCANNER: 'Vulnerability Scanner',
  GEO_VELOCITY_ANOMALY: 'Impossible Travel',
  IP_BURST: 'Request Bursting',
  SEQUENTIAL_SCAN: 'Sequential IP Scan',
}

export default function HumanConfirmation() {
  const { layer1Results, layer2Results, confirmedFindings, toggleFindingConfirmation } = useCertifyStore()
  const [filter, setFilter] = useState('ALL')

  const allFindings = [
    ...layer1Results.map(f => ({ ...f, id: `l1-${f.timestamp}-${f.ip}`, layer: 1 })),
    ...layer2Results.map((f, i) => ({ ...f, id: `l2-${i}`, layer: 2 }))
  ]

  const filteredFindings = allFindings.filter(f => {
    if (filter === 'ALL') return true
    if (filter === 'VERIFIED') return confirmedFindings[f.id]
    if (filter === 'UNVERIFIED') return !confirmedFindings[f.id]
    return true
  })

  const verifiedCount = Object.values(confirmedFindings).filter(Boolean).length

  return (
    <div className="px-6 md:px-12 py-10 min-h-[calc(100vh-130px)]">
      {/* Header */}
      <div className="mb-12 flex justify-between items-end flex-wrap gap-4">
        <div>
          <h2 className="text-2xl md:text-4xl font-bold uppercase tracking-tighter">
            HUMAN <span className="text-accent">CONFIRMATION</span>
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Review and validate automated findings to finalize the forensic report
          </p>
        </div>
        
        <div className="bg-muted p-4 border-2 border-border flex items-center gap-6">
          <div className="text-center">
            <p className="text-[0.6rem] font-bold text-muted-foreground uppercase tracking-widest">Total Findings</p>
            <p className="text-xl font-bold">{allFindings.length}</p>
          </div>
          <div className="w-px h-8 bg-border" />
          <div className="text-center">
            <p className="text-[0.6rem] font-bold text-accent uppercase tracking-widest">Verified</p>
            <p className="text-xl font-bold text-accent">{verifiedCount}</p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-4 mb-8">
        {['ALL', 'UNVERIFIED', 'VERIFIED'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`h-10 px-6 text-xs font-bold uppercase tracking-widest border-2 transition-all ${
              filter === f 
                ? 'bg-foreground text-background border-foreground' 
                : 'border-border text-muted-foreground hover:border-foreground hover:text-foreground'
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.length === 0 ? (
          <div className="border-2 border-border p-12 text-center bg-muted/20">
            <p className="text-muted-foreground uppercase tracking-widest font-bold">No Findings to Display</p>
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <div 
              key={finding.id}
              className={`border-2 p-6 transition-all duration-300 ${
                confirmedFindings[finding.id] 
                  ? 'border-accent bg-accent/[0.03]' 
                  : 'border-border bg-background'
              }`}
            >
              <div className="flex items-center gap-6">
                <button
                  onClick={() => toggleFindingConfirmation(finding.id)}
                  className={`w-12 h-12 flex-shrink-0 border-2 rounded-full flex items-center justify-center transition-all ${
                    confirmedFindings[finding.id]
                      ? 'bg-accent border-accent text-accent-foreground'
                      : 'border-border hover:border-accent text-muted-foreground'
                  }`}
                  aria-label={confirmedFindings[finding.id] ? 'Unverify finding' : 'Verify finding'}
                >
                  {confirmedFindings[finding.id] ? (
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="square" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <div className="w-3 h-3 bg-muted group-hover:bg-accent" />
                  )}
                </button>

                <div className="flex-1">
                  <div className="flex justify-between items-start mb-1">
                    <h3 className="text-lg font-bold uppercase tracking-tight">
                      {TYPE_LABELS[finding.type] || finding.type.replace(/_/g, ' ')}
                    </h3>
                    <span className={`text-[0.6rem] font-bold px-2 py-0.5 border ${
                      finding.severity === 'CRITICAL' ? 'border-severity-critical text-severity-critical' :
                      finding.severity === 'HIGH' ? 'border-severity-high text-severity-high' :
                      'border-accent text-accent'
                    }`}>
                      {finding.severity}
                    </span>
                  </div>
                  <div className="flex gap-4 text-xs font-mono text-muted-foreground">
                    <span>IP: <span className="text-foreground">{finding.ip || finding.involvedIPs?.[0]}</span></span>
                    {finding.path && <span>PATH: <span className="text-foreground">{finding.path}</span></span>}
                  </div>
                  <p className="text-xs text-muted-foreground mt-2 line-clamp-1">
                    {finding.evidence}
                  </p>
                </div>

                <div className="hidden md:block text-right">
                  <p className="text-[0.6rem] font-bold text-muted-foreground uppercase tracking-widest mb-1">Status</p>
                  <p className={`text-xs font-bold uppercase ${confirmedFindings[finding.id] ? 'text-accent' : 'text-muted-foreground'}`}>
                    {confirmedFindings[finding.id] ? 'Verified' : 'Pending Review'}
                  </p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="mt-12 p-8 border-2 border-accent/20 bg-accent/[0.01]">
         <div className="flex gap-6 items-center">
            <div className="w-16 h-16 bg-accent flex items-center justify-center flex-shrink-0">
               <svg className="w-8 h-8 text-accent-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="square" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
               </svg>
            </div>
            <div>
               <h4 className="text-xl font-bold uppercase tracking-tight mb-1">Analyst Sign-off</h4>
               <p className="text-sm text-muted-foreground leading-relaxed">
                 Once findings are verified, the final PDF report will include a "Forensic Verification" badge for each confirmed entry. 
                 This step is mandatory for CERT-In compliant legal documentation.
               </p>
            </div>
         </div>
      </div>
    </div>
  )
}
