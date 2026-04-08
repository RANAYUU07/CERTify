import { useState } from 'react'
import useCertifyStore from '../store/certifyStore'

const PRIORITY_COLORS = {
  CRITICAL: 'text-severity-critical border-severity-critical bg-severity-critical/10',
  HIGH: 'text-severity-high border-severity-high bg-severity-high/10',
  MEDIUM: 'text-accent border-accent bg-accent/10',
}

export default function ActionPlaybook() {
  const { playbookActions, addToast } = useCertifyStore()
  const [completed, setCompleted] = useState({})

  const toggleComplete = (id) => {
    setCompleted(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const copyCommand = (cmd) => {
    navigator.clipboard.writeText(cmd)
    addToast('Command copied to clipboard', 'success')
  }

  return (
    <div className="px-6 md:px-12 py-10 min-h-[calc(100vh-130px)]">
      {/* Header */}
      <div className="mb-12">
        <h2 className="text-2xl md:text-4xl font-bold uppercase tracking-tighter">
          ACTION <span className="text-accent">PLAYBOOK</span>
        </h2>
        <p className="text-muted-foreground text-sm mt-1">
          Prioritized remediation steps based on your forensic analysis
        </p>
      </div>

      <div className="max-w-4xl space-y-6">
        {playbookActions.length === 0 ? (
          <div className="border-2 border-border p-12 text-center bg-muted/20">
            <p className="text-muted-foreground uppercase tracking-widest font-bold">No High-Risk Actions Suggested</p>
            <p className="text-xs text-muted-foreground mt-2">Signatures and behavioral patterns did not trigger immediate remediation requirements.</p>
          </div>
        ) : (
          playbookActions.map((action) => (
            <div 
              key={action.id} 
              className={`border-2 transition-all duration-300 ${completed[action.id] ? 'opacity-40 grayscale border-border' : 'border-border bg-background'}`}
            >
              <div className="flex flex-col md:flex-row">
                {/* Priority Sidebar */}
                <div className={`w-full md:w-32 p-4 md:border-r-2 border-border flex md:flex-col justify-between items-center text-center ${PRIORITY_COLORS[action.priority] || 'text-muted-foreground border-border bg-muted/20'}`}>
                  <span className="text-[0.6rem] font-bold tracking-[0.2em] uppercase opacity-60">Priority</span>
                  <span className="text-sm font-bold tracking-tighter">{action.priority}</span>
                </div>

                {/* Content */}
                <div className="flex-1 p-6">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <span className="text-[0.6rem] font-bold tracking-widest text-accent uppercase bg-accent/10 px-2 py-0.5 mb-2 inline-block">
                        {action.category}
                      </span>
                      <h3 className="text-xl font-bold uppercase tracking-tight">{action.title}</h3>
                    </div>
                    <button 
                      onClick={() => toggleComplete(action.id)}
                      className={`w-8 h-8 border-2 flex items-center justify-center transition-all ${completed[action.id] ? 'bg-accent border-accent text-accent-foreground' : 'border-border hover:border-accent'}`}
                    >
                      {completed[action.id] ? '✓' : ''}
                    </button>
                  </div>
                  
                  <p className="text-muted-foreground text-sm leading-relaxed mb-6">
                    {action.desc}
                  </p>

                  {action.command && (
                    <div className="bg-muted p-4 border-l-4 border-accent group relative mb-2">
                       <p className="text-[0.6rem] font-bold text-muted-foreground uppercase tracking-widest mb-2">Suggested Command</p>
                       <code className="text-xs font-mono text-foreground break-all">{action.command}</code>
                       <button 
                        onClick={() => copyCommand(action.command)}
                        className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity bg-accent text-accent-foreground px-3 py-1 text-xs font-bold uppercase"
                       >
                         Copy
                       </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="mt-12 pt-8 border-t-2 border-border max-w-4xl">
        <h4 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-4">Proactive Security Best Practices</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 border border-border bg-muted/10">
            <p className="text-sm font-bold uppercase mb-1">Log Rotation & Integrity</p>
            <p className="text-xs text-muted-foreground">Ensure /var/log/apache2 logs are rotated daily and offloaded to a write-only WORM storage.</p>
          </div>
          <div className="p-4 border border-border bg-muted/10">
            <p className="text-sm font-bold uppercase mb-1">MFA Enforcement</p>
            <p className="text-xs text-muted-foreground">Enforce WebAuthn based MFA for all administrative endpoints to mitigate geo-velocity credential stuffing.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
