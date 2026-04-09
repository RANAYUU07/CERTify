import { useState, useEffect } from 'react'
import useCertifyStore from './store/certifyStore'
import NoiseTexture from './components/NoiseTexture'
import LogUploader from './components/LogUploader'
import DetectionResults from './components/DetectionResults'
import AttackMap from './components/AttackMap'
import AICopilot from './components/AICopilot'
import CERTInEvidence from './components/CERTInEvidence'
import ActionPlaybook from './components/ActionPlaybook'
import HumanConfirmation from './components/HumanConfirmation'
import ReportExporter from './components/ReportExporter'

const TABS = [
  { id: 'overview',  label: 'OVERVIEW' },
  { id: 'events',    label: 'EVENTS' },
  { id: 'map',       label: 'ATTACK MAP' },
  { id: 'copilot',   label: 'AI COPILOT' },
  { id: 'playbook',  label: 'PLAYBOOK' },
  { id: 'certin',    label: 'CERT-IN EVIDENCE' },
  { id: 'confirm',   label: 'CONFIRMATION' },
  { id: 'export',    label: 'EXPORT' },
]

function Toast({ toast }) {
  const [visible, setVisible] = useState(false)
  useEffect(() => { setVisible(true) }, [])
  return (
    <div
      className={`border-2 px-5 py-3 text-sm font-bold uppercase tracking-wider transition-all duration-300 ${
        visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
      } ${
        toast.type === 'error'
          ? 'bg-background border-severity-critical text-severity-critical'
          : 'bg-accent text-accent-foreground border-accent'
      }`}
    >
      {toast.message}
    </div>
  )
}

export default function App() {
  const { hasResults, isProcessing, activeTab, setActiveTab, reset, toasts, fileName, isDemoMode, apiKey, setApiKey } = useCertifyStore()
  const [showConfig, setShowConfig] = useState(false)
  const [showKey, setShowKey] = useState(false)

  const showLanding = !hasResults && !isProcessing

  const renderActiveTab = () => {
    if (activeTab === 'overview' || activeTab === 'events') {
      return <DetectionResults key="detection" />
    }
    if (activeTab === 'map')     return <AttackMap key="map" />
    if (activeTab === 'copilot') return <AICopilot key="copilot" />
    if (activeTab === 'playbook') return <ActionPlaybook key="playbook" />
    if (activeTab === 'certin')  return <CERTInEvidence key="certin" />
    if (activeTab === 'confirm') return <HumanConfirmation key="confirmation" />
    if (activeTab === 'export')  return <ReportExporter key="export" />
    return null
  }

  return (
    <div className="min-h-screen bg-background text-foreground font-sans">
      <NoiseTexture />

      {/* Navigation */}
      <nav
        className="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-sm border-b-2 border-border"
        role="navigation"
        aria-label="CERTify navigation"
      >
        <div className="flex items-center h-16 px-6 md:px-8">
          {/* Logo */}
          <button
            onClick={reset}
            className="text-2xl md:text-3xl font-bold uppercase tracking-tighter text-accent mr-6 flex-shrink-0 hover:opacity-80 transition-opacity"
            aria-label="CERTify — go to home"
          >
            CERTIFY
          </button>

          {/* Tab navigation — only when hasResults */}
          {hasResults && (
            <div className="flex-1 overflow-x-auto flex items-center border-l-2 border-border pl-6">
              <div className="flex items-center gap-0 flex-shrink-0">
                {TABS.map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`h-16 px-4 text-xs font-bold uppercase tracking-widest border-b-2 transition-all duration-200 whitespace-nowrap flex-shrink-0 ${
                      activeTab === tab.id
                        ? 'text-accent border-b-accent'
                        : 'text-muted-foreground hover:text-foreground border-b-transparent'
                    }`}
                    aria-current={activeTab === tab.id ? 'page' : undefined}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Right side */}
          <div className="ml-auto flex items-center gap-3 flex-shrink-0">
            {/* Config Button - Always Available */}
            <button
              onClick={() => setShowConfig(true)}
              className="border-2 border-border h-9 w-9 flex items-center justify-center text-foreground hover:bg-accent hover:border-accent hover:text-accent-foreground transition-all duration-200"
              aria-label="Configuration"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="square" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="square" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </button>

            {isDemoMode && (
              <span className="text-xs font-bold uppercase tracking-widest text-accent-foreground bg-accent px-3 py-1">
                DEMO
              </span>
            )}
            {hasResults && (
              <>
                <span className="text-xs text-muted-foreground uppercase tracking-wider hidden md:block">
                  {fileName}
                </span>
                
                <button
                  onClick={reset}
                  className="border-2 border-border h-9 px-4 text-xs font-bold uppercase tracking-widest text-foreground hover:bg-foreground hover:text-background transition-all duration-200"
                >
                  NEW ANALYSIS
                </button>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="pt-16">
        {(showLanding || isProcessing) && <LogUploader />}
        {hasResults && renderActiveTab()}
      </main>

      {/* Config Modal */}
      {showConfig && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-background/80 backdrop-blur-sm">
          <div className="bg-background border-2 border-border w-full max-w-md p-8 relative">
            <button 
              onClick={() => setShowConfig(false)}
              className="absolute top-4 right-4 text-muted-foreground hover:text-foreground"
            >
              ✕
            </button>
            <h3 className="text-2xl font-bold uppercase tracking-tighter mb-6">Configuration</h3>
            
            <div className="space-y-6">
              <div>
                <label className="block text-xs font-bold uppercase tracking-widest text-muted-foreground mb-2">AI API Key</label>
                <div className="relative">
                   <input
                    type={showKey ? 'text' : 'password'}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="sk-..."
                    className="w-full bg-background border-b-2 border-border focus:border-accent font-mono text-sm py-2 px-0 outline-none"
                  />
                  <button 
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-0 top-1/2 -translate-y-1/2 text-muted-foreground"
                  >
                    {showKey ? 'Hide' : 'Show'}
                  </button>
                </div>
                <p className="text-[0.6rem] text-muted-foreground mt-2 uppercase tracking-wider">Stored in-memory for current session only</p>
              </div>
              
              <button
                onClick={() => setShowConfig(false)}
                className="w-full bg-accent text-accent-foreground h-12 font-bold uppercase tracking-widest text-sm hover:scale-[1.02] active:scale-95 transition-all"
              >
                Save & Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast notifications */}
      <div className="fixed bottom-6 right-6 z-[100] flex flex-col gap-2 items-end">
        {toasts.map(toast => (
          <Toast key={toast.id} toast={toast} />
        ))}
      </div>
    </div>
  )
}
