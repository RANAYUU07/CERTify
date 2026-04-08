import { useState, useRef, useEffect } from 'react'
import useCertifyStore from '../store/certifyStore'

const QUICK_QUESTIONS = [
  'Which IP was most aggressive?',
  'Were there successful intrusions?',
  'What was the attack timeline?',
  'Which endpoints are most at risk?',
]

function LoadingDots() {
  return (
    <div className="flex items-center gap-2">
      {[0, 1, 2].map(i => (
        <div
          key={i}
          className="w-2 h-2 bg-accent"
          style={{ animation: `pulse 1s ease-in-out ${i * 0.2}s infinite` }}
        />
      ))}
    </div>
  )
}

export default function AICopilot() {
  const {
    copilotMessages, isCopilotLoading, sendCopilotMessage,
    attackNarrative, isGeneratingNarrative, generateNarrativeAction,
    apiKey, setApiKey, layer2JsonSummary, addToast,
  } = useCertifyStore()

  const [input, setInput] = useState('')
  const [narrativeCopied, setNarrativeCopied] = useState(false)
  const messagesEndRef = useRef(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [copilotMessages])

  const handleSend = async () => {
    const msg = input.trim()
    if (!msg || isCopilotLoading) return
    setInput('')
    await sendCopilotMessage(msg)
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const copyNarrative = () => {
    if (attackNarrative) {
      navigator.clipboard.writeText(attackNarrative)
      setNarrativeCopied(true)
      setTimeout(() => setNarrativeCopied(false), 2000)
      addToast('Narrative copied to clipboard', 'success')
    }
  }

  const hasEnvKey = Boolean(import.meta.env.VITE_ANTHROPIC_API_KEY)
  const showKeyHint = !hasEnvKey && !apiKey

  return (
    <div className="flex flex-col h-[calc(100vh-130px)] min-h-[600px]">
      {/* Header */}
      <div className="px-6 md:px-12 py-6 border-b-2 border-border flex-shrink-0">
        <h2 className="text-2xl md:text-4xl font-bold uppercase tracking-tighter">
          <span className="text-accent">AI</span> COPILOT
        </h2>
        <p className="text-muted-foreground text-sm mt-1">
          Powered by Claude — ask questions about your threat data
        </p>
      </div>

      {/* Key missing warning — discrete */}
      {showKeyHint && (
        <div className="px-6 md:px-12 py-2 bg-severity-high/10 border-b border-severity-high/20 flex justify-between items-center shrink-0">
          <p className="text-[0.6rem] font-bold text-severity-high uppercase tracking-widest">
            AI API Key not detected. Features disabled.
          </p>
          <p className="text-[0.6rem] text-muted-foreground uppercase tracking-tight">
            Configure key in the top-right settings icon
          </p>
        </div>
      )}

      <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
        {/* Chat panel */}
        <div className="flex-1 flex flex-col border-r border-border overflow-hidden">
          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-6 md:px-8 py-6 space-y-4">
            {copilotMessages.length === 0 && !isCopilotLoading && (
              <div className="flex flex-col items-center justify-center h-full text-center py-12">
                <div className="text-[6rem] md:text-[8rem] font-bold text-muted leading-none select-none mb-6" aria-hidden="true">
                  AI
                </div>
                <p className="text-lg text-muted-foreground max-w-md leading-relaxed">
                  Ask questions about detected threats, attacker patterns, geo-velocity anomalies, and generate CERT-In narratives.
                </p>
                {/* Quick questions */}
                <div className="flex flex-wrap gap-3 mt-8 justify-center">
                  {QUICK_QUESTIONS.map(q => (
                    <button
                      key={q}
                      onClick={() => setInput(q)}
                      className="border-2 border-border px-4 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground hover:border-accent transition-all duration-300 uppercase tracking-wider"
                    >
                      {q.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {copilotMessages.map((msg) => (
              <div
                key={msg.id}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[85%] ${
                    msg.role === 'user'
                      ? 'border-2 border-border bg-muted p-4'
                      : 'border-2 border-accent/30 bg-background border-l-4 border-l-accent p-4'
                  }`}
                >
                  {msg.role === 'assistant' && (
                    <p className="text-xs text-accent tracking-widest uppercase font-bold mb-2">CLAUDE</p>
                  )}
                  <p className="text-base text-foreground leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                  <p className="text-xs text-muted-foreground tracking-widest mt-2">
                    {new Date(msg.id).toLocaleTimeString()}
                  </p>
                </div>
              </div>
            ))}

            {isCopilotLoading && (
              <div className="flex justify-start">
                <div className="border-2 border-accent/30 bg-background border-l-4 border-l-accent p-4">
                  <p className="text-xs text-accent tracking-widest uppercase font-bold mb-3">CLAUDE</p>
                  <LoadingDots />
                  <p className="text-xs text-muted-foreground tracking-widest uppercase mt-3">ANALYZING...</p>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="border-t-2 border-border px-6 md:px-8 py-4 flex-shrink-0">
            {copilotMessages.length > 0 && (
              <div className="flex flex-wrap gap-2 mb-3">
                {QUICK_QUESTIONS.slice(0, 2).map(q => (
                  <button
                    key={q}
                    onClick={() => setInput(q)}
                    className="border border-border px-3 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-accent-foreground hover:border-accent transition-all duration-200 uppercase tracking-wider"
                  >
                    {q.toUpperCase().slice(0, 30)}{q.length > 30 ? '...' : ''}
                  </button>
                ))}
              </div>
            )}
            <div className="flex gap-3 items-end">
              <input
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about your threat data..."
                disabled={isCopilotLoading || (!apiKey && !hasEnvKey)}
                className="flex-1 bg-transparent border-b-2 border-border focus:border-accent text-foreground text-lg py-2 px-0 outline-none placeholder:text-muted disabled:opacity-40"
                id="copilot-input"
              />
              <button
                onClick={handleSend}
                disabled={!input.trim() || isCopilotLoading || (!apiKey && !hasEnvKey)}
                className="bg-accent text-accent-foreground h-12 px-6 font-bold uppercase tracking-tighter text-sm hover:scale-105 active:scale-95 transition-all duration-200 disabled:opacity-40 disabled:pointer-events-none"
              >
                SEND →
              </button>
            </div>
          </div>
        </div>

        {/* Narrative panel */}
        <div className="w-full md:w-80 lg:w-96 flex flex-col border-t-2 md:border-t-0 border-border overflow-y-auto">
          <div className="p-6 flex-1">
            <h3 className="text-sm uppercase tracking-widest text-muted-foreground font-bold mb-4 border-b border-border pb-3">
              ATTACK NARRATIVE
            </h3>
            <p className="text-xs text-muted-foreground mb-6 leading-relaxed">
              Generate a 2-3 paragraph prose narrative for use in the PDF report Executive Summary.
            </p>

            {!attackNarrative && !isGeneratingNarrative && (
              <button
                onClick={generateNarrativeAction}
                disabled={!layer2JsonSummary || (!apiKey && !hasEnvKey)}
                className="w-full bg-accent text-accent-foreground h-14 font-bold uppercase tracking-tighter text-base hover:scale-[1.02] active:scale-95 transition-all duration-200 disabled:opacity-40 disabled:pointer-events-none"
              >
                ⚡ GENERATE NARRATIVE
              </button>
            )}

            {isGeneratingNarrative && (
              <div className="text-center py-8">
                <LoadingDots />
                <p className="text-xs text-muted-foreground uppercase tracking-widest mt-4">GENERATING...</p>
              </div>
            )}

            {attackNarrative && (
              <div className="border-2 border-accent bg-accent/5 p-4 relative">
                <div className="flex justify-between items-center mb-3">
                  <p className="text-xs text-accent tracking-widest uppercase font-bold">GENERATED NARRATIVE</p>
                  <button
                    onClick={copyNarrative}
                    className={`border-2 h-8 px-3 text-xs font-bold uppercase tracking-widest transition-all duration-200 ${
                      narrativeCopied
                        ? 'bg-accent text-accent-foreground border-accent'
                        : 'border-border text-muted-foreground hover:bg-accent hover:text-accent-foreground hover:border-accent'
                    }`}
                  >
                    {narrativeCopied ? 'COPIED ✓' : 'COPY'}
                  </button>
                </div>
                <p className="text-sm text-foreground leading-relaxed">{attackNarrative}</p>

                <button
                  onClick={generateNarrativeAction}
                  disabled={isGeneratingNarrative}
                  className="mt-4 w-full border-2 border-border h-10 text-xs font-bold uppercase tracking-widest text-muted-foreground hover:bg-foreground hover:text-background transition-all duration-200"
                >
                  REGENERATE
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
