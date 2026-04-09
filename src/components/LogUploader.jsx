import { useCallback, useRef, useState, useEffect } from 'react'
import useCertifyStore from '../store/certifyStore'

const MARQUEE_ITEMS = [
  '3-LAYER DETECTION', 'CERT-IN COMPLIANT', 'ZERO BACKEND',
  'MITRE ATT&CK MAPPED', 'GEO-VELOCITY ANALYSIS', 'AI-POWERED NARRATIVES',
  'ZERO DATA LEAVES BROWSER', 'APACHE + NGINX SUPPORT', 'INSTANT PDF REPORTS',
]

const PROCESSING_STEPS = [
  'PARSING LOGS',
  'RUNNING SIGNATURE DETECTION',
  'BEHAVIORAL ANALYSIS',
  'FETCHING GEO DATA',
  'DETECTING IP ROTATION',
  'BUILDING EVIDENCE SUMMARY',
]

function FadeIn({ children, className = '', delay = 0 }) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), delay)
    return () => clearTimeout(timer)
  }, [delay])
  return (
    <div
      className={`transition-all duration-500 ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'} ${className}`}
    >
      {children}
    </div>
  )
}

export default function LogUploader() {
  const { isProcessing, processingStep, processingStepIndex, geoEnrichmentProgress, processLogs, loadDemoData } = useCertifyStore()
  const fileInputRef = useRef(null)

  const handleFile = useCallback(async (file) => {
    if (!file) return
    await processLogs(file, false)
  }, [processLogs])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const handleDragOver = (e) => {
    e.preventDefault()
  }

  if (isProcessing) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4 py-16">
        {/* Background decorative step number */}
        <div
          className="absolute inset-0 flex items-center justify-center pointer-events-none select-none overflow-hidden"
          aria-hidden="true"
        >
          <span className="text-[20rem] font-bold text-muted leading-none opacity-30">
            {processingStepIndex + 1}
          </span>
        </div>

        <div className="relative z-10 text-center max-w-2xl w-full">
          {/* Step label */}
          <FadeIn key={processingStepIndex}>
            <p className="text-xs tracking-widest text-muted-foreground uppercase mb-6">
              STEP {processingStepIndex + 1} OF {PROCESSING_STEPS.length}
            </p>
            <h2 className="text-3xl md:text-5xl font-bold uppercase tracking-tighter text-accent leading-none mb-4">
              {PROCESSING_STEPS[processingStepIndex]}
            </h2>
            {processingStep && processingStep !== PROCESSING_STEPS[processingStepIndex] && (
              <p className="text-muted-foreground font-mono text-sm mt-2">{processingStep}</p>
            )}
          </FadeIn>

          {/* Progress bar */}
          <div className="mt-12 w-full">
            <div className="h-0.5 bg-border w-full">
              <div
                className="h-full bg-accent transition-all duration-500"
                style={{ width: `${((processingStepIndex + 1) / PROCESSING_STEPS.length) * 100}%` }}
              />
            </div>
            <div className="flex justify-between mt-3">
              {PROCESSING_STEPS.map((step, i) => (
                <div
                  key={step}
                  className={`w-2 h-2 border-2 transition-all duration-300 ${
                    i <= processingStepIndex
                      ? 'bg-accent border-accent'
                      : 'bg-background border-border'
                  }`}
                />
              ))}
            </div>
          </div>

          {/* Geo sub-progress */}
          {processingStepIndex === 3 && (
            <div className="mt-8">
              <div className="h-0.5 bg-border w-full">
                <div
                  className="h-full bg-accent/60 transition-all duration-300"
                  style={{ width: `${geoEnrichmentProgress}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground tracking-widest mt-2 uppercase">
                Geo enrichment {geoEnrichmentProgress}%
              </p>
            </div>
          )}

          {/* Scanning animation dots */}
          <div className="flex gap-2 justify-center mt-12">
            {[0, 1, 2].map(i => (
              <div
                key={i}
                className="w-3 h-3 bg-accent animate-pulse"
                style={{ animationDelay: `${i * 200}ms` }}
              />
            ))}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Hero section */}
      <section className="relative min-h-screen flex flex-col justify-center items-center text-center px-6 md:px-12 pt-24 pb-16 overflow-hidden">
        <FadeIn className="relative z-10 w-full">
          <div className="max-w-6xl mx-auto">
            <FadeIn>
              <h1 className="font-bold uppercase tracking-tighter leading-[0.90] mb-3 text-[clamp(4.90rem,13vw,12.5rem)]">
                <span className="text-foreground block">CERTIFY</span>
                <span className="text-accent block">THREAT</span>
                <span className="text-foreground block">ANALYZER</span>
              </h1>
            </FadeIn>

            <FadeIn delay={200}>
              <p className="text-2xl md:text-2.9xl text-muted-foreground max-w-3xl mx-auto leading-tight mt-7">
                Zero-backend cyberattack detection. Upload Apache or Nginx logs, detect threats across 3 analysis layers, and generate CERT-In compliant incident reports — entirely in your browser. No data leaves your device.
              </p>
            </FadeIn>
          </div>

          {/* Stats row */}
          <FadeIn
            delay={400}
            className="w-full flex items-start justify-between mt-12 border-t-2 border-border pt-10 px-4 sm:px-10 md:px-20 lg:px-32"
          >
            {[
              { num: '3', label: 'Detection Layers' },
              { num: '15+', label: 'Attack Signatures' },
              { num: '100%', label: 'Browser Only' },
              { num: '0', label: 'Data Leaves Device' },
            ].map(({ num, label }) => (
              <div key={label} className="text-center flex-1 min-w-0">
                <div className="text-4xl md:text-5xl font-bold text-accent">{num}</div>
                <div className="text-sm tracking-widest text-muted-foreground uppercase mt-2">{label}</div>
              </div>
            ))}
          </FadeIn>
        </FadeIn>
      </section>

      {/* Marquee — features strip */}
      <div className="border-y-2 border-border overflow-hidden bg-accent shrink-0">
        <div className="animate-marquee h-36 items-center">
          {[...MARQUEE_ITEMS, ...MARQUEE_ITEMS].map((item, idx) => (
            <span
              key={idx}
              className="inline-flex items-center gap-4 px-12 text-2xl md:text-3xl font-extrabold tracking-widest uppercase text-accent-foreground"
            >
              {item}
              <span className="text-black/40 mx-4">·</span>
            </span>
          ))}
        </div>
      </div>

      {/* Upload zone */}
      <section className="px-6 md:px-12 py-20">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-display font-bold uppercase tracking-tighter leading-none mb-12 text-center">
            UPLOAD YOUR<br />
            <span className="text-accent">LOG FILE</span>
          </h2>

          {/* Drop zone */}
          <div
            className="border-2 border-dashed border-border hover:border-accent hover:bg-accent/5 transition-all duration-300 p-12 md:p-20 text-center cursor-pointer group"
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onClick={() => fileInputRef.current?.click()}
            role="button"
            tabIndex={0}
            aria-label="Drop log file here or click to browse"
            onKeyDown={(e) => e.key === 'Enter' && fileInputRef.current?.click()}
          >
            {/* Shield icon */}
            <div className="flex justify-center mb-8">
              <svg
                className="w-16 h-16 md:w-24 md:h-24 text-muted group-hover:text-accent transition-colors duration-300"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="square"
                  strokeLinejoin="miter"
                  strokeWidth={1.5}
                  d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                />
              </svg>
            </div>

            <p className="text-2xl md:text-4xl font-bold uppercase tracking-tighter text-foreground group-hover:text-accent transition-colors duration-300 mb-4">
              DROP YOUR LOG FILE
            </p>
            <p className="text-muted-foreground text-base md:text-lg mb-8">
              Apache Combined Log Format or Nginx default format
            </p>
            <p className="text-muted-foreground text-sm tracking-widest uppercase">.log · .txt · any text format</p>

            <div className="mt-10">
              <button
                onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click() }}
                className="border-2 border-border h-14 px-8 uppercase tracking-tighter font-bold text-foreground hover:bg-foreground hover:text-background transition-all duration-300"
              >
                Browse Files
              </button>
            </div>

            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.access"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) handleFile(file)
              }}
            />
          </div>

          {/* Demo Mode */}
          <div className="mt-8 text-center">
            <p className="text-muted-foreground text-sm uppercase tracking-widest mb-4">— OR —</p>
            <button
              onClick={loadDemoData}
              className="bg-accent text-accent-foreground h-16 px-12 text-xl font-bold uppercase tracking-tighter hover:scale-105 active:scale-95 transition-all duration-300 w-full md:w-auto"
            >
              ⚡ LAUNCH DEMO MODE
            </button>
            <p className="text-xs text-muted-foreground uppercase tracking-widest mt-3">
              Loads realistic sample attack logs — no file needed
            </p>
          </div>
        </div>
      </section>

      {/* Info cards */}
      <section className="border-t-2 border-border">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border">
          {[
            {
              num: '01',
              title: 'SIGNATURE DETECTION',
              desc: 'SQL injection, XSS, path traversal, command injection, and malicious scanner detection using 50+ regex patterns.',
            },
            {
              num: '02',
              title: 'BEHAVIORAL ANALYSIS',
              desc: '7 behavioral checks including IP diversity rate, burst detection, sequential scanning, and temporal grouping.',
            },
            {
              num: '03',
              title: 'GEO-VELOCITY',
              desc: 'Haversine-formula based impossible travel detection. Mumbai → Moscow in 2 seconds = physically impossible.',
            },
          ].map(({ num, title, desc }) => (
            <div
              key={num}
              className="bg-background p-8 md:p-12 group cursor-default hover:bg-accent transition-all duration-300"
            >
              <div className="text-[4rem] md:text-[6rem] font-bold text-muted leading-none group-hover:text-accent-foreground/20 transition-colors duration-300 select-none" aria-hidden="true">
                {num}
              </div>
              <h3 className="text-xl font-bold uppercase tracking-tighter mt-4 mb-3 text-foreground group-hover:text-accent-foreground transition-colors duration-300">
                {title}
              </h3>
              <p className="text-muted-foreground text-base leading-relaxed group-hover:text-accent-foreground/80 transition-colors duration-300">
                {desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Footer CTA */}
      <footer className="border-t-2 border-border bg-accent text-black min-h-screen flex items-center">
        <div className="w-full px-6 md:px-12 py-20 md:py-28">
          <div className="max-w-6xl ml-0 mr-auto">
            <h2 className="font-black uppercase tracking-tighter leading-[0.90] text-[clamp(4.90rem,13vw,12.5rem)]">
              READY TO<br />
              TRANSFORM<br />
              YOUR<br />
              WORKFLOW?
            </h2>

            <div className="mt-10 max-w-xl">
              <label className="block text-sm font-bold uppercase tracking-widest text-black/70 mb-3">
                Email address
              </label>
              <input
                type="email"
                inputMode="email"
                placeholder=""
                className="w-full bg-transparent border-b-2 border-black/70 focus:border-black outline-none py-3 text-lg placeholder:text-black/50"
                aria-label="Email address"
              />
            </div>
          </div>

          {/* Footer links (centered block) */}
          <div className="max-w-8xl mx-auto w-full">
            <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-20 md:gap-32 text-lg">
              <div>
                <div className="text-sm font-black uppercase tracking-widest text-black/70 mb-4">Product</div>
                <ul className="space-y-2 font-black uppercase tracking-wide">
                  <li>Features</li>
                  <li>Pricing</li>
                  <li>Security</li>
                  <li>Integrations</li>
                  <li>Changelog</li>
                </ul>
              </div>

              <div>
                <div className="text-sm font-black uppercase tracking-widest text-black/70 mb-4">Company</div>
                <ul className="space-y-2 font-black uppercase tracking-wide">
                  <li>About</li>
                  <li>Blog</li>
                  <li>Careers</li>
                  <li>Contact</li>
                </ul>
              </div>

              <div>
                <div className="text-sm font-black uppercase tracking-widest text-black/70 mb-4">Resources</div>
                <ul className="space-y-2 font-black uppercase tracking-wide">
                  <li>Documentation</li>
                  <li>Help Center</li>
                  <li>API Reference</li>
                  <li>Community</li>
                </ul>
              </div>

              <div>
                <div className="text-sm font-black uppercase tracking-widest text-black/70 mb-4">Legal</div>
                <ul className="space-y-2 font-black uppercase tracking-wide">
                  <li>Privacy Policy</li>
                  <li>Terms of Service</li>
                  <li>Cookie Policy</li>
                  <li>GDPR</li>
                </ul>
              </div>
            </div>

            <div className="mt-14 border-t border-black/30" />

            <div className="pt-6 flex items-center justify-between text-[0.7rem] font-bold uppercase tracking-widest text-black/70">
              <span>© 2026 CERTIFY. All rights reserved.</span>
              <span className="text-black/80">CERTIFY</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
