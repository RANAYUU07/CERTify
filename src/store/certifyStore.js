import { create } from 'zustand'
import { parseLogFile, getUniqueIPs } from '../engine/logParser.js'
import { runLayer1 } from '../engine/layer1_signatures.js'
import { runLayer2Behavioral, getMaxIPDiversityRate } from '../engine/layer2_behavioral.js'
import { enrichGeoData } from '../engine/layer2_geo.js'
import { runLayer2Rotation } from '../engine/layer2_rotation.js'
import { buildLayer2Json } from '../engine/layer2_jsonBuilder.js'
import { getMitreSummary } from '../utils/mitreMapping.js'
import { generateCERTInEvidence } from '../engine/layer3_certinEvidence.js'
import { generateAttackNarrative, chatWithCopilot } from '../engine/layer3_ai.js'
import { generateCERTInReport } from '../utils/reportGenerator.js'
import { clearGeoCache } from '../utils/geoCache.js'
import { SAMPLE_LOG, SAMPLE_FILENAME } from '../constants/sampleLog.js'
import { MOCK_GEO_DATA } from '../constants/mockGeoData.js'

const useCertifyStore = create((set, get) => ({
  // ─── Input ────────────────────────────────────────
  rawLogs: [],
  fileName: '',
  isDemoMode: false,

  // ─── Detection Results ────────────────────────────
  layer1Results: [],
  layer2Results: [],       // behavioral + rotation combined
  layer2JsonSummary: null,
  geoData: {},
  mitreMappings: [],
  ipDiversityRate: 0,
  parseWarnings: [],
  playbookActions: [],
  confirmedFindings: {}, // { eventId: boolean }

  // ─── UI State ─────────────────────────────────────
  isProcessing: false,
  processingStep: '',
  processingStepIndex: 0,
  geoEnrichmentProgress: 0,
  geoLimited: false,
  hasResults: false,
  activeTab: 'overview',
  toasts: [],

  // ─── AI ──────────────────────────────────────────
  attackNarrative: '',
  certInEvidence: null,
  isGeneratingEvidence: false,
  isGeneratingNarrative: false,
  copilotMessages: [],
  isCopilotLoading: false,
  apiKey: import.meta.env.VITE_ANTHROPIC_API_KEY || '',

  // ─── Actions ─────────────────────────────────────

  setApiKey: (key) => set({ apiKey: key }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  toggleFindingConfirmation: (id) => set(state => ({
    confirmedFindings: {
      ...state.confirmedFindings,
      [id]: !state.confirmedFindings[id]
    }
  })),

  addToast: (message, type = 'success') => {
    const id = Date.now()
    set(state => ({ toasts: [...state.toasts, { id, message, type }] }))
    setTimeout(() => {
      set(state => ({ toasts: state.toasts.filter(t => t.id !== id) }))
    }, 3000)
  },

  reset: () => {
    clearGeoCache()
    set({
      rawLogs: [], fileName: '', isDemoMode: false,
      layer1Results: [], layer2Results: [], layer2JsonSummary: null,
      geoData: {}, mitreMappings: [], ipDiversityRate: 0, parseWarnings: [],
      isProcessing: false, processingStep: '', processingStepIndex: 0,
      geoEnrichmentProgress: 0, geoLimited: false, hasResults: false,
      activeTab: 'overview',
      attackNarrative: '', certInEvidence: null,
      isGeneratingEvidence: false, isGeneratingNarrative: false,
      copilotMessages: [], isCopilotLoading: false,
      playbookActions: [], confirmedFindings: {},
    })
  },

  loadDemoData: async () => {
    await get().processLogs(null, true)
  },

  processLogs: async (file, isDemoMode = false) => {
    const STEPS = [
      'Parsing logs...',
      'Running signature detection...',
      'Behavioral analysis...',
      `Fetching geo data...`,
      'Detecting IP rotation patterns...',
      'Building evidence summary...',
    ]

    set({
      isProcessing: true, hasResults: false, isDemoMode,
      processingStep: STEPS[0], processingStepIndex: 0,
      layer1Results: [], layer2Results: [], geoData: {},
      certInEvidence: null, attackNarrative: '', copilotMessages: [],
    })

    try {
      // ── Step 1: Parse logs ──
      let content
      let fileName
      if (isDemoMode) {
        content = SAMPLE_LOG
        fileName = SAMPLE_FILENAME
      } else {
        content = await file.text()
        fileName = file.name
      }

      const { entries: rawLogs, warnings, malformedCount } = parseLogFile(content)
      set({ rawLogs, fileName, parseWarnings: warnings, processingStep: STEPS[1], processingStepIndex: 1 })

      await tick()

      // ── Step 2: Layer 1 — Signatures ──
      const layer1Results = runLayer1(rawLogs)
      set({ layer1Results, processingStep: STEPS[2], processingStepIndex: 2 })

      await tick()

      // ── Step 3: Layer 2 Phase 1 — Behavioral ──
      const behavioralResults = runLayer2Behavioral(rawLogs, layer1Results)
      const ipDiversityRate = getMaxIPDiversityRate(behavioralResults)
      set({ ipDiversityRate })

      // ── Step 4: Layer 2 Phase 2 — Geo enrichment ──
      const uniqueIPs = getUniqueIPs(rawLogs)
      set({
        processingStep: `Fetching geo data... (0/${Math.min(uniqueIPs.length, 900)} IPs)`,
        processingStepIndex: 3,
      })

      const { geoData, limited } = await enrichGeoData(
        uniqueIPs,
        (current, total) => {
          set({
            geoEnrichmentProgress: Math.round((current / total) * 100),
            processingStep: `Fetching geo data... (${current}/${total} IPs)`,
          })
        },
        isDemoMode,
        isDemoMode ? MOCK_GEO_DATA : {}
      )

      set({ geoData, geoLimited: limited, processingStep: STEPS[4], processingStepIndex: 4 })

      await tick()

      // ── Step 5: Layer 2 Phase 3 — Rotation ──
      const rotationResults = runLayer2Rotation(layer1Results, behavioralResults, geoData)
      const layer2Results = [...behavioralResults, ...rotationResults]
      const mitreMappings = getMitreSummary([...layer1Results, ...layer2Results])

      set({ layer2Results, mitreMappings, processingStep: STEPS[5], processingStepIndex: 5 })

      await tick()

      // ── Step 6: Build JSON summary ──
      const forensicSummary = buildLayer2Json(rawLogs, layer1Results, layer2Results, geoData)

      // ── Step 7: Generate Playbook ──
      const playbookActions = generatePlaybook(layer1Results, layer2Results)

      set({
        layer2JsonSummary: forensicSummary,
        playbookActions,
        isProcessing: false,
        hasResults: true,
        processingStep: '',
        activeTab: 'overview',
      })
    } catch (err) {
      console.error('Processing failed:', err)
      set({
        isProcessing: false,
        processingStep: '',
      })
      get().addToast(`Processing error: ${err.message}`, 'error')
    }
  },

  generateCERTInEvidenceAction: async () => {
    const { layer2JsonSummary, apiKey } = get()
    if (!layer2JsonSummary) return

    set({ isGeneratingEvidence: true, certInEvidence: null })
    try {
      const evidence = await generateCERTInEvidence(layer2JsonSummary, apiKey || null)
      set({ certInEvidence: evidence, isGeneratingEvidence: false })
    } catch (err) {
      set({ isGeneratingEvidence: false })
      get().addToast(`Evidence generation failed: ${err.message}`, 'error')
    }
  },

  generateNarrativeAction: async () => {
    const { layer2JsonSummary, apiKey } = get()
    if (!layer2JsonSummary) return

    set({ isGeneratingNarrative: true })
    try {
      const narrative = await generateAttackNarrative(layer2JsonSummary, apiKey || null)
      set({ attackNarrative: narrative, isGeneratingNarrative: false })
    } catch (err) {
      set({ isGeneratingNarrative: false })
      get().addToast(`Narrative generation failed: ${err.message}`, 'error')
    }
  },

  sendCopilotMessage: async (userMessage) => {
    const { copilotMessages, layer2JsonSummary, apiKey } = get()
    if (!layer2JsonSummary) return

    const newMessages = [...copilotMessages, { role: 'user', content: userMessage, id: Date.now() }]
    set({ copilotMessages: newMessages, isCopilotLoading: true })

    try {
      const apiMessages = newMessages.map(m => ({ role: m.role, content: m.content }))
      const response = await chatWithCopilot(apiMessages, layer2JsonSummary, apiKey || null)
      set(state => ({
        copilotMessages: [
          ...state.copilotMessages,
          { role: 'assistant', content: response, id: Date.now() + 1 },
        ],
        isCopilotLoading: false,
      }))
    } catch (err) {
      set({ isCopilotLoading: false })
      get().addToast(`Copilot error: ${err.message}`, 'error')
    }
  },

  exportReport: (orgName) => {
    const {
      mitreMappings, attackNarrative, layer2JsonSummary, fileName, confirmedFindings,
      rawLogs, layer1Results, layer2Results, geoData
    } = get()

    try {
      const incidentId = generateCERTInReport({
        orgName,
        fileName,
        parsedLogs: rawLogs,
        layer1Results,
        layer2Results,
        geoData,
        mitreSummary: mitreMappings,
        attackNarrative,
        layer2JsonSummary,
        confirmedFindings,
      })
      get().addToast(`Report downloaded: ${incidentId}`, 'success')
      return incidentId
    } catch (err) {
      get().addToast(`Export failed: ${err.message}`, 'error')
      return null
    }
  },
}))

// Helper: yield to browser event loop between expensive steps
function tick() {
  return new Promise(resolve => setTimeout(resolve, 50))
}

// Helper: generate suggested actions based on threats
function generatePlaybook(layer1, layer2) {
  const actions = []
  const types = new Set([...layer1.map(e => e.type), ...layer2.map(e => e.type)])
  const criticalIPs = new Set([
    ...layer1.filter(e => e.severity === 'CRITICAL').map(e => e.ip),
    ...layer2.filter(e => e.severity === 'CRITICAL').map(e => e.involvedIPs).flat().filter(Boolean)
  ])

  // Network Priority
  if (criticalIPs.size > 0) {
    actions.push({
      id: 'block-ips',
      category: 'NETWORK',
      title: 'Block Critical Attacker IPs',
      desc: `Immediately null-route or block the following high-risk IPs at the firewall: ${Array.from(criticalIPs).slice(0, 5).join(', ')}${criticalIPs.size > 5 ? '...' : ''}`,
      command: `iptables -A INPUT -s ${Array.from(criticalIPs)[0]} -j DROP`,
      priority: 'CRITICAL'
    })
  }

  // Application Priority
  if (types.has('SQL_INJECTION')) {
    actions.push({
      id: 'patch-sqli',
      category: 'APPLICATION',
      title: 'Parameterized Query Enforcement',
      desc: 'Significant SQL injection attempts detected. Audit data-access layer to ensure all queries use prepared statements.',
      priority: 'HIGH'
    })
  }

  if (types.has('XSS')) {
    actions.push({
      id: 'patch-xss',
      category: 'APPLICATION',
      title: 'Implement Content Security Policy (CSP)',
      desc: 'Cross-site scripting attempts detected. Deploy a strict CSP header and ensure output encoding on all reflected parameters.',
      priority: 'HIGH'
    })
  }

  // Monitoring Priority
  if (types.has('GEO_VELOCITY_ANOMALY')) {
    actions.push({
      id: 'monitor-geo',
      category: 'MONITORING',
      title: 'Impossible Travel Monitoring',
      desc: 'Account takeover signature detected via geo-velocity anomalies. Enable multi-factor authentication (MFA) for all administrative users.',
      priority: 'CRITICAL'
    })
  }

  return actions
}

export default useCertifyStore
