/**
 * Layer 3 — General AI Copilot (Claude API)
 * Conversational Q&A and attack narrative generation for PDF reports.
 */

const NARRATIVE_SYSTEM_PROMPT = `You are a cybersecurity analyst generating an incident narrative for a CERT-In report.
Given the structured attack data, write a coherent 2-3 paragraph narrative that:
1. Describes the timeline and sequence of events
2. Groups related attacks (e.g., recon followed by exploitation attempts)
3. Assesses attacker intent and sophistication
4. Notes if multiple distinct threat actors appear to be present

Use professional, technical language appropriate for a CERT-In incident report.
Do NOT use bullet points. Write in prose paragraphs only.
Keep it concise — 150-250 words total.`

const COPILOT_SYSTEM_PROMPT = (layer2Json) => `You are CERTify's AI Security Copilot analyzing a cyber incident.

You have access to the following incident data:
${JSON.stringify(layer2Json, null, 2).slice(0, 8000)}

Answer questions about this specific incident. Be concise, factual, and technically precise.
Reference specific IPs, timestamps, endpoints, and attack types from the data.
If asked about something not in the data, say so clearly.`

/**
 * Generate a prose attack narrative for the PDF report (Executive Summary)
 * @param {object} layer2Json - structured detection summary
 * @param {string} apiKey - optional direct API key
 * @returns {string} 2-3 paragraph narrative
 */
export async function generateAttackNarrative(layer2Json, apiKey = null) {
  try {
    const headers = {
      'Content-Type': 'application/json',
      'anthropic-version': '2023-06-01',
    }
    if (apiKey) headers['x-api-key'] = apiKey

    const body = {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      messages: [
        {
          role: 'user',
          content: `Generate an incident narrative for this attack data:\n${JSON.stringify(layer2Json)}`,
        },
      ],
      system: NARRATIVE_SYSTEM_PROMPT,
    }

    const endpoint = apiKey ? 'https://api.anthropic.com/v1/messages' : '/api/claude'
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    })

    if (!response.ok) throw new Error(`API error: ${response.status}`)
    const data = await response.json()
    return data.content?.[0]?.text || generateFallbackNarrative(layer2Json)
  } catch (err) {
    console.error('Narrative generation failed:', err)
    return generateFallbackNarrative(layer2Json)
  }
}

/**
 * Q&A Copilot — answer questions about the detected threats
 * @param {Array} messages - conversation history [{ role, content }]
 * @param {object} layer2Json - detection context
 * @param {string} apiKey - optional direct API key
 * @returns {string} AI response
 */
export async function chatWithCopilot(messages, layer2Json, apiKey = null) {
  const headers = {
    'Content-Type': 'application/json',
    'anthropic-version': '2023-06-01',
  }
  if (apiKey) headers['x-api-key'] = apiKey

  const body = {
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1024,
    system: COPILOT_SYSTEM_PROMPT(layer2Json),
    messages: messages.map(m => ({ role: m.role, content: m.content })),
  }

  const endpoint = apiKey ? 'https://api.anthropic.com/v1/messages' : '/api/claude'
  const response = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const err = await response.text()
    throw new Error(`Claude API error ${response.status}: ${err}`)
  }

  const data = await response.json()
  return data.content?.[0]?.text || 'Unable to generate response.'
}

/**
 * Fallback narrative when Claude API is unavailable
 * Generated from structured data — ensures demo never breaks
 */
function generateFallbackNarrative(layer2Json) {
  const { analysisWindow, totalRequestsAnalyzed, severityBreakdown, detectedEvents, ipRotationSummary } = layer2Json
  const topTypes = [...new Set(detectedEvents.slice(0, 10).map(e => e.type))].slice(0, 3)
  const startTime = analysisWindow?.start ? new Date(analysisWindow.start).toUTCString() : 'unknown time'

  return `Beginning at ${startTime}, the monitored infrastructure experienced a sustained multi-vector cyberattack campaign. Analysis of ${totalRequestsAnalyzed?.toLocaleString() || 'multiple'} HTTP requests revealed ${severityBreakdown?.CRITICAL || 0} critical and ${severityBreakdown?.HIGH || 0} high-severity events, with attack patterns including ${topTypes.join(', ').toLowerCase() || 'signature-based attacks'}.

The attack exhibited characteristics of organized threat activity, with ${ipRotationSummary?.uniqueAttackingIPs || 'multiple'} unique source IP addresses involved. An IP diversity rate of ${((ipRotationSummary?.ipDiversityRate || 0) * 100).toFixed(1)}% on targeted endpoints indicates distributed attack infrastructure rather than a single actor, with ${ipRotationSummary?.anonymizedIPCount || 0} IPs identified as using anonymization services (proxy, hosting, or Tor).

Immediate containment measures are recommended, including blocking identified source IP ranges at the network perimeter, patching identified vulnerable endpoints, and filing a formal report with CERT-In within the mandatory 6-hour reporting window as required under the IT Amendment Rules 2022.`
}
