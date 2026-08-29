/**
 * Layer 3 — General AI Copilot (Groq API)
 * Conversational Q&A and attack narrative generation for PDF reports.
 */

const GROQ_MODEL = "openai/gpt-oss-120b";

/**
 * Trim a layer2Json summary down to a token-friendly size before sending to the AI.
 * Groq's free tier caps at 8,000 TPM for gpt-oss models, so large logs can blow
 * past that if we send every detected event verbatim. This keeps the most
 * relevant, highest-severity events and truncates long text fields.
 *
 * @param {object} layer2Json - full structured detection summary
 * @param {number} maxEvents - max number of individual events to include
 * @returns {object} slimmed copy safe to JSON.stringify and send to the model
 */
export function slimLayer2JsonForAI(layer2Json, maxEvents = 25) {
  const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  const trimmedEvents = [...(layer2Json.detectedEvents || [])]
    .sort(
      (a, b) =>
        (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9),
    )
    .slice(0, maxEvents)
    .map((e) => ({
      timestamp: e.timestamp,
      type: e.type,
      severity: e.severity,
      sourceIP: e.sourceIP,
      targetPath: e.targetPath,
      // Truncate long evidence strings — full payloads aren't needed for narrative/report text
      evidence:
        typeof e.evidence === "string" ? e.evidence.slice(0, 120) : e.evidence,
      country: e.geoInfo?.country,
      proxy: e.geoInfo?.proxy || e.geoInfo?.hosting || e.geoInfo?.tor || false,
      mitreId: e.mitreId,
    }));

  return {
    analysisWindow: layer2Json.analysisWindow,
    totalRequestsAnalyzed: layer2Json.totalRequestsAnalyzed,
    uniqueSourceIPs: layer2Json.uniqueSourceIPs,
    affectedEndpoints: (layer2Json.affectedEndpoints || []).slice(0, 10),
    severityBreakdown: layer2Json.severityBreakdown,
    detectedEvents: trimmedEvents,
    detectedEventsTruncated:
      (layer2Json.detectedEvents || []).length > maxEvents,
    topAttackers: (layer2Json.topAttackers || []).slice(0, 5),
    ipRotationSummary: layer2Json.ipRotationSummary,
    geoVelocityAnomalies: (layer2Json.geoVelocityAnomalies || []).slice(0, 5),
    mitreTechniquesSummary: layer2Json.mitreTechniquesSummary,
  };
}

const NARRATIVE_SYSTEM_PROMPT = `You are a cybersecurity analyst generating an incident narrative for a CERT-In report.
Given the structured attack data, write a coherent 2-3 paragraph narrative that:
1. Describes the timeline and sequence of events
2. Groups related attacks (e.g., recon followed by exploitation attempts)
3. Assesses attacker intent and sophistication
4. Notes if multiple distinct threat actors appear to be present

Use professional, technical language appropriate for a CERT-In incident report.
Do NOT use bullet points. Write in prose paragraphs only.
Keep it concise — 150-250 words total.`;

const COPILOT_SYSTEM_PROMPT = (
  layer2Json,
) => `You are CERTify's AI Security Copilot analyzing a cyber incident.

You have access to the following incident data (top events by severity — some lower-priority events may be omitted for brevity):
${JSON.stringify(slimLayer2JsonForAI(layer2Json))}

Answer questions about this specific incident. Be concise, factual, and technically precise.
Reference specific IPs, timestamps, endpoints, and attack types from the data.
If asked about something not in the data, say so clearly.`;

/**
 * Generate a prose attack narrative for the PDF report (Executive Summary)
 * @param {object} layer2Json - structured detection summary
 * @param {string} apiKey - optional direct API key
 * @returns {string} 2-3 paragraph narrative
 */
export async function generateAttackNarrative(layer2Json, apiKey = null) {
  try {
    const slimmed = slimLayer2JsonForAI(layer2Json);
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

    const body = {
      model: GROQ_MODEL,
      max_tokens: 1024,
      messages: [
        { role: "system", content: NARRATIVE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Generate an incident narrative for this attack data:\n${JSON.stringify(slimmed)}`,
        },
      ],
    };

    const endpoint = apiKey
      ? "https://api.groq.com/openai/v1/chat/completions"
      : "/api/groq";

    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) throw new Error(`API error: ${response.status}`);
    const data = await response.json();
    return (
      data.choices?.[0]?.message?.content ||
      generateFallbackNarrative(layer2Json)
    );
  } catch (err) {
    console.error("Narrative generation failed:", err);
    return generateFallbackNarrative(layer2Json);
  }
}

/**
 * Q&A Copilot — answer questions about the detected threats
 * @param {Array} messages - conversation history [{ role, content }] (role: 'user' | 'assistant')
 * @param {object} layer2Json - detection context
 * @param {string} apiKey - optional direct API key
 * @returns {string} AI response
 */
export async function chatWithCopilot(messages, layer2Json, apiKey = null) {
  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  const body = {
    model: GROQ_MODEL,
    max_tokens: 1024,
    messages: [
      { role: "system", content: COPILOT_SYSTEM_PROMPT(layer2Json) },
      // Groq/OpenAI format already uses 'user' / 'assistant' — no role mapping needed
      ...messages.map((m) => ({ role: m.role, content: m.content })),
    ],
  };

  const endpoint = apiKey
    ? "https://api.groq.com/openai/v1/chat/completions"
    : "/api/groq";

  const response = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Groq API error ${response.status}: ${err}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || "Unable to generate response.";
}

/**
 * Fallback narrative when Groq API is unavailable
 * Generated from structured data — ensures demo never breaks
 */
function generateFallbackNarrative(layer2Json) {
  const {
    analysisWindow,
    totalRequestsAnalyzed,
    severityBreakdown,
    detectedEvents,
    ipRotationSummary,
  } = layer2Json;
  const topTypes = [
    ...new Set(detectedEvents.slice(0, 10).map((e) => e.type)),
  ].slice(0, 3);
  const startTime = analysisWindow?.start
    ? new Date(analysisWindow.start).toUTCString()
    : "unknown time";

  return `Beginning at ${startTime}, the monitored infrastructure experienced a sustained multi-vector cyberattack campaign. Analysis of ${totalRequestsAnalyzed?.toLocaleString() || "multiple"} HTTP requests revealed ${severityBreakdown?.CRITICAL || 0} critical and ${severityBreakdown?.HIGH || 0} high-severity events, with attack patterns including ${topTypes.join(", ").toLowerCase() || "signature-based attacks"}.

The attack exhibited characteristics of organized threat activity, with ${ipRotationSummary?.uniqueAttackingIPs || "multiple"} unique source IP addresses involved. An IP diversity rate of ${((ipRotationSummary?.ipDiversityRate || 0) * 100).toFixed(1)}% on targeted endpoints indicates distributed attack infrastructure rather than a single actor, with ${ipRotationSummary?.anonymizedIPCount || 0} IPs identified as using anonymization services (proxy, hosting, or Tor).

Immediate containment measures are recommended, including blocking identified source IP ranges at the network perimeter, patching identified vulnerable endpoints, and filing a formal report with CERT-In within the mandatory 6-hour reporting window as required under the IT Amendment Rules 2022.`;
}
