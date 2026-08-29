/**
 * Layer 3 — CERT-In Evidence Generation (Groq API)
 * Sends structured L2 JSON to Groq and gets a 7-section evidence document
 * specifically formatted for CERT-In portal submission.
 */

const CERTIN_SYSTEM_PROMPT = `You are a cybersecurity incident analyst preparing evidence for submission to CERT-In (Indian Computer Emergency Response Team).

Given structured attack detection data in JSON format, generate a formal incident evidence document.

Return your response as a valid JSON object with EXACTLY these keys:
{
  "timeline": "Numbered chronological list of attack events. Each entry on new line: '1. [HH:MM:SS] - Event description'. Use the exact timestamps from the data.",
  "attackPhases": [
    { "phase": "Reconnaissance", "events": ["description1", "description2"], "mitreIds": ["T1595"] }
  ],
  "affectedSystems": ["endpoint1", "endpoint2"],
  "threatActorAssessment": "2-3 paragraph prose assessment of attacker sophistication, tools used, and whether multiple distinct threat actors appear to be present based on the geo-velocity and ASN clustering data.",
  "iocs": {
    "sourceIPs": ["1.2.3.4", "5.6.7.8"],
    "userAgents": ["sqlmap/1.7", "nikto/2.1"],
    "payloadPatterns": ["UNION SELECT", "../../etc/passwd"]
  },
  "certInCategory": "Unauthorised Access Attempt",
  "certInFields": {
    "briefDescription": "2-3 sentence formal description of the incident suitable for CERT-In portal submission.",
    "howDetected": "Description of how the incident was detected (via log analysis using CERTify tool, signature matching, behavioral analysis).",
    "impact": "Assessment of potential impact including systems at risk, data exposure possibility, and business continuity concerns.",
    "actionsTaken": "List of recommended immediate actions: block IPs, patch vulnerabilities, contact ISP, preserve logs, etc."
  }
}

CERT-In incident categories (choose the most appropriate):
- Unauthorised Access Attempt
- Denial of Service
- Malicious Code
- Website Defacement  
- Phishing
- Network Scanning / Probing
- Other

Rules:
- Use formal, professional language appropriate for a government regulatory body
- Be specific with timestamps, IP addresses, and technical details from the data
- The timeline must be numbered chronological entries in order of occurrence
- certInFields must be ready to copy-paste into the CERT-In portal
- Do NOT include markdown formatting, backticks, or code fences in your response
- Return ONLY the raw JSON object, nothing else`;

const GROQ_MODEL = "openai/gpt-oss-120b";

import { slimLayer2JsonForAI } from "./layer3_ai.js";

/**
 * Generate CERT-In evidence document using Groq API
 * @param {object} layer2Json - structured detection summary
 * @param {string} apiKey - optional API key (uses proxy if not provided)
 * @returns {object} parsed evidence object
 */
export async function generateCERTInEvidence(layer2Json, apiKey = null) {
  // Slim the payload — full logs can exceed Groq's free-tier 8K TPM cap
  const slimmed = slimLayer2JsonForAI(layer2Json, 30);

  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  const body = {
    model: GROQ_MODEL,
    max_tokens: 4096,
    // gpt-oss models on Groq support JSON mode — helps keep output parseable
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: CERTIN_SYSTEM_PROMPT },
      { role: "user", content: JSON.stringify(slimmed) },
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
    const errorText = await response.text();
    throw new Error(`Groq API error ${response.status}: ${errorText}`);
  }

  const data = await response.json();
  const rawContent = data.choices?.[0]?.message?.content || "";

  // Strip markdown code fences if present
  const cleaned = rawContent
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    // If JSON parsing fails, return a structured fallback
    return {
      timeline: rawContent,
      attackPhases: [],
      affectedSystems: layer2Json.affectedEndpoints || [],
      threatActorAssessment:
        "Analysis pending — AI response was not in expected JSON format.",
      iocs: { sourceIPs: [], userAgents: [], payloadPatterns: [] },
      certInCategory: "Unauthorised Access Attempt",
      certInFields: {
        briefDescription: "Cyber incident detected via log analysis.",
        howDetected: "Automated log analysis using CERTify tool.",
        impact: "Impact assessment pending.",
        actionsTaken:
          "Preserve logs, block suspicious IPs, notify security team.",
      },
    };
  }
}
