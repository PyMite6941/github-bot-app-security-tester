"use strict";

// Native fetch (Node 18+).

class AIClient {
  constructor(apiKey, baseUrl, model, timeout = 60) {
    this.apiKey = apiKey || process.env.SECPATCH_AI_API_KEY;
    this.baseUrl = (baseUrl || process.env.SECPATCH_AI_BASE_URL || "https://models.inference.ai.azure.com").replace(/\/$/, "");
    this.model = model || process.env.SECPATCH_AI_MODEL || "gpt-4o";
    this.timeout = timeout;
  }

  available() {
    return Boolean(this.apiKey);
  }

  async draftPatch(filePath, originalCode, finding) {
    if (!this.available()) return null;

    const prompt =
      `You are a senior security engineer. Produce ONE unified diff that fixes the ` +
      `vulnerability described below. Output ONLY the diff - no markdown fences, no ` +
      `explanation, no extra text.\n` +
      `Rules:\n` +
      `  - Header: --- a/<file_path>  then  +++ b/<file_path>\n` +
      `  - One hunk, three lines of context, exact line numbers.\n` +
      `  - Fix ONLY the reported vulnerability; do not refactor unrelated code.\n` +
      `  - Prefer parameterised queries, input validation, escaping, or removing dangerous calls.\n\n` +
      `File: ${filePath}\n` +
      `Vulnerability: ${finding.title} (${finding.ruleId})\n` +
      `Severity: ${finding.severity}\n` +
      `Location: line ${finding.line}\n` +
      `Fix hint: ${finding.fixHint}\n\n` +
      `Current file content:\n${originalCode}\n` +
      `Return the unified diff now:\n`;

    const body = {
      model: this.model,
      messages: [
        { role: "system", content: "You output only valid unified diffs." },
        { role: "user", content: prompt },
      ],
      temperature: 0.1,
      max_tokens: 1500,
    };

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout * 1000);
      const resp = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!resp.ok) {
        console.error(`[secpatch] AI request failed: ${resp.status} ${resp.statusText}`);
        return null;
      }
      const payload = await resp.json();
      const content = payload.choices?.[0]?.message?.content;
      if (!content) {
        console.error(`[secpatch] Unexpected AI response: ${JSON.stringify(payload)}`);
        return null;
      }
      return { filePath, diff: this._extractDiff(content), model: this.model };
    } catch (e) {
      console.error(`[secpatch] AI request failed: ${e.message}`);
      return null;
    }
  }

  _extractDiff(content) {
    let text = content.trim();
    if (text.startsWith("```")) {
      text = text.split("\n").slice(1).join("\n");
      if (text.endsWith("```")) text = text.slice(0, -3).trim();
    }
    return text.trim();
  }
}

module.exports = { AIClient };
