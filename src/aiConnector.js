"use strict";

const { defaultLogger } = require("./logger");
const { Config } = require("./config");

/**
 * Pluggable AI connector interface.
 *
 * Secpatch ships with a default OpenAI-compatible connector (GitHub Models,
 * OpenAI, Azure OpenAI, Ollama, LM Studio, or any endpoint exposing the
 * OpenAI /chat/completions shape). Providers are interchangeable: implement
 * the `AIProvider` interface (draftPatch + name) and register it with
 * AIConnector to swap providers without touching the orchestrator.
 *
 * Environment variables (prefix SECPATCH_AI_*):
 *   SECPATCH_AI_API_KEY       - bearer token for the AI endpoint
 *   SECPATCH_AI_BASE_URL      - base URL (default: GitHub Models)
 *   SECPATCH_AI_MODEL         - model name (default: gpt-4o)
 *   SECPATCH_AI_PROVIDER      - provider key (default: openai-compatible)
 *   SECPATCH_AI_MAX_ATTEMPTS  - retry attempts (default: 3)
 *   SECPATCH_AI_BACKOFF_MS    - retry backoff ms (default: 2000)
 */

class AIProviderError extends Error {
  constructor(message, provider, retryable = false) {
    super(message);
    this.name = "AIProviderError";
    this.provider = provider;
    this.retryable = retryable;
  }
}

class AIProvider {
  constructor(config) {
    this.config = config;
    this.name = "base";
  }

  // Subclasses must implement this.
  async draftPatch(prompt) {
    throw new AIProviderError("draftPatch not implemented", this.name, false);
  }

  async _fetchWithRetry(url, body, attempt = 1) {
    const maxAttempts = this.config.retry?.maxAttempts ?? 3;
    const backoffMs = this.config.retry?.backoffMs ?? 2000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutSeconds * 1000);

    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (resp.status === 429 || (resp.status >= 500 && resp.status < 600)) {
        if (attempt < maxAttempts) {
          defaultLogger.warn(`AI provider ${this.name} returned ${resp.status}, retrying in ${backoffMs}ms (attempt ${attempt}/${maxAttempts})`);
          await this._sleep(backoffMs);
          return this._fetchWithRetry(url, body, attempt + 1);
        }
        throw new AIProviderError(
          `AI provider ${this.name} failed after ${maxAttempts} attempts (last status ${resp.status})`,
          this.name,
          false
        );
      }

      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        throw new AIProviderError(
          `AI provider ${this.name} returned ${resp.status}: ${text}`,
          this.name,
          false
        );
      }

      return await resp.json();
    } catch (e) {
      clearTimeout(timer);
      if (e instanceof AIProviderError) throw e;
      if (e.name === "AbortError") {
        throw new AIProviderError(
          `AI provider ${this.name} request timed out after ${this.config.timeoutSeconds}s`,
          this.name,
          true
        );
      }
      if (attempt < maxAttempts) {
        defaultLogger.warn(`AI provider ${this.name} request error: ${e.message}, retrying (attempt ${attempt}/${maxAttempts})`);
        await this._sleep(backoffMs);
        return this._fetchWithRetry(url, body, attempt + 1);
      }
      throw new AIProviderError(
        `AI provider ${this.name} request failed: ${e.message}`,
        this.name,
        true
      );
    }
  }

  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  _buildBody(prompt) {
    return {
      model: this.config.model,
      messages: [
        { role: "system", content: "You output only valid unified diffs." },
        { role: "user", content: prompt },
      ],
      temperature: 0.1,
      max_tokens: 1500,
    };
  }
}

/**
 * Default provider: any OpenAI-compatible /chat/completions endpoint
 * (GitHub Models, OpenAI, Azure OpenAI, Ollama, LM Studio, etc.)
 */
class OpenAICompatibleProvider extends AIProvider {
  constructor(config) {
    super(config);
    this.name = "openai-compatible";
  }

  async draftPatch(prompt) {
    const url = `${this.config.baseUrl.replace(/\/$/, "")}/chat/completions`;
    const payload = await this._fetchWithRetry(url, this._buildBody(prompt));
    const content = payload.choices?.[0]?.message?.content;
    if (!content) {
      throw new AIProviderError(
        `AI provider ${this.name} returned no content`,
        this.name,
        false
      );
    }
    return this._extractDiff(content);
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

class AIConnector {
  constructor() {
    this.providers = new Map();
    this.defaultProvider = null;
  }

  register(provider) {
    this.providers.set(provider.name, provider);
    if (!this.defaultProvider) {
      this.defaultProvider = provider.name;
    }
    defaultLogger.info(`AI provider registered: ${provider.name}`);
  }

  use(name) {
    if (!this.providers.has(name)) {
      throw new Error(`AI provider not registered: ${name}`);
    }
    this.defaultProvider = name;
    defaultLogger.info(`AI provider switched to: ${name}`);
  }

  async draftPatch(prompt, providerName = null) {
    const name = providerName || this.defaultProvider;
    const provider = this.providers.get(name);
    if (!provider) {
      throw new Error(`No AI provider available (registered: ${[...this.providers.keys()].join(", ") || "none"})`);
    }

    const start = Date.now();
    try {
      const diff = await provider.draftPatch(prompt);
      defaultLogger.info(`AI draft completed`, {
        provider: name,
        durationMs: Date.now() - start,
        diffLength: diff.length,
      });
      return diff;
    } catch (e) {
      defaultLogger.error(`AI draft failed`, {
        provider: name,
        durationMs: Date.now() - start,
        error: e.message,
        retryable: e.retryable,
      });
      throw e;
    }
  }

  async draftPatchWithFallback(prompt) {
    const providers = [...this.providers.keys()];
    let lastError = null;
    for (const name of providers) {
      try {
        return await this.draftPatch(prompt, name);
      } catch (e) {
        lastError = e;
        defaultLogger.warn(`Provider ${name} failed, trying next`, { error: e.message });
      }
    }
    throw lastError || new Error("All AI providers failed");
  }
}

const aiConnector = new AIConnector();

// Auto-register the default OpenAI-compatible provider when config is available.
function createDefaultProvider(config) {
  const aiCfg = config.getAIConfig();
  if (!aiCfg.apiKey) {
    defaultLogger.warn("No SECPATCH_AI_API_KEY set — AI patching disabled; template-only mode will be used");
    return null;
  }
  const provider = new OpenAICompatibleProvider(aiCfg);
  aiConnector.register(provider);
  return provider;
}

module.exports = {
  AIProvider,
  AIProviderError,
  AIConnector,
  OpenAICompatibleProvider,
  aiConnector,
  createDefaultProvider,
};
