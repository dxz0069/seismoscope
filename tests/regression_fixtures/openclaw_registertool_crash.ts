/* Regression fixture: minimized from mem0 openclaw/index.ts (Apache-2.0, parent commit
 * 3a9fcdb). Reproduced a native SIGSEGV (Windows 0xC0000005) via tree-sitter
 * start_point/end_point access; line numbers must come from byte offsets.
 */
/**
 * OpenClaw Memory (Mem0) Plugin
 *
 * Long-term memory via Mem0 — supports both the Mem0 platform
 * and the open-source self-hosted SDK. Uses the official `mem0ai` package.
 *
 * Features:
 * - 5 tools: memory_search, memory_list, memory_store, memory_get, memory_forget
 *   (with session/long-term scope support via scope and longTerm parameters)
 * - Short-term (session-scoped) and long-term (user-scoped) memory
 * - Auto-recall: injects relevant memories (both scopes) before each agent turn
 * - Auto-capture: stores key facts scoped to the current session after each agent turn
 * - Per-agent isolation: multi-agent setups write/read from separate userId namespaces
 *   automatically via sessionKey routing (zero breaking changes for single-agent setups)
 * - CLI: openclaw mem0 search, openclaw mem0 stats
 * - Dual mode: platform or open-source (self-hosted)
 */

import { Type } from "@sinclair/typebox";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";

import type {
  Mem0Config,
  Mem0Provider,
  MemoryItem,
  AddOptions,
  SearchOptions,
} from "./types.ts";
import { createProvider } from "./providers.ts";
import { mem0ConfigSchema } from "./config.ts";
import {
  filterMessagesForExtraction,
} from "./filtering.ts";
import {
  effectiveUserId,
  agentUserId,
  resolveUserId,
  isNonInteractiveTrigger,
  isSubagentSession,
} from "./isolation.ts";

// ============================================================================
// Re-exports (for tests and external consumers)
// ============================================================================

export { extractAgentId, effectiveUserId, agentUserId, resolveUserId, isNonInteractiveTrigger, isSubagentSession } from "./isolation.ts";
export {
  isNoiseMessage,
  isGenericAssistantMessage,
  stripNoiseFromContent,
  filterMessagesForExtraction,
} from "./filtering.ts";
export { mem0ConfigSchema } from "./config.ts";
export { createProvider } from "./providers.ts";

// ============================================================================
// Helpers
// ============================================================================

/** Convert Record<string, string> categories to the array format mem0ai expects */
function categoriesToArray(
  cats: Record<string, string>,
): Array<Record<string, string>> {
  return Object.entries(cats).map(([key, value]) => ({ [key]: value }));
}

// ============================================================================
// Plugin Definition
// ============================================================================

const memoryPlugin = {
  id: "openclaw-mem0",
  name: "Memory (Mem0)",
  description:
    "Mem0 memory backend — Mem0 platform or self-hosted open-source",
  kind: "memory" as const,
  configSchema: mem0ConfigSchema,

  register(api: OpenClawPluginApi) {
    const cfg = mem0ConfigSchema.parse(api.pluginConfig);
    const provider = createProvider(cfg, api);

    // Track current session ID for tool-level session scoping.
    // NOTE: This is shared mutable state — tools don't receive ctx, so they
    // read this as a best-effort fallback. Hooks should use ctx.sessionKey
    // directly and avoid relying on this variable.
    let currentSessionId: string | undefined;

    // ========================================================================
    // Per-agent isolation helpers (thin wrappers around exported functions)
    // ========================================================================
    const _effectiveUserId = (sessionKey?: string) =>
      effectiveUserId(cfg.userId, sessionKey);
    const _agentUserId = (id: string) => agentUserId(cfg.userId, id);
    const _resolveUserId = (opts: { agentId?: string; userId?: string }) =>
      resolveUserId(cfg.userId, opts, currentSessionId);

    api.logger.info(
      `openclaw-mem0: registered (mode: ${cfg.mode}, user: ${cfg.userId}, graph: ${cfg.enableGraph}, autoRecall: ${cfg.autoRecall}, autoCapture: ${cfg.autoCapture})`,
    );

    // Helper: build add options
    function buildAddOptions(userIdOverride?: string, runId?: string, sessionKey?: string): AddOptions {
      const opts: AddOptions = {
        user_id: userIdOverride || _effectiveUserId(sessionKey),
        source: "OPENCLAW",
      };
      if (runId) opts.run_id = runId;
      if (cfg.mode === "platform") {
        opts.custom_instructions = cfg.customInstructions;
        opts.custom_categories = categoriesToArray(cfg.customCategories);
        opts.enable_graph = cfg.enableGraph;
        opts.output_format = "v1.1";
      }
      return opts;
    }

    // Helper: build search options
    function buildSearchOptions(
      userIdOverride?: string,
      limit?: number,
      runId?: string,
      sessionKey?: string,
    ): SearchOptions {
      const opts: SearchOptions = {
        user_id: userIdOverride || _effectiveUserId(sessionKey),
        top_k: limit ?? cfg.topK,
        limit: limit ?? cfg.topK,
        threshold: cfg.searchThreshold,
        keyword_search: true,
        reranking: true,
        source: "OPENCLAW",
      };
      if (runId) opts.run_id = runId;
      return opts;
    }

    // ========================================================================
    // Tools
    // ========================================================================

    registerTools(api, provider, cfg, _resolveUserId, _effectiveUserId, _agentUserId, buildAddOptions, buildSearchOptions, () => currentSessionId);

    // ========================================================================
    // CLI Commands
    // ========================================================================

    registerCli(api, provider, cfg, _effectiveUserId, _agentUserId, buildSearchOptions, () => currentSessionId);

    // ========================================================================
    // Lifecycle Hooks
    // ========================================================================

    registerHooks(api, provider, cfg, _effectiveUserId, buildAddOptions, buildSearchOptions, {
      setCurrentSessionId: (id: string) => { currentSessionId = id; },
    });

    // ========================================================================
    // Service
    // ========================================================================

    api.registerService({
      id: "openclaw-mem0",
      start: () => {
        api.logger.info(
          `openclaw-mem0: initialized (mode: ${cfg.mode}, user: ${cfg.userId}, autoRecall: ${cfg.autoRecall}, autoCapture: ${cfg.autoCapture})`,
        );
      },
      stop: () => {
        api.logger.info("openclaw-mem0: stopped");
      },
    });
  },
};

// ============================================================================
// Tool Registration
// ============================================================================

function registerTools(
  api: OpenClawPluginApi,
  provider: Mem0Provider,
  cfg: Mem0Config,
  _resolveUserId: (opts: { agentId?: string; userId?: string }) => string,
  _effectiveUserId: (sessionKey?: string) => string,
  _agentUserId: (id: string) => string,
  buildAddOptions: (userIdOverride?: string, runId?: string, sessionKey?: string) => AddOptions,
  buildSearchOptions: (userIdOverride?: string, limit?: number, runId?: string, sessionKey?: string) => SearchOptions,
  getCurrentSessionId: () => string | undefined,
) {
  api.registerTool(
    {
      name: "memory_search",
      label: "Memory Search",
      description:
        "Search through long-term memories stored in Mem0. Use when you need context about user preferences, past decisions, or previously discussed topics.",
      parameters: Type.Object({
        query: Type.String({ description: "Search query" }),
        limit: Type.Optional(
          Type.Number({
            description: `Max results (default: ${cfg.topK})`,
          }),
        ),
        userId: Type.Optional(
          Type.String({
            description:
              "User ID to scope search (default: configured userId)",
          }),
        ),
        agentId: Type.Optional(
          Type.String({
            description:
              "Agent ID to search memories for a specific agent (e.g. \"researcher\"). Overrides userId.",
          }),
        ),
        scope: Type.Optional(
          Type.Union([
            Type.Literal("session"),
            Type.Literal("long-term"),
            Type.Literal("all"),
          ], {
            description:
              'Memory scope: "session" (current session only), "long-term" (user-scoped only), or "all" (both). Default: "all"',
          }),
        ),
      }),
      async execute(_toolCallId, params) {
        const { query, limit, userId, agentId, scope = "all" } = params as {
          query: string;
          limit?: number;
          userId?: string;
          agentId?: string;
          scope?: "session" | "long-term" | "all";
        };

        try {
          let results: MemoryItem[] = [];
          const uid = _resolveUserId({ agentId, userId });
          const currentSessionId = getCurrentSessionId();

          if (scope === "session") {
            if (currentSessionId) {
              results = await provider.search(
                query,
                buildSearchOptions(uid, limit, currentSessionId),
              );
            }
          } else if (scope === "long-term") {
            results = await provider.search(
              query,
              buildSearchOptions(uid, limit),
            );
          } else {
            // "all" — search both scopes and combine
            const longTermResults = await provider.search(
              query,
              buildSearchOptions(uid, limit),
            );
            let sessionResults: MemoryItem[] = [];
            if (currentSessionId) {
              sessionResults = await provider.search(
                query,
                buildSearchOptions(uid, limit, currentSessionId),
              );
            }
            // Deduplicate by ID, preferring long-term
            const seen = new Set(longTermResults.map((r) => r.id));
            results = [
              ...longTermResults,
              ...sessionResults.filter((r) => !seen.has(r.id)),
            ];
          }

          if (!results || results.length === 0) {
            return {
              content: [
                { type: "text", text: "No relevant memories found." },
              ],
              details: { count: 0 },
            };
          }

          const text = results
            .map(
              (r, i) =>
                `${i + 1}. ${r.memory} (score: ${((r.score ?? 0) * 100).toFixed(0)}%, id: ${r.id})`,
            )
            .join("\n");

          const sanitized = results.map((r) => ({
            id: r.id,
            memory: r.memory,
            score: r.score,
            categories: r.categories,
            created_at: r.created_at,
          }));

          return {
            content: [
              {
                type: "text",
                text: `Found ${results.length} memories:\n\n${text}`,
              },
            ],
            details: { count: results.length, memories: sanitized },
          };
        } catch (err) {
          return {
            content: [
              {
                type: "text",
                text: `Memory search failed: ${String(err)}`,
              },
            ],
            details: { error: String(err) },
          };
        }
      },
    },
    { name: "memory_search" },
  );

  api.registerTool(
    {
      name: "memory_store",
      label: "Memory Store",
      description:
        "Save important information in long-term memory via Mem0. Use for preferences, facts, decisions, and anything worth remembering.",
      parameters: Type.Object({
        text: Type.String({ description: "Information to remember" }),
        userId: Type.Optional(
          Type.String({
            description: "User ID to scope this memory",
          }),
        ),
        agentId: Type.Optional(
          Type.String({
            description:
              "Agent ID to store memory under a specific agent's namespace (e.g. \"researcher\"). Overrides userId.",
          }),
        ),
        metadata: Type.Optional(
          Type.Record(Type.String(), Type.Unknown(), {
            description: "Optional metadata to attach to this memory",
          }),
        ),
        longTerm: Type.Optional(
          Type.Boolean({
            description:
              "Store as long-term (user-scoped) memory. Default: true. Set to false for session-scoped memory.",
          }),
        ),
      }),
      async execute(_toolCallId, params) {
        const { text, userId, agentId, longTerm = true } = params as {
          text: string;
          userId?: string;
          agentId?: string;
          metadata?: Record<string, unknown>;
          longTerm?: boolean;
        };

        try {
          const uid = _resolveUserId({ agentId, userId });
          const currentSessionId = getCurrentSessionId();
          const runId = !longTerm && currentSessionId ? currentSessionId : undefined;

          // Pre-check for near-duplicates so the extraction model has
          // context about existing memories and can UPDATE rather than ADD
          const preview = text.slice(0, 200);
          const dedupOpts = buildSearchOptions(uid, 3);
          dedupOpts.threshold = 0.85;
          const existing = await provider.search(preview, dedupOpts);
          if (existing.length > 0) {
            api.logger.info(
              `openclaw-mem0: found ${existing.length} similar existing memories — mem0 may update instead of add`,
            );
          }

          const result = await provider.add(
            [{ role: "user", content: text }],
            buildAddOptions(uid, runId, currentSessionId),
          );

          const added =
            result.results?.filter((r) => r.event === "ADD") ?? [];
          const updated =
            result.results?.filter((r) => r.event === "UPDATE") ?? [];

          const summary = [];
          if (added.length > 0)
            summary.push(
              `${added.length} new memor${added.length === 1 ? "y" : "ies"} added`,
            );
          if (updated.length > 0)
            summary.push(
              `${updated.length} memor${updated.length === 1 ? "y" : "ies"} updated`,
            );
          if (summary.length === 0)
            summary.push("No new memories extracted");

          return {
            content: [
              {
                type: "text",
                text: `Stored: ${summary.join(", ")}. ${result.results?.map((r) => `[${r.event}] ${r.memory}`).join("; ") ?? ""}`,
              },
            ],
            details: {
              action: "stored",
              results: result.results,
            },
          };
        } catch (err) {
          return {
            content: [
              {
                type: "text",
                text: `Memory store failed: ${String(err)}`,
              },
            ],
            details: { error: String(err) },
          };
        }
      },
    },
    { name: "memory_store" },
  );