// pi-redact-all — Extension entry point
// Hooks: tool_result (PostToolUse), tool_call (PreToolUse Block),
//        before_agent_start (User-Input Filter)

import { loadConfig } from "./config.js";
import { createSessionStats, recordMatches, recordBlock, formatStats } from "./stats.js";
import { applyRedaction, type ToolResultLike } from "./hooks/tool-result.js";
import { shouldBlock, inputContainsSensitiveSecrets } from "./hooks/tool-call.js";
import { filterUserPrompt, type BeforeAgentStartLike } from "./hooks/user-input.js";
import { redactText } from "./layers/index.js";
import type { RedactionContext } from "./types.js";

/** Default write-like tools — model output, never filtered or blocked */
const WRITE_TOOLS = new Set(["write", "edit", "ssh_write", "ssh_edit", "multi_edit"]);

function isWriteTool(name: string): boolean {
  if (WRITE_TOOLS.has(name)) return true;
  // ponytail: simplistic pattern, add more patterns if needed
  if (name.startsWith("mcp__") && /__write/i.test(name)) return true;
  return false;
}

interface AutocompleteItem {
  value: string;
  label: string;
  description?: string;
}

interface ExtensionAPI {
  on(event: string, handler: (...args: unknown[]) => unknown): void;
  registerCommand(
    name: string,
    config: {
      description: string;
      handler: (args: string, ctx: unknown) => Promise<string> | string;
      getArgumentCompletions?: (argumentPrefix: string) => AutocompleteItem[] | null;
    },
  ): void;
}

export default function (pi: ExtensionAPI) {
  const config = loadConfig();
  const stats = createSessionStats();
  const partialPrivateKeyPaths = new Set<string>();

  // Session-level enable toggle (slash commands: redact on | redact off | redact status)
  let enabled = true;

  const makeContext = (toolName?: string, input?: Record<string, unknown>): RedactionContext => ({
    config,
    partialPrivateKeyPaths,
    enabled,
    toolName,
    inputPath: input ? (input.path as string) : undefined,
    command: input ? (input.command as string) : undefined,
  });

  // ──────────────────────────────────────────────────────────────
  // POST-TOOL HOOK: Redact tool output before it reaches the LLM
  // ──────────────────────────────────────────────────────────────
  pi.on("tool_result", async (event: unknown) => {
    const e = event as ToolResultLike;
    if (isWriteTool(e.toolName)) return undefined; // write-tool output = model output, never filter

    const ctx = makeContext(e.toolName, e.input);
    const result = applyRedaction(e, ctx);

    // Track partial private key paths
    if (e.toolName === "read" && ctx.inputPath) {
      const textItem = e.content.find((c) => c.type === "text");
      if (textItem && textItem.type === "text") {
        if (/-----BEGIN[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text) &&
            !/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
          partialPrivateKeyPaths.add(ctx.inputPath);
        } else if (/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
          partialPrivateKeyPaths.delete(ctx.inputPath);
        }
      }
    }

    // Stats
    if (result.content) {
      let totalMatches = 0;
      for (let i = 0; i < e.content.length; i++) {
        const orig = e.content[i];
        const mod = result.content[i];
        if (orig.type === "text" && mod.type === "text" && orig.text !== mod.text) {
          const scanResult = redactText(orig.text, ctx);
          totalMatches += scanResult.matches.length;
        }
      }
      if (totalMatches > 0) {
        recordMatches(
          stats,
          Array(totalMatches).fill({ start: 0, end: 0, type: "unknown", replacement: "" }),
          e.toolName
        );
      }
    }

    return result;
  });

  // ──────────────────────────────────────────────────────────────
  pi.on("tool_call", async (event: unknown) => {
    const e = event as ToolResultLike;
    if (isWriteTool(e.toolName)) return undefined; // write-tool input = model output, never block

    const blockResult = shouldBlock({ toolName: e.toolName, input: e.input }, config, enabled);
    if (blockResult) {
      recordBlock(stats);
      return blockResult;
    }
    const inputBlock = inputContainsSensitiveSecrets({ toolName: e.toolName, input: e.input }, config, enabled);
    if (inputBlock) {
      recordBlock(stats);
      return inputBlock;
    }
    return undefined;
  });

  // ──────────────────────────────────────────────────────────────
  // USER-INPUT HOOK: Filter user prompt before agent loop starts
  // ──────────────────────────────────────────────────────────────
  pi.on("before_agent_start", async (event: unknown) => {
    const e = event as BeforeAgentStartLike;
    const ctx = makeContext("user_input");
    const result = filterUserPrompt(e, ctx);
    if (result.prompt && result.prompt !== e.prompt) {
      const scanResult = redactText(e.prompt, ctx);
      if (scanResult.matches.length > 0) {
        recordMatches(
          stats,
          scanResult.matches,
          "user_input"
        );
      }
    }
    return result;
  });
  // Session toggle command — registered as a single top-level `/redact` so it
  // appears in the slash-menu autocomplete, with argument completions for
  // on | off | status.
  const setEnabled = (next: boolean) => {
    const changed = enabled !== next;
    enabled = next;
    partialPrivateKeyPaths.clear();
    return changed;
  };

  const REDACT_SUBS: Array<{ value: string; label: string; description: string }> = [
    { value: "on", label: "on", description: "Enable redaction in this session" },
    { value: "off", label: "off", description: "Disable redaction in this session" },
    { value: "status", label: "status", description: "Show whether redaction is enabled" },
    { value: "stats", label: "stats", description: "Show session statistics" },
    { value: "config", label: "config", description: "Show current configuration" },
  ];

  pi.registerCommand("redact", {
    description: "Toggle pi-redact-all redaction (on|off|status|stats|config)",
    getArgumentCompletions: (prefix: string) => {
      const p = prefix.trim().toLowerCase();
      const matches = REDACT_SUBS.filter((s) => s.value.startsWith(p));
      return matches.length > 0 ? matches : null;
    },
    handler: (args: string) => {
      const sub = (args ?? "").trim().toLowerCase().split(/\s+/)[0] ?? "";
      switch (sub) {
        case "on": {
          const changed = setEnabled(true);
          return changed
            ? "pi-redact-all: redaction ENABLED. Tool output, user input and sensitive tool calls will be filtered/blocked."
            : "pi-redact-all: redaction already enabled.";
        }
        case "off": {
          const changed = setEnabled(false);
          return changed
            ? "pi-redact-all: redaction DISABLED. Tool output, user input and sensitive tool calls pass through unmodified. Use `/redact on` to re-enable."
            : "pi-redact-all: redaction already disabled.";
        }
        case "status":
          return `pi-redact-all: redaction is ${enabled ? "ENABLED" : "DISABLED"}.`;
        case "stats":
          return formatStats(stats);
        case "config":
          return JSON.stringify(config, null, 2);
        default:
          return `pi-redact-all: unknown argument '${sub}'. Usage: /redact <on|off|status|stats|config>`;
      }
    },
  });

  // Legacy flat commands (still registered so older sessions / docs keep working,
  // but the canonical surface is the unified `/redact` above).
  pi.registerCommand("redact-all-stats", {
    description: "Show pi-redact-all session statistics (alias of `/redact stats`)",
    handler: () => formatStats(stats),
  });

  pi.registerCommand("redact-all-config", {
    description: "Show current pi-redact-all configuration (alias of `/redact config`)",
    handler: () => JSON.stringify(config, null, 2),
  });
}
