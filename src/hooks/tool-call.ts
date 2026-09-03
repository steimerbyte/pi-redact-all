// tool-call hook — PreToolUse blocking

import type { Config } from "../types.js";
import { commandReadsSensitive, shouldBlockPath } from "../layers/layer-7-path.js";
import { redactText } from "../layers/index.js";

export interface ToolCallLike {
  toolName: string;
  input?: Record<string, unknown>;
}

export interface BlockResult {
  block: true;
  reason: string;
}

const WRITE_TOOLS = new Set(["write", "edit", "ssh_write", "ssh_edit", "multi_edit"]);

function isWriteTool(name: string): boolean {
  if (WRITE_TOOLS.has(name)) return true;
  if (name.startsWith("mcp__") && /__write/i.test(name)) return true;
  return false;
}

/**
 * Check whether a tool call should be blocked.
 * Write-tools are always skipped (model output = never block).
 */
export function shouldBlock(event: ToolCallLike, config: Config, enabled: boolean = true): BlockResult | undefined {
  if (!enabled) return undefined;
  if (isWriteTool(event.toolName)) return undefined;

  if (!config.blockMode) return undefined;
  const input = event.input;
  if (!input) return undefined;

  // bash: check command for sensitive paths
  if (event.toolName === "bash") {
    const cmd = (input.command ?? input.cmd) as string | undefined;
    if (cmd && commandReadsSensitive(cmd)) {
      return {
        block: true,
        reason: `pi-redact-all: bash command likely reads sensitive files. Run 'pi-redact-all-stats' to view layer activity.`,
      };
    }
  }

  // read: check path
  if (event.toolName === "read") {
    const path = (input.path ?? input.file_path ?? input.file) as string | undefined;
    if (path && shouldBlockPath(path)) {
      return {
        block: true,
        reason: `pi-redact-all: access to sensitive path "${path}" is blocked. Configure toolPolicy.whitelist to override.`,
      };
    }
  }

  return undefined;
}

/**
 * Check if input contains secrets that should be blocked.
 * Write-tools are always skipped.
 */
export function inputContainsSensitiveSecrets(event: ToolCallLike, config: Config, enabled: boolean = true): BlockResult | undefined {
  if (!enabled) return undefined;
  if (isWriteTool(event.toolName)) return undefined;
  if (!config.blockMode) return undefined;
  const input = event.input;
  if (!input) return undefined;

  const serialized = JSON.stringify(input);
  const result = redactText(serialized, {
    config,
    partialPrivateKeyPaths: new Set(),
  });

  if (result.matches.length > 0) {
    return {
      block: true,
      reason: `pi-redact-all: tool input contains ${result.matches.length} potential secret(s). Use a safe reference instead.`,
    };
  }

  return undefined;
}
