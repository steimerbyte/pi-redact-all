// tool-result hook — PostToolUse redaction

import type { RedactionContext, Match, RedactionResult } from "../types.js";
import { redactText } from "../layers/index.js";
import { mapTextItems, type ContentItem, isTextItem } from "./content-utils.js";

export interface ToolResultLike {
  toolName: string;
  toolCallId: string;
  input?: Record<string, unknown>;
  content: ContentItem[];
}

/**
 * Apply redaction to all text items in tool result content.
 * Returns the patched content array (or undefined if no changes).
 */
export function applyRedaction(event: ToolResultLike, ctx: RedactionContext): {
  content?: ContentItem[];
} {
  if (ctx.enabled === false) return {};
  if (ctx.config.mode === "off") return {};

  // Skip whitelisted tools
  if (ctx.config.toolPolicy.whitelist.includes(event.toolName)) return {};
  // Apply blacklisted tools (always redact, regardless of whitelist)
  // For blacklisted, we just apply redaction normally

  const inputPath = extractPath(event.input);
  const command = extractCommand(event.input);

  const partialCtx: RedactionContext = {
    ...ctx,
    toolName: event.toolName,
    inputPath,
    command,
  };

  let totalMatches = 0;
  let newContent: ContentItem[] | undefined;

  for (let i = 0; i < event.content.length; i++) {
    const item = event.content[i];
    if (!isTextItem(item)) continue;

    const result = redactText(item.text, partialCtx);
    if (result.matches.length === 0) continue;

    if (!newContent) newContent = [...event.content];
    newContent[i] = { ...item, text: result.text };
    totalMatches += result.matches.length;
  }

  if (totalMatches === 0) return {};
  return { content: newContent ?? event.content };
}

function extractPath(input: Record<string, unknown> | undefined): string | undefined {
  if (!input) return undefined;
  const path = input.path ?? input.file_path ?? input.file;
  return typeof path === "string" ? path : undefined;
}

function extractCommand(input: Record<string, unknown> | undefined): string | undefined {
  if (!input) return undefined;
  const cmd = input.command ?? input.cmd;
  return typeof cmd === "string" ? cmd : undefined;
}