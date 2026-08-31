// user-input hook — filterUserPrompt for before_agent_start

import { redactText } from "../layers/index.js";
import type { RedactionContext } from "../types.js";

export interface BeforeAgentStartLike {
  type: "before_agent_start";
  prompt: string;
  images?: unknown;
}

export interface BeforeAgentStartResult {
  prompt?: string;
}

export function filterUserPrompt(
  event: BeforeAgentStartLike,
  ctx: RedactionContext
): BeforeAgentStartResult {
  if (ctx.config.mode === "off") return {};
  if (ctx.config.toolPolicy.whitelist.includes("user_input")) return {};

  const result = redactText(event.prompt, { ...ctx, toolName: "user_input" });
  if (result.matches.length === 0) return {};

  return { prompt: result.text };
}
