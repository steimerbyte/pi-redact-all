import type { RedactionContext } from "../types.js";
export interface BeforeAgentStartLike {
    type: "before_agent_start";
    prompt: string;
    images?: unknown;
}
export interface BeforeAgentStartResult {
    prompt?: string;
}
export declare function filterUserPrompt(event: BeforeAgentStartLike, ctx: RedactionContext): BeforeAgentStartResult;
//# sourceMappingURL=user-input.d.ts.map