import type { RedactionContext } from "../types.js";
export interface BeforeAgentStartLike {
    type: "before_agent_start";
    prompt: string;
    images?: unknown;
}
export interface BeforeAgentStartResult {
    prompt?: string;
}
export interface BeforeProviderRequestLike {
    type: "before_provider_request";
    payload: unknown;
}
/**
 * Filter the user prompt before the agent loop starts.
 * This catches User-Input before it enters the conversation.
 */
export declare function filterUserPrompt(event: BeforeAgentStartLike, ctx: RedactionContext): BeforeAgentStartResult;
/**
 * Best-effort final defense: mutate text strings in-place within the payload.
 * Returns nothing — relies on mutation (similar to before_provider_headers).
 */
export declare function filterProviderPayload(event: BeforeProviderRequestLike, ctx: RedactionContext): void;
//# sourceMappingURL=before-provider.d.ts.map