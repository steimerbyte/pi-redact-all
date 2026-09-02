import type { RedactionContext } from "../types.js";
export interface MessageEndLike {
    type: "message_end";
    message: AgentMessageLike;
}
export interface AgentMessageLike {
    role: string;
    [key: string]: unknown;
}
export interface MessageEndResult {
    message?: AgentMessageLike;
}
/**
 * Filter message content while preserving the original message shape exactly.
 * Only mutates text fields where appropriate.
 */
export declare function filterMessage(event: MessageEndLike, ctx: RedactionContext): MessageEndResult;
//# sourceMappingURL=message-end.d.ts.map