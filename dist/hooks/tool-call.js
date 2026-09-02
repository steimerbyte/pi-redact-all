// tool-call hook — PreToolUse blocking
import { commandReadsSensitive, shouldBlockPath } from "../layers/layer-7-path.js";
import { redactText } from "../layers/index.js";
/**
 * Check whether a tool call should be blocked.
 * Returns a BlockResult if blocked, undefined otherwise.
 */
export function shouldBlock(event, config) {
    if (!config.blockMode)
        return undefined;
    const input = event.input;
    if (!input)
        return undefined;
    // bash: check command for sensitive paths
    if (event.toolName === "bash") {
        const cmd = (input.command ?? input.cmd);
        if (cmd && commandReadsSensitive(cmd)) {
            return {
                block: true,
                reason: `pi-redact-all: bash command likely reads sensitive files. Run 'pi-redact-all-stats' to view layer activity.`,
            };
        }
    }
    // read/write/edit: check path
    if (["read", "write", "edit"].includes(event.toolName)) {
        const path = (input.path ?? input.file_path ?? input.file);
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
 * Check if input contains secrets that should be blocked (e.g., curl with --data
 * containing a token, or git commit -m with embedded credentials).
 */
export function inputContainsSensitiveSecrets(event, config) {
    if (!config.blockMode)
        return undefined;
    const input = event.input;
    if (!input)
        return undefined;
    // Serialize input to scan for secrets
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
//# sourceMappingURL=tool-call.js.map