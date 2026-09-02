// Config loader for pi-redact-all
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
export const DEFAULT_CONFIG = {
    mode: "mask",
    blockMode: false,
    streamingRedaction: false,
    toolPolicy: {
        whitelist: [],
        blacklist: [],
    },
    layers: {
        vendor: true,
        pem: true,
        prefix: true,
        entropy: true,
        asn1: true,
        context: true,
        path: true,
        pii: false,
        connection: true,
    },
    allowlistRegex: [
        "\\b[a-f0-9]{40}\\b",
        "\\b[0-9a-f]{7,40}\\b",
    ],
    blocklistRegex: [],
    minEntropy: 4.5,
    minLength: 32,
    preservePrefixChars: 4,
    asterisksMax: 20,
};
export function loadConfig() {
    const configPath = join(homedir(), ".pi", "agent", "pi-redact-all.json");
    if (!existsSync(configPath))
        return { ...DEFAULT_CONFIG };
    try {
        const raw = readFileSync(configPath, "utf-8");
        const user = JSON.parse(raw);
        return mergeConfig(DEFAULT_CONFIG, user);
    }
    catch (err) {
        console.error(`[pi-redact-all] Failed to load config at ${configPath}:`, err);
        return { ...DEFAULT_CONFIG };
    }
}
function mergeConfig(base, user) {
    return {
        mode: user.mode ?? base.mode,
        blockMode: user.blockMode ?? base.blockMode,
        streamingRedaction: user.streamingRedaction ?? base.streamingRedaction,
        toolPolicy: {
            whitelist: user.toolPolicy?.whitelist ?? base.toolPolicy.whitelist,
            blacklist: user.toolPolicy?.blacklist ?? base.toolPolicy.blacklist,
        },
        layers: {
            vendor: user.layers?.vendor ?? base.layers.vendor,
            pem: user.layers?.pem ?? base.layers.pem,
            prefix: user.layers?.prefix ?? base.layers.prefix,
            entropy: user.layers?.entropy ?? base.layers.entropy,
            asn1: user.layers?.asn1 ?? base.layers.asn1,
            context: user.layers?.context ?? base.layers.context,
            path: user.layers?.path ?? base.layers.path,
            pii: user.layers?.pii ?? base.layers.pii,
            connection: user.layers?.connection ?? base.layers.connection,
        },
        allowlistRegex: user.allowlistRegex ?? base.allowlistRegex,
        blocklistRegex: user.blocklistRegex ?? base.blocklistRegex,
        minEntropy: user.minEntropy ?? base.minEntropy,
        minLength: user.minLength ?? base.minLength,
        preservePrefixChars: user.preservePrefixChars ?? base.preservePrefixChars,
        asterisksMax: user.asterisksMax ?? base.asterisksMax,
    };
}
//# sourceMappingURL=config.js.map