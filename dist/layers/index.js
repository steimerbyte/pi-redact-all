// Layer Registry — orchestriert alle Layer
import * as layer1 from "./layer-1-vendor.js";
import * as layer2 from "./layer-2-pem.js";
import * as layer3 from "./layer-3-prefix.js";
import * as layer4 from "./layer-4-entropy.js";
import * as layer5 from "./layer-5-asn1.js";
import * as layer6 from "./layer-6-context.js";
import * as layer7 from "./layer-7-path.js";
import * as layer8 from "./layer-8-pii.js";
import * as layer9 from "./layer-9-10-connection.js";
import { applyMatches } from "./shared.js";
const ALL_LAYERS = [
    { id: "path", apply: layer7.apply }, // Path-detection FIRST — if path is sensitive, protect everything
    { id: "vendor", apply: layer1.apply },
    { id: "prefix", apply: layer3.apply },
    { id: "pem", apply: layer2.apply },
    { id: "asn1", apply: layer5.apply },
    { id: "context", apply: layer6.apply },
    { id: "connection", apply: layer9.apply },
    { id: "pii", apply: layer8.apply },
    { id: "entropy", apply: layer4.apply }, // Entropy LAST — most expensive, least specific
];
export function redactText(text, ctx) {
    // Graceful handling of null/undefined/empty
    if (!text || typeof text !== "string") {
        return { text: "", matches: [] };
    }
    // Hot-path fast-exit: the configured minimum-length guard. Most redaction
    // targets are >= minLength tokens (32 chars by default). Text shorter than
    // minLength cannot contain a match — vendor patterns, PEM blocks, entropy
    // tokens, connection strings, PII regexes all require at least minLength
    // characters. The layer-7 path detector also requires a file path in
    // `input.path`, which would never fire on short text. Skipping layers
    // here is correct *and* faster than iterating 9 layers on every short
    // tool-result text item (a common case).
    const minLength = ctx.config.minLength;
    if (text.length < minLength) {
        return { text, matches: [] };
    }
    let current = text;
    const allMatches = [];
    for (const layer of ALL_LAYERS) {
        if (!ctx.config.layers[layer.id])
            continue;
        const result = layer.apply(current, ctx);
        if (result.matches.length === 0)
            continue;
        // Apply this layer's matches to current
        current = applyMatches(current, result.matches);
        allMatches.push(...result.matches);
    }
    return { text: current, matches: allMatches };
}
//# sourceMappingURL=index.js.map