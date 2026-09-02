// before_agent_start + before_provider_request hooks
//
// Two responsibilities:
//   1. filterUserPrompt: Filter user prompt before agent loop (before_agent_start)
//   2. filterProviderPayload: Final defense before HTTP call to LLM (before_provider_request)
//
// For before_provider_request: payload structure is provider-specific and opaque.
// We CANNOT safely return a modified payload object — it may have:
//   - Class instances with methods
//   - Streams/Buffers
//   - Strict schema validation
//   - Provider-specific structure (OpenAI, Anthropic, etc. differ)
//
// Strategy: Detect the messages-array location and mutate strings IN-PLACE.
// If we can't safely identify the structure, we pass through untouched.
import { redactText } from "../layers/index.js";
/**
 * Filter the user prompt before the agent loop starts.
 * This catches User-Input before it enters the conversation.
 */
export function filterUserPrompt(event, ctx) {
    if (ctx.config.mode === "off")
        return {};
    if (ctx.config.toolPolicy.whitelist.includes("user_input"))
        return {};
    const result = redactText(event.prompt, { ...ctx, toolName: "user_input" });
    if (result.matches.length === 0)
        return {};
    return { prompt: result.text };
}
/**
 * Best-effort final defense: mutate text strings in-place within the payload.
 * Returns nothing — relies on mutation (similar to before_provider_headers).
 */
export function filterProviderPayload(event, ctx) {
    if (ctx.config.mode === "off")
        return;
    if (!event.payload)
        return;
    // Recursively walk and mutate string values in place
    redactInPlace(event.payload, ctx, 0);
}
/**
 * Detect multimodal image blocks where binary content lives under a `data` key.
 * We must never redact these fields — providers strictly validate the bytes and
 * any redaction marker turns them into a 400 error like
 * `invalid image content: decode image config: image: unknown format (2013)`.
 *
 * Recognized shapes (Pi internal + every major provider):
 *  - Anthropic: `{ type: "image", source: { type: "base64", media_type, data } }`
 *  - Pi core:   `{ type: "image", data: "<base64>", mimeType }`
 *  - OpenAI Chat: `{ type: "image_url", image_url: { url: "data:image/..." } }`
 *  - OpenAI Responses: `{ type: "input_image", image_url: "...", file_id }`
 *  - Google:    `{ inlineData: { mimeType, data } }`
 *  - Tool result attachments: `{ type: "image", data: "<base64>" }`
 *  - Generated-image API output: `{ b64_json: "..." }`
 *  - Any data-URI URL string (`data:image/png;base64,XXX`)
 *
 * Key insight: top-level `data` strings (e.g. `{ data: "ghp_FAKE..." }`) on
 * arbitrary unrelated objects are NOT multimodal blocks and SHOULD still be
 * redacted. We only skip the data field when the surrounding structure looks
 * like an image/multimodal envelope.
 */
function isProtectedImageKey(parent, key, value) {
    // Anthropic image.source.data — guarded by the `source` wrapper.
    // The check has to look at the GRANDPARENT (the outer `{type:"image"}` block)
    // because when the recursive walker enters the `source` object the *parent*
    // is the source itself.
    if (key === "data" && parent && typeof parent === "object" && "source" in parent) {
        const source = parent.source;
        if (source && typeof source === "object" && source.type === "base64") {
            return true;
        }
    }
    // v0.1.6: when we're INSIDE an Anthropic image.source object, the parent
    // has the discriminator `type === "base64"` and a `media_type` field.
    // Recognise that and skip the data field, since Anthropic would otherwise
    // see a redaction marker inside the base64 and reject the request with
    // "illegal base64 data at input byte N".
    if (key === "data" &&
        parent &&
        typeof parent === "object" &&
        parent.type === "base64" &&
        typeof parent.media_type === "string") {
        return true;
    }
    // Pi internal: a ContentItem with type === "image" OR toolResult attachments.
    // The data field is base64.
    if (key === "data" && parent && typeof parent === "object" && parent.type === "image") {
        return true;
    }
    // Google inlineData wrapper: `{ inlineData: { mimeType, data } }`.
    if (key === "inlineData" || (key === "data" && isInsideInlineData(parent))) {
        return true;
    }
    if (key === "inline_data")
        return true;
    if (isInsideInlineData(parent) && key === "data")
        return true;
    // OpenAI ChatCompletion image_url wrapper — the inner `url` is a data URI.
    if (key === "image_url")
        return true;
    if (key === "input_image")
        return true;
    // OpenAI image-generation response: `{ b64_json: "..." }`.
    if (key === "b64_json")
        return true;
    // Any stand-alone data: URL string (covers random image URL fields).
    if (typeof value === "string" && /^data:[a-z0-9./+-]+;base64,/i.test(value)) {
        return true;
    }
    return false;
}
function isInsideInlineData(obj) {
    if (!obj || typeof obj !== "object")
        return false;
    const maybe = obj;
    return maybe.inlineData !== undefined && typeof maybe.inlineData === "object";
}
/**
 * Recursively walk an object/array and mutate string values in place.
 * Stops at depth > 20 to prevent runaway traversal.
 *
 * v0.1.4 fix: Never redact multimodal binary payloads (Anthropic image.source.data,
 * Pi ImageContent.data, OpenAI image_url.url, Google inlineData.data, generated
 * image b64_json, and data: URLs). Previously, Layer 4 entropy + Layer 2 PEM
 * regexes matched on long base64 sequences and silently corrupted the `data`
 * field, which providers reject with
 * `invalid image content: decode image config: image: unknown format (2013)`.
 *
 * The check is structural (looks at sibling keys like `source.type === "base64"`,
 * `type === "image"`, `inlineData`, etc.) rather than blanket-key-based so that
 * ordinary `data` properties on unrelated payloads (e.g. `{ data: "ghp_..." }`)
 * are still redacted normally.
 */
function redactInPlace(value, ctx, depth) {
    if (depth > 20)
        return;
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            const item = value[i];
            if (typeof item === "string") {
                const result = redactText(item, ctx);
                if (result.matches.length > 0) {
                    value[i] = result.text;
                }
            }
            else if (item && typeof item === "object") {
                redactInPlace(item, ctx, depth + 1);
            }
        }
        return;
    }
    if (value && typeof value === "object") {
        // Walk own enumerable properties (skip prototype chain, methods, etc.)
        const obj = value;
        for (const key of Object.keys(obj)) {
            // Skip non-data properties (functions, getters, symbols)
            const descriptor = Object.getOwnPropertyDescriptor(obj, key);
            if (!descriptor || typeof descriptor.value === "function")
                continue;
            const v = obj[key];
            if (v && (Array.isArray(v) || typeof v === "object")) {
                redactInPlace(v, ctx, depth + 1);
                continue;
            }
            if (typeof v !== "string")
                continue;
            // v0.1.4: never redact known multimodal image data fields. Providers
            // strictly validate these and any mutation is a guaranteed 400.
            if (isProtectedImageKey(obj, key, v))
                continue;
            const result = redactText(v, ctx);
            if (result.matches.length > 0) {
                obj[key] = result.text;
            }
        }
    }
}
//# sourceMappingURL=before-provider.js.map