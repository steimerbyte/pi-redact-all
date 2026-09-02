// Content utilities — helpers to walk and modify ToolResultEvent.content
export function isTextItem(item) {
    return item.type === "text";
}
/**
 * Maps over text items in content, replacing each with the result of `transform`.
 * Image items pass through untouched.
 */
export function mapTextItems(content, transform) {
    return content.map((item) => {
        if (isTextItem(item)) {
            return { ...item, text: transform(item.text) };
        }
        return item;
    });
}
/**
 * Extracts all text from content (for stats/debugging).
 */
export function extractText(content) {
    return content.filter(isTextItem).map((item) => item.text);
}
//# sourceMappingURL=content-utils.js.map