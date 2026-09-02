export interface TextContent {
    type: "text";
    text: string;
}
export interface ImageContent {
    type: "image";
    [key: string]: unknown;
}
export type ContentItem = TextContent | ImageContent;
export declare function isTextItem(item: ContentItem): item is TextContent;
/**
 * Maps over text items in content, replacing each with the result of `transform`.
 * Image items pass through untouched.
 */
export declare function mapTextItems(content: ContentItem[], transform: (text: string) => string): ContentItem[];
/**
 * Extracts all text from content (for stats/debugging).
 */
export declare function extractText(content: ContentItem[]): string[];
//# sourceMappingURL=content-utils.d.ts.map