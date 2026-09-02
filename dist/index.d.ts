/**
 * Minimal Pi Extension API contract that we depend on.
 * The real Pi runtime provides this — we just use the parts we need.
 */
interface ExtensionAPI {
    on(event: string, handler: (...args: unknown[]) => unknown): void;
    registerCommand(name: string, config: {
        description: string;
        handler: (args: string, ctx: unknown) => Promise<string> | string;
    }): void;
}
/**
 * Default export — Pi calls this with the ExtensionAPI.
 */
export default function (pi: ExtensionAPI): void;
export {};
//# sourceMappingURL=index.d.ts.map