interface AutocompleteItem {
    value: string;
    label: string;
    description?: string;
}
interface ExtensionAPI {
    on(event: string, handler: (...args: unknown[]) => unknown): void;
    registerCommand(name: string, config: {
        description: string;
        handler: (args: string, ctx: unknown) => Promise<string> | string;
        getArgumentCompletions?: (argumentPrefix: string) => AutocompleteItem[] | null;
    }): void;
}
export default function (pi: ExtensionAPI): void;
export {};
//# sourceMappingURL=index.d.ts.map