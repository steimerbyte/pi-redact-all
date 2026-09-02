import type { Match } from "./types.js";
export interface SessionStats {
    totalRedactions: number;
    byType: Map<string, number>;
    byTool: Map<string, number>;
    blockedCalls: number;
    startTime: number;
}
export declare function createSessionStats(): SessionStats;
export declare function recordMatches(stats: SessionStats, matches: Match[], toolName: string): void;
export declare function recordBlock(stats: SessionStats): void;
export declare function formatStats(stats: SessionStats): string;
//# sourceMappingURL=stats.d.ts.map