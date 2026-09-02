// Session stats tracking
export function createSessionStats() {
    return {
        totalRedactions: 0,
        byType: new Map(),
        byTool: new Map(),
        blockedCalls: 0,
        startTime: Date.now(),
    };
}
export function recordMatches(stats, matches, toolName) {
    stats.totalRedactions += matches.length;
    for (const m of matches) {
        stats.byType.set(m.type, (stats.byType.get(m.type) || 0) + 1);
    }
    stats.byTool.set(toolName, (stats.byTool.get(toolName) || 0) + matches.length);
}
export function recordBlock(stats) {
    stats.blockedCalls++;
}
export function formatStats(stats) {
    const duration = Math.round((Date.now() - stats.startTime) / 1000);
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;
    const lines = [
        `## pi-redact-all Session Stats`,
        ``,
        `**Total redactions:** ${stats.totalRedactions}`,
        `**Blocked calls:** ${stats.blockedCalls}`,
        `**Duration:** ${minutes}m ${seconds}s`,
        ``,
        `### By Type`,
    ];
    if (stats.byType.size === 0) {
        lines.push(`(none)`);
    }
    else {
        const sorted = [...stats.byType.entries()].sort((a, b) => b[1] - a[1]);
        for (const [type, count] of sorted) {
            lines.push(`- ${type}: ${count}`);
        }
    }
    lines.push(``, `### By Tool`);
    if (stats.byTool.size === 0) {
        lines.push(`(none)`);
    }
    else {
        const sorted = [...stats.byTool.entries()].sort((a, b) => b[1] - a[1]);
        for (const [tool, count] of sorted) {
            lines.push(`- ${tool}: ${count}`);
        }
    }
    return lines.join("\n");
}
//# sourceMappingURL=stats.js.map