// Layer 7: File-Path-basierte Erkennung
// Wenn das read-Tool auf eine sensible Datei zugreift, ganzen Inhalt redacted
const SENSITIVE_PATH_PATTERNS = [
    // PEM/Cert-Files
    { pattern: /\.pem$/i, type: "PEM File" },
    { pattern: /\.crt$/i, type: "Certificate File" },
    { pattern: /\.cer$/i, type: "Certificate File" },
    { pattern: /\.der$/i, type: "DER File" },
    { pattern: /\.p7b$/i, type: "PKCS7 File" },
    { pattern: /\.p7c$/i, type: "PKCS7 File" },
    { pattern: /\.p12$/i, type: "PKCS12 File" },
    { pattern: /\.pfx$/i, type: "PKCS12 File" },
    // SSH-Keys
    { pattern: /(^|\/)\.ssh\/id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/i, type: "SSH Key" },
    { pattern: /\.ssh\/config$/i, type: "SSH Config" },
    { pattern: /\.ssh\/known_hosts$/i, type: "SSH Known Hosts" },
    { pattern: /\.ssh\/authorized_keys$/i, type: "SSH Authorized Keys" },
    // Environment
    { pattern: /(^|\/)\.env(\.\w+)?$/i, type: "Env File" },
    // Cloud credentials
    { pattern: /\.aws\/credentials$/i, type: "AWS Credentials" },
    { pattern: /\.aws\/config$/i, type: "AWS Config" },
    { pattern: /\.npmrc$/i, type: "npm Config" },
    { pattern: /\.pypirc$/i, type: "PyPI Config" },
    { pattern: /\.netrc$/i, type: "Netrc File" },
    { pattern: /\.docker\/config\.json$/i, type: "Docker Config" },
    // Generic
    { pattern: /\.gitconfig-credentials$/i, type: "Git Credentials" },
    { pattern: /(^|\/)credentials(\.\w+)?$/i, type: "Credentials File" },
    { pattern: /(^|\/)secrets?\.(ya?ml|json|env)$/i, type: "Secrets File" },
    { pattern: /\.kube\/config$/i, type: "Kube Config" },
    { pattern: /\.kube\/.*\.crt$/i, type: "Kube Cert" },
];
export function apply(text, ctx) {
    const matches = [];
    // Only applies to read-tool with a known path
    if (ctx.toolName !== "read")
        return { matches };
    if (!ctx.inputPath)
        return { matches };
    for (const { pattern, type } of SENSITIVE_PATH_PATTERNS) {
        if (pattern.test(ctx.inputPath)) {
            matches.push({
                start: 0,
                end: text.length,
                type: `Protected File (${type})`,
                replacement: `[REDACTED:Protected File (${type})]`,
            });
            return { matches };
        }
    }
    return { matches };
}
/**
 * Returns true if the path should be blocked entirely (PreToolUse hook).
 */
export function shouldBlockPath(path) {
    for (const { pattern } of SENSITIVE_PATH_PATTERNS) {
        if (pattern.test(path))
            return true;
    }
    return false;
}
/**
 * Returns true if the bash command reads sensitive paths.
 */
export function commandReadsSensitive(command) {
    const sensitiveNames = [
        ".env",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "credentials",
        ".aws/credentials",
        ".npmrc",
        ".netrc",
        ".pypirc",
        ".gitconfig-credentials",
    ];
    for (const name of sensitiveNames) {
        // cat/cp/mv/grep/less/more <path>
        const re = new RegExp(`\\b(?:cat|cp|mv|grep|less|more|head|tail|vi[m]?|nano|less)\\b\\s+[^|;&]*${name.replace(/\./g, "\\.")}`, "i");
        if (re.test(command))
            return true;
        // printenv | grep SECRET
        const envRe = new RegExp(`\\bprintenv\\b.*${name}`, "i");
        if (envRe.test(command))
            return true;
    }
    return false;
}
//# sourceMappingURL=layer-7-path.js.map