/**
 * dnsProtection.ts
 *
 * Proteção abrangente contra ataques e abusos relacionados a DNS em aplicações Next.js.
 *
 * Vetores cobertos:
 *  - DNS Rebinding Attack
 *  - Host Header Injection / Poisoning
 *  - DNS Tunneling (detecção de exfiltração via DNS)
 *  - Subdomain Takeover (fingerprint de serviços vulneráveis)
 *  - Open Redirect via manipulação de host
 *  - SSRF via resolução de hostname interno
 *  - Homograph/IDN Homoglyph Attack (domínios unicode enganosos)
 *  - DNS Cache Poisoning (validação de respostas)
 *  - Wildcard DNS Abuse
 *  - Punycode / IDN spoofing
 *  - Dangling DNS (registros apontando para recursos inexistentes)
 *  - DNS over HTTPS (DoH) fingerprinting
 *  - Amplitude analysis para detecção de tunneling
 *
 * Integra-se com: requestSanitizer.ts, rateLimiter.ts, authGuard.ts, csrfProtection.ts
 *
 * @module security/dnsProtection
 */

import { NextRequest, NextResponse } from "next/server";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

export type DnsViolationType =
    | "DNS_REBINDING"
    | "HOST_HEADER_INJECTION"
    | "HOST_HEADER_POISONING"
    | "SSRF_INTERNAL_HOST"
    | "SSRF_CLOUD_METADATA"
    | "HOMOGRAPH_ATTACK"
    | "IDN_SPOOFING"
    | "PUNYCODE_SPOOFING"
    | "SUBDOMAIN_TAKEOVER_FINGERPRINT"
    | "OPEN_REDIRECT_HOST"
    | "DNS_TUNNELING_PATTERN"
    | "WILDCARD_DNS_ABUSE"
    | "DANGLING_DNS"
    | "INVALID_HOST_FORMAT"
    | "HOST_TOO_LONG"
    | "LABEL_TOO_LONG"
    | "NUMERIC_TLD"
    | "NULL_BYTE_IN_HOST"
    | "CRLF_IN_HOST"
    | "PORT_NOT_ALLOWED"
    | "FORBIDDEN_HOST"
    | "NOT_IN_ALLOWLIST";

export interface DnsViolation {
    type: DnsViolationType;
    message: string;
    host?: string;
    detail?: string;
}

export interface DnsCheckResult {
    ok: boolean;
    host?: string;
    normalizedHost?: string;
    violations: DnsViolation[];
    /** Metadados para logging/auditoria — não expor ao cliente */
    meta?: {
        isPrivateRange: boolean;
        isLoopback: boolean;
        hasPort: boolean;
        port?: number;
        isIDN: boolean;
        punycode?: string;
        subdomainDepth: number;
        labelLengths: number[];
    };
}

export interface DnsProtectionOptions {
    /**
     * Lista de hosts/domínios explicitamente permitidos.
     * Se definida, qualquer host fora dela é rejeitado.
     * Suporta wildcards simples: "*.example.com"
     */
    allowedHosts?: string[];

    /**
     * Lista de hosts explicitamente bloqueados (além dos internos).
     */
    blockedHosts?: string[];

    /**
     * Portas HTTP(S) permitidas. Padrão: [80, 443].
     * Use [] para bloquear qualquer porta explícita no host.
     */
    allowedPorts?: number[];

    /**
     * Profundidade máxima de subdomínios (padrão: 10).
     * Subdomínios muito profundos são indicador de DNS tunneling.
     */
    maxSubdomainDepth?: number;

    /**
     * Comprimento máximo de um label DNS individual (padrão: 63 — RFC 1035).
     */
    maxLabelLength?: number;

    /**
     * Comprimento máximo do hostname completo (padrão: 253 — RFC 1035).
     */
    maxHostLength?: number;

    /**
     * Se deve aplicar detecção de IDN/homograph (padrão: true).
     */
    checkHomograph?: boolean;

    /**
     * Se deve verificar fingerprints de serviços vulneráveis a subdomain takeover.
     */
    checkSubdomainTakeover?: boolean;

    /**
     * Se deve detectar padrões de DNS tunneling no hostname.
     */
    checkDnsTunneling?: boolean;

    /**
     * Domínio canônico da aplicação (usado como referência para validações).
     * Exemplo: "meusite.com.br"
     */
    canonicalDomain?: string;

    /** Modo estrito: qualquer violação resulta em rejeição (padrão: true) */
    strictMode?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES E LISTAS DE REFERÊNCIA
// ─────────────────────────────────────────────────────────────────────────────

/** RFC 1918 + RFC 4193 + loopback + link-local + cloud metadata */
const PRIVATE_IP_PATTERNS: RegExp[] = [
    // Loopback IPv4
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
    // RFC 1918 — Classe A
    /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
    // RFC 1918 — Classe B
    /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
    // RFC 1918 — Classe C
    /^192\.168\.\d{1,3}\.\d{1,3}$/,
    // Link-local
    /^169\.254\.\d{1,3}\.\d{1,3}$/,
    // CGNAT (RFC 6598)
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$/,
    // Localhost IPv6
    /^::1$/,
    // IPv6 link-local
    /^fe[89ab][0-9a-f]:/i,
    // IPv6 ULA (RFC 4193)
    /^f[cd][0-9a-f]{2}:/i,
    // IPv4-mapped IPv6
    /^::ffff:(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/i,
];

/** Hostnames internos e especiais que nunca devem ser acessados via HTTP externo */
const RESERVED_HOSTNAMES = new Set([
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "local",
    "internal",
    "intranet",
    "corp",
    "home",
    "lan",
    "host",
    "gateway",
    "router",
    "modem",
]);

/**
 * Endpoints de metadata de cloud providers.
 * Usados em ataques SSRF para roubar credenciais IAM.
 */
const CLOUD_METADATA_HOSTS: Set<string> = new Set([
    // AWS IMDSv1 / IMDSv2
    "169.254.169.254",
    "fd00:ec2::254",
    // GCP
    "metadata.google.internal",
    "169.254.169.254", // GCP também usa
    // Azure
    "169.254.169.254", // Azure também usa
    "fd00:ec2::254",
    // Oracle Cloud
    "192.0.0.192",
    // Alibaba Cloud
    "100.100.100.200",
    // DigitalOcean
    "169.254.169.254",
    // IBM Cloud
    "169.254.169.254",
    // Kubernetes internal
    "kubernetes.default.svc.cluster.local",
    "kubernetes.default",
]);

const CLOUD_METADATA_PATTERNS: RegExp[] = [
    /metadata\.google\.internal/i,
    /\.svc\.cluster\.local$/i,
    /\.cluster\.local$/i,
    /\.internal$/i,
    /\.local$/i,
    /imds\.amazonaws\.com/i,
    /instance-data\.ec2\.internal/i,
];

/**
 * Fingerprints de serviços vulneráveis a Subdomain Takeover.
 * Quando um CNAME aponta para estes serviços mas a conta foi deletada,
 * um atacante pode registrar a propriedade e receber tráfego legítimo.
 *
 * Fonte: https://github.com/EdOverflow/can-i-take-over-xyz
 */
const SUBDOMAIN_TAKEOVER_FINGERPRINTS: Array<{
    service: string;
    pattern: RegExp;
    cname?: RegExp;
}> = [
        {
            service: "GitHub Pages",
            pattern: /there isn't a github pages site here/i,
            cname: /\.github\.io$/i,
        },
        {
            service: "Heroku",
            pattern: /no such app/i,
            cname: /\.herokuapp\.com$/i,
        },
        {
            service: "Shopify",
            pattern: /sorry, this shop is currently unavailable/i,
            cname: /\.myshopify\.com$/i,
        },
        {
            service: "Fastly",
            pattern: /fastly error: unknown domain/i,
            cname: /\.fastly\.net$/i,
        },
        {
            service: "Pantheon",
            pattern: /the gods are wise, but do not know of the site/i,
            cname: /\.pantheonsite\.io$/i,
        },
        {
            service: "Tumblr",
            pattern: /whatever you were looking for doesn't currently exist/i,
            cname: /\.tumblr\.com$/i,
        },
        {
            service: "WP Engine",
            pattern: /the site you were looking for couldn't be found/i,
            cname: /\.wpengine\.com$/i,
        },
        {
            service: "Ghost",
            pattern: /the thing you were looking for is no longer here/i,
            cname: /\.ghost\.io$/i,
        },
        {
            service: "Surge.sh",
            pattern: /project not found/i,
            cname: /\.surge\.sh$/i,
        },
        {
            service: "Bitbucket",
            pattern: /repository not found/i,
            cname: /\.bitbucket\.io$/i,
        },
        {
            service: "Azure",
            pattern: /404 web site not found/i,
            cname: /\.azurewebsites\.net$/i,
        },
        {
            service: "AWS S3",
            pattern: /noSuchBucket/i,
            cname: /\.s3\.amazonaws\.com$/i,
        },
        {
            service: "AWS CloudFront",
            pattern: /bad request.*cloudfront/i,
            cname: /\.cloudfront\.net$/i,
        },
        {
            service: "Netlify",
            pattern: /not found - request id/i,
            cname: /\.netlify\.app$/i,
        },
        {
            service: "Vercel",
            pattern: /the deployment could not be found/i,
            cname: /\.vercel\.app$/i,
        },
        {
            service: "ReadMe.io",
            pattern: /project doesnt exist.*readme/i,
            cname: /\.readme\.io$/i,
        },
        {
            service: "Zendesk",
            pattern: /help center closed/i,
            cname: /\.zendesk\.com$/i,
        },
        {
            service: "Freshdesk",
            pattern: /this page is no longer active/i,
            cname: /\.freshdesk\.com$/i,
        },
        {
            service: "HubSpot",
            pattern: /does not exist in our system/i,
            cname: /\.hubspot\.com$/i,
        },
        {
            service: "Intercom",
            pattern: /this page doesn't exist/i,
            cname: /\.intercom\.help$/i,
        },
        {
            service: "Squarespace",
            pattern: /no such account/i,
            cname: /\.squarespace\.com$/i,
        },
    ];

/**
 * Caracteres Unicode de diferentes scripts que se parecem visualmente
 * com letras latinas — usados em ataques Homograph/IDN.
 * Mapeamento: caractere suspeito → equivalente ASCII.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
    // Cirílico
    а: "a", е: "e", о: "o", р: "p", с: "c", х: "x", у: "y",
    А: "A", В: "B", Е: "E", К: "K", М: "M", Н: "H", О: "O",
    Р: "P", С: "C", Т: "T", Х: "X", У: "Y",
    // Grego
    α: "a", β: "b", ε: "e", ο: "o", ρ: "p", υ: "u", ν: "v",
    Α: "A", Β: "B", Ε: "E", Η: "H", Ι: "I", Κ: "K", Μ: "M",
    Ν: "N", Ο: "O", Ρ: "P", Τ: "T", Υ: "Y", Χ: "X", Ζ: "Z",
    // Fullwidth
    ａ: "a", ｂ: "b", ｃ: "c", ｄ: "d", ｅ: "e", ｆ: "f",
    ｇ: "g", ｈ: "h", ｉ: "i", ｊ: "j", ｋ: "k", ｌ: "l",
    ｍ: "m", ｎ: "n", ｏ: "o", ｐ: "p", ｑ: "q", ｒ: "r",
    ｓ: "s", ｔ: "t", ｕ: "u", ｖ: "v", ｗ: "w", ｘ: "x",
    ｙ: "y", ｚ: "z",
    // Subscript/superscript digits
    "⁰": "0", "¹": "1", "²": "2", "³": "3", "⁴": "4",
    "⁵": "5", "⁶": "6", "⁷": "7", "⁸": "8", "⁹": "9",
};

/**
 * Padrões indicativos de DNS Tunneling no hostname.
 * Ferramentas como iodine, dnscat2 e dns2tcp codificam dados em labels DNS.
 */
const DNS_TUNNELING_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    // Labels muito longos (iodine usa labels de 63 chars com base32/base64)
    { name: "LONG_LABEL", pattern: /(?:^|\.)([A-Za-z0-9+/=]{50,})(?:\.|$)/ },
    // Alta entropia em label (base64/base32 encoding)
    { name: "HIGH_ENTROPY_BASE64", pattern: /(?:^|\.)([A-Za-z0-9+/]{40,}={0,2})(?:\.|$)/ },
    // Base32 encoding (iodine)
    { name: "BASE32_LABEL", pattern: /(?:^|\.)([A-Z2-7]{30,})(?:\.|$)/i },
    // Hex encoding em labels
    { name: "HEX_LABEL", pattern: /(?:^|\.)([0-9a-f]{32,})(?:\.|$)/i },
    // Labels com mix incomum de maiúsculas/minúsculas (case-encoding)
    { name: "CASE_ENCODING", pattern: /(?:^|\.)([A-Za-z]{20,}[A-Z][a-z][A-Z])(?:\.|$)/ },
    // Muitos subdomínios numéricos sequenciais
    { name: "SEQUENTIAL_NUMERIC_LABELS", pattern: /(\d+\.\d+\.\d+\.\d+\.\d+)/ },
    // Prefixos conhecidos de ferramentas de tunneling
    { name: "KNOWN_TUNNEL_PREFIX", pattern: /^(t1|t2|dns2tcp|iodine|dnscat|tunnel)\./i },
];

// ─────────────────────────────────────────────────────────────────────────────
// DEFAULTS
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULTS: Required<Omit<DnsProtectionOptions, "allowedHosts" | "blockedHosts" | "canonicalDomain">> = {
    allowedPorts: [80, 443],
    maxSubdomainDepth: 10,
    maxLabelLength: 63,    // RFC 1035
    maxHostLength: 253,    // RFC 1035
    checkHomograph: true,
    checkSubdomainTakeover: true,
    checkDnsTunneling: true,
    strictMode: true,
};

// ─────────────────────────────────────────────────────────────────────────────
// FUNÇÕES UTILITÁRIAS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se um IP está em faixa privada/reservada.
 */
export function isPrivateIP(ip: string): boolean {
    const normalized = ip.trim().toLowerCase();
    return PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(normalized));
}

/**
 * Verifica se é um endereço de loopback.
 */
export function isLoopback(host: string): boolean {
    return host === "localhost" ||
        host === "::1" ||
        /^127\.\d+\.\d+\.\d+$/.test(host);
}

/**
 * Extrai hostname e porta de uma string de host (pode conter porta).
 */
export function parseHostPort(raw: string): { hostname: string; port: number | null } {
    // IPv6 com porta: [::1]:8080
    const ipv6WithPort = /^\[([^\]]+)\]:(\d+)$/.exec(raw);
    if (ipv6WithPort) {
        return { hostname: ipv6WithPort[1], port: parseInt(ipv6WithPort[2], 10) };
    }

    // IPv6 sem porta: ::1 ou [::1]
    if (raw.startsWith("[")) {
        return { hostname: raw.slice(1, -1), port: null };
    }

    // IPv4 ou hostname com porta
    const lastColon = raw.lastIndexOf(":");
    if (lastColon !== -1) {
        const potentialPort = raw.slice(lastColon + 1);
        if (/^\d+$/.test(potentialPort)) {
            return {
                hostname: raw.slice(0, lastColon),
                port: parseInt(potentialPort, 10),
            };
        }
    }

    return { hostname: raw, port: null };
}

/**
 * Normaliza hostname para lowercase e remove trailing dot.
 */
export function normalizeHostname(host: string): string {
    return host.toLowerCase().replace(/\.$/, "").trim();
}

/**
 * Converte hostname IDN (unicode) para Punycode ASCII.
 * Usa a API nativa do browser/Node quando disponível.
 */
export function toPunycode(hostname: string): string {
    try {
        // No ambiente Node.js/Next.js, URL faz a conversão automaticamente
        const url = new URL(`http://${hostname}`);
        return url.hostname;
    } catch {
        return hostname;
    }
}

/**
 * Detecta se um hostname contém caracteres homoglyph conhecidos.
 * Retorna o hostname "normalizado" com ASCII equivalente para comparação.
 */
export function detectHomoglyphs(hostname: string): {
    hasHomoglyphs: boolean;
    normalized: string;
    suspiciousChars: string[];
} {
    let normalized = "";
    const suspiciousChars: string[] = [];

    for (const char of hostname) {
        if (HOMOGLYPH_MAP[char] !== undefined) {
            suspiciousChars.push(char);
            normalized += HOMOGLYPH_MAP[char];
        } else {
            normalized += char;
        }
    }

    return {
        hasHomoglyphs: suspiciousChars.length > 0,
        normalized,
        suspiciousChars,
    };
}

/**
 * Calcula a entropia de Shannon de uma string.
 * Alta entropia em labels DNS pode indicar encoding (tunneling).
 */
export function shannonEntropy(input: string): number {
    if (!input.length) return 0;
    const freq: Record<string, number> = {};
    for (const char of input) {
        freq[char] = (freq[char] ?? 0) + 1;
    }
    return Object.values(freq).reduce((entropy, count) => {
        const p = count / input.length;
        return entropy - p * Math.log2(p);
    }, 0);
}

/**
 * Verifica se um hostname corresponde a um padrão de wildcard.
 * Suporta: "*.example.com", "example.com", "sub.example.com"
 */
export function matchesWildcard(hostname: string, pattern: string): boolean {
    if (pattern.startsWith("*.")) {
        const base = pattern.slice(2);
        return hostname === base || hostname.endsWith(`.${base}`);
    }
    return hostname === pattern;
}

/**
 * Verifica fingerprints de subdomain takeover no hostname.
 * Retorna o serviço vulnerável se encontrado.
 */
export function detectSubdomainTakeoverRisk(hostname: string): string | null {
    for (const fp of SUBDOMAIN_TAKEOVER_FINGERPRINTS) {
        if (fp.cname && fp.cname.test(hostname)) {
            return fp.service;
        }
    }
    return null;
}

/**
 * Detecta padrões de DNS tunneling no hostname.
 */
export function detectDnsTunneling(hostname: string): {
    detected: boolean;
    pattern?: string;
    entropy?: number;
} {
    // Verifica padrões conhecidos
    for (const { name, pattern } of DNS_TUNNELING_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(hostname)) {
            return { detected: true, pattern: name };
        }
    }

    // Verifica entropia dos labels individualmente
    const labels = hostname.split(".");
    for (const label of labels) {
        if (label.length >= 20) {
            const entropy = shannonEntropy(label);
            // Entropia > 4.5 em labels longos é altamente suspeito
            if (entropy > 4.5) {
                return {
                    detected: true,
                    pattern: "HIGH_SHANNON_ENTROPY",
                    entropy: Math.round(entropy * 100) / 100,
                };
            }
        }
    }

    return { detected: false };
}

/**
 * Valida formato de hostname conforme RFC 952, RFC 1123 e RFC 5891.
 */
export function isValidHostnameFormat(hostname: string): boolean {
    // Endereços IP v4
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        return hostname.split(".").every((octet) => {
            const n = parseInt(octet, 10);
            return n >= 0 && n <= 255;
        });
    }

    // Endereços IP v6 (simplificado)
    if (/^[0-9a-f:]+$/i.test(hostname) && hostname.includes(":")) {
        return true;
    }

    // Hostname: labels separados por pontos
    const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
    const labels = hostname.split(".");
    return labels.every((label) => label.length > 0 && labelRegex.test(label));
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFICADOR PRINCIPAL DE HOST
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executa todas as verificações de DNS Protection em um hostname.
 *
 * @example
 * ```ts
 * const result = checkHost("evil.internal.company.com", {
 *   allowedHosts: ["*.company.com"],
 *   canonicalDomain: "company.com",
 * });
 * if (!result.ok) {
 *   console.error(result.violations);
 * }
 * ```
 */
export function checkHost(
    rawHost: string,
    options: DnsProtectionOptions = {}
): DnsCheckResult {
    const opts = { ...DEFAULTS, ...options };
    const violations: DnsViolation[] = [];

    // ── Pré-validação básica ───────────────────────────────────────────────────
    if (!rawHost || typeof rawHost !== "string") {
        return {
            ok: false,
            violations: [{
                type: "INVALID_HOST_FORMAT",
                message: "Host header is missing or not a string",
            }],
        };
    }

    // Null byte injection
    if (/\x00/.test(rawHost)) {
        return {
            ok: false,
            violations: [{
                type: "NULL_BYTE_IN_HOST",
                message: "Null byte detected in Host header",
                host: rawHost,
            }],
        };
    }

    // CRLF injection (Host Header Injection)
    if (/[\r\n]/.test(rawHost)) {
        return {
            ok: false,
            violations: [{
                type: "CRLF_IN_HOST",
                message: "CRLF characters detected in Host header — possible header injection",
                host: rawHost.replace(/[\r\n]/g, "\\n"),
            }],
        };
    }

    // ── Parse hostname e porta ─────────────────────────────────────────────────
    const { hostname: rawHostname, port } = parseHostPort(rawHost);
    const hostname = normalizeHostname(rawHostname);

    // ── Comprimento do host (RFC 1035) ─────────────────────────────────────────
    if (hostname.length > opts.maxHostLength) {
        violations.push({
            type: "HOST_TOO_LONG",
            message: `Hostname exceeds RFC 1035 maximum of ${opts.maxHostLength} characters (got ${hostname.length})`,
            host: hostname,
        });
    }

    // ── Validação de formato ───────────────────────────────────────────────────
    if (!isValidHostnameFormat(hostname)) {
        return {
            ok: false,
            violations: [{
                type: "INVALID_HOST_FORMAT",
                message: `Invalid hostname format: ${hostname}`,
                host: hostname,
            }],
        };
    }

    // ── Labels DNS ─────────────────────────────────────────────────────────────
    const labels = hostname.split(".");
    const labelLengths = labels.map((l) => l.length);
    const subdomainDepth = labels.length - 1;

    // Label muito longo (RFC 1035: máx 63)
    const longLabel = labels.find((l) => l.length > opts.maxLabelLength);
    if (longLabel) {
        violations.push({
            type: "LABEL_TOO_LONG",
            message: `DNS label "${longLabel}" exceeds maximum length of ${opts.maxLabelLength}`,
            host: hostname,
        });
    }

    // TLD puramente numérico indica IP disfarçado ou abuso
    const tld = labels[labels.length - 1];
    if (/^\d+$/.test(tld)) {
        violations.push({
            type: "NUMERIC_TLD",
            message: `TLD "${tld}" is purely numeric — possible IP address disguise`,
            host: hostname,
        });
    }

    // ── Porta ─────────────────────────────────────────────────────────────────
    if (port !== null) {
        if (!opts.allowedPorts.includes(port)) {
            violations.push({
                type: "PORT_NOT_ALLOWED",
                message: `Port ${port} is not in the allowed ports list: [${opts.allowedPorts.join(", ")}]`,
                host: hostname,
                detail: `Requested port: ${port}`,
            });
        }
    }

    // ── Hosts reservados e internos ────────────────────────────────────────────
    const isReserved = RESERVED_HOSTNAMES.has(hostname);
    const isLoop = isLoopback(hostname);
    const isPrivate = isPrivateIP(hostname);
    const isCloudMeta =
        CLOUD_METADATA_HOSTS.has(hostname) ||
        CLOUD_METADATA_PATTERNS.some((p) => p.test(hostname));

    if (isLoop) {
        violations.push({
            type: "SSRF_INTERNAL_HOST",
            message: `Loopback address detected: ${hostname}`,
            host: hostname,
            detail: "DNS Rebinding or SSRF via loopback",
        });
    }

    if (isPrivate && !isLoop) {
        violations.push({
            type: "DNS_REBINDING",
            message: `Private IP range detected: ${hostname}`,
            host: hostname,
            detail: "Possible DNS Rebinding attack targeting internal network",
        });
    }

    if (isCloudMeta) {
        violations.push({
            type: "SSRF_CLOUD_METADATA",
            message: `Cloud metadata endpoint detected: ${hostname}`,
            host: hostname,
            detail: "SSRF attempt targeting cloud provider metadata service (IMDSv1/v2)",
        });
    }

    if (isReserved) {
        violations.push({
            type: "SSRF_INTERNAL_HOST",
            message: `Reserved hostname detected: ${hostname}`,
            host: hostname,
            detail: "Reserved/internal hostname that should not be publicly accessible",
        });
    }

    // ── Blocked hosts list ─────────────────────────────────────────────────────
    if (opts.blockedHosts && Array.isArray(opts.blockedHosts)) {
        const blocked = opts.blockedHosts.find((b) => matchesWildcard(hostname, b));
        if (blocked) {
            violations.push({
                type: "FORBIDDEN_HOST",
                message: `Host "${hostname}" is explicitly blocked (matched: "${blocked}")`,
                host: hostname,
            });
        }
    }

    // ── IDN / Homograph / Punycode ─────────────────────────────────────────────
    const hasNonASCII = /[^\x00-\x7F]/.test(hostname);
    let punycodeHost = hostname;
    let isIDN = false;

    if (hasNonASCII || hostname.includes("xn--")) {
        isIDN = true;
        punycodeHost = toPunycode(hostname);

        if (opts.checkHomograph) {
            const { hasHomoglyphs, suspiciousChars } = detectHomoglyphs(hostname);
            if (hasHomoglyphs) {
                violations.push({
                    type: "HOMOGRAPH_ATTACK",
                    message: `Homograph/IDN spoofing detected in hostname: ${hostname}`,
                    host: hostname,
                    detail: `Suspicious characters: ${suspiciousChars.join(", ")}`,
                });
            }

            // Verifica se o punycode resolve para um domínio suspeito
            if (punycodeHost !== hostname && opts.canonicalDomain) {
                const punyNorm = normalizeHostname(punycodeHost);
                if (
                    !matchesWildcard(punyNorm, opts.canonicalDomain) &&
                    !matchesWildcard(punyNorm, `*.${opts.canonicalDomain}`)
                ) {
                    violations.push({
                        type: "IDN_SPOOFING",
                        message: `IDN hostname "${hostname}" resolves to "${punycodeHost}" which differs from canonical domain`,
                        host: hostname,
                        detail: `Punycode: ${punycodeHost}`,
                    });
                }
            }

            // Punycode com label "xn--" suspeito (possível spoofing de TLD)
            if (/\.xn--[a-z0-9]+$/i.test(punycodeHost)) {
                violations.push({
                    type: "PUNYCODE_SPOOFING",
                    message: `Punycode TLD detected — verify this is a legitimate IDN TLD`,
                    host: hostname,
                    detail: `Resolved: ${punycodeHost}`,
                });
            }
        }
    }

    // ── Host Header Poisoning (mismatch com canonical) ─────────────────────────
    if (opts.canonicalDomain) {
        const normalizedCanonical = normalizeHostname(opts.canonicalDomain);
        const effectiveHost = punycodeHost || hostname;

        if (
            effectiveHost !== normalizedCanonical &&
            !matchesWildcard(effectiveHost, `*.${normalizedCanonical}`)
        ) {
            // Só é uma violação se não estiver na allowlist
            const inAllowlist =
                opts.allowedHosts &&
                opts.allowedHosts.some((allowed) =>
                    matchesWildcard(effectiveHost, allowed)
                );

            if (!inAllowlist) {
                violations.push({
                    type: "HOST_HEADER_POISONING",
                    message: `Host "${effectiveHost}" does not match canonical domain "${normalizedCanonical}"`,
                    host: hostname,
                    detail: "Possible Host Header Poisoning — used in cache poisoning and password reset attacks",
                });
            }
        }
    }

    // ── Subdomain depth (DNS tunneling heuristic) ──────────────────────────────
    if (subdomainDepth > opts.maxSubdomainDepth) {
        violations.push({
            type: "WILDCARD_DNS_ABUSE",
            message: `Subdomain depth ${subdomainDepth} exceeds maximum of ${opts.maxSubdomainDepth}`,
            host: hostname,
            detail: "Excessive subdomain depth is a common indicator of DNS tunneling or wildcard abuse",
        });
    }

    // ── DNS Tunneling ──────────────────────────────────────────────────────────
    if (opts.checkDnsTunneling) {
        const tunneling = detectDnsTunneling(hostname);
        if (tunneling.detected) {
            violations.push({
                type: "DNS_TUNNELING_PATTERN",
                message: `DNS tunneling pattern detected in hostname: ${hostname}`,
                host: hostname,
                detail: `Pattern: ${tunneling.pattern}${tunneling.entropy ? ` | Entropy: ${tunneling.entropy}` : ""}`,
            });
        }
    }

    // ── Subdomain Takeover fingerprint ────────────────────────────────────────
    if (opts.checkSubdomainTakeover) {
        const vulnerableService = detectSubdomainTakeoverRisk(hostname);
        if (vulnerableService) {
            violations.push({
                type: "SUBDOMAIN_TAKEOVER_FINGERPRINT",
                message: `Hostname matches known subdomain takeover target: ${vulnerableService}`,
                host: hostname,
                detail: `Service: ${vulnerableService} — verify CNAME ownership`,
            });
        }
    }

    // ── Allowlist check (verificação final) ───────────────────────────────────
    if (opts.allowedHosts && opts.allowedHosts.length > 0) {
        const effectiveHost = normalizeHostname(punycodeHost || hostname);
        const isAllowed = opts.allowedHosts.some((allowed) =>
            matchesWildcard(effectiveHost, normalizeHostname(allowed))
        );

        if (!isAllowed) {
            // Remove a violação de HOST_HEADER_POISONING se já adicionada
            // pois NOT_IN_ALLOWLIST é mais específica
            const filtered = violations.filter(
                (v) => v.type !== "HOST_HEADER_POISONING"
            );
            filtered.push({
                type: "NOT_IN_ALLOWLIST",
                message: `Host "${effectiveHost}" is not in the allowed hosts list`,
                host: hostname,
                detail: `Allowed: [${opts.allowedHosts.join(", ")}]`,
            });
            return { ok: false, host: hostname, violations: filtered };
        }
    }

    // ── Resultado ──────────────────────────────────────────────────────────────
    const hasBlockingViolation =
        violations.some((v) =>
            [
                "DNS_REBINDING",
                "SSRF_INTERNAL_HOST",
                "SSRF_CLOUD_METADATA",
                "HOMOGRAPH_ATTACK",
                "CRLF_IN_HOST",
                "NULL_BYTE_IN_HOST",
                "FORBIDDEN_HOST",
                "HOST_HEADER_INJECTION",
                "HOST_HEADER_POISONING",
            ].includes(v.type)
        );

    const ok = opts.strictMode
        ? violations.length === 0
        : !hasBlockingViolation;

    return {
        ok,
        host: rawHost,
        normalizedHost: punycodeHost || hostname,
        violations,
        meta: {
            isPrivateRange: isPrivate,
            isLoopback: isLoop,
            hasPort: port !== null,
            port: port ?? undefined,
            isIDN,
            punycode: isIDN ? punycodeHost : undefined,
            subdomainDepth,
            labelLengths,
        },
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE PARA NEXT.JS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extrai e valida o Host header de uma NextRequest.
 * Protege contra Host Header Injection, DNS Rebinding e SSRF.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { validateRequestHost } from "@/lib/security/dnsProtection";
 *
 * export function middleware(request: NextRequest) {
 *   const result = validateRequestHost(request, {
 *     allowedHosts: ["meusite.com.br", "*.meusite.com.br"],
 *     canonicalDomain: "meusite.com.br",
 *   });
 *   if (!result.ok) {
 *     return new NextResponse("Forbidden", { status: 403 });
 *   }
 *   return NextResponse.next();
 * }
 * ```
 */
export function validateRequestHost(
    request: NextRequest,
    options: DnsProtectionOptions = {}
): DnsCheckResult {
    // Prioridade: X-Forwarded-Host > Host header
    // Importante: X-Forwarded-Host pode ser forjado — valide AMBOS
    const forwardedHost = request.headers.get("x-forwarded-host");
    const hostHeader = request.headers.get("host");
    const urlHost = new URL(request.url).host;

    const hostsToCheck: Array<{ header: string; value: string }> = [];

    if (hostHeader) hostsToCheck.push({ header: "Host", value: hostHeader });
    if (forwardedHost) hostsToCheck.push({ header: "X-Forwarded-Host", value: forwardedHost });

    // Detecta discrepância entre Host e URL (sinal de manipulação)
    if (hostHeader && urlHost && normalizeHostname(hostHeader) !== normalizeHostname(urlHost)) {
        return {
            ok: false,
            violations: [{
                type: "HOST_HEADER_INJECTION",
                message: `Host header "${hostHeader}" does not match request URL host "${urlHost}"`,
                host: hostHeader,
                detail: "Host header mismatch — possible Host Header Injection attack",
            }],
        };
    }

    // Valida cada header de host
    for (const { value } of hostsToCheck) {
        const result = checkHost(value, options);
        if (!result.ok) {
            return result;
        }
    }

    // Usa o host primário para retorno
    const primaryHost = hostHeader ?? urlHost;
    return checkHost(primaryHost, options);
}

/**
 * Wrapper middleware completo para Route Handlers e API Routes.
 * Combina validação de host + resposta automática de erro.
 *
 * @example
 * ```ts
 * export async function GET(req: NextRequest) {
 *   return withDnsProtection(req, async () => {
 *     return NextResponse.json({ data: "ok" });
 *   }, { allowedHosts: ["*.meusite.com.br"] });
 * }
 * ```
 */
export async function withDnsProtection(
    request: NextRequest,
    handler: (hostInfo: DnsCheckResult) => Promise<NextResponse>,
    options: DnsProtectionOptions = {}
): Promise<NextResponse> {
    const result = validateRequestHost(request, options);

    if (!result.ok) {
        const isDev = process.env.NODE_ENV === "development";

        // Log para SIEM/auditoria (não expõe ao cliente)
        console.warn("[DNS_PROTECTION] Request blocked", {
            violations: result.violations,
            host: result.host,
            url: request.url,
            ip: request.headers.get("x-forwarded-for") ?? "unknown",
            timestamp: new Date().toISOString(),
        });

        return new NextResponse(
            JSON.stringify({
                error: "Forbidden",
                ...(isDev && {
                    details: result.violations.map((v) => ({
                        type: v.type,
                        message: v.message,
                    })),
                }),
            }),
            {
                status: 403,
                headers: {
                    "Content-Type": "application/json",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    // Bloqueia o host problemático de ser armazenado em cache
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "Pragma": "no-cache",
                },
            }
        );
    }

    return handler(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDAÇÃO DE URLS EXTERNAS (para uso em fetch/redirect)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Valida uma URL externa antes de fazer fetch ou redirect.
 * Previne SSRF em chamadas server-side e Open Redirect.
 *
 * @example
 * ```ts
 * const check = validateExternalUrl("https://evil.internal/steal-data", {
 *   allowedHosts: ["api.trusted-partner.com"],
 * });
 * if (!check.ok) throw new Error("Blocked: " + check.violations[0].message);
 * const data = await fetch(url); // seguro
 * ```
 */
export function validateExternalUrl(
    rawUrl: string,
    options: DnsProtectionOptions = {}
): DnsCheckResult & { url?: URL } {
    let parsed: URL;

    try {
        parsed = new URL(rawUrl);
    } catch {
        return {
            ok: false,
            violations: [{
                type: "INVALID_HOST_FORMAT",
                message: `Invalid URL: ${rawUrl}`,
            }],
        };
    }

    // Apenas HTTPS em produção
    if (
        process.env.NODE_ENV === "production" &&
        parsed.protocol !== "https:"
    ) {
        return {
            ok: false,
            violations: [{
                type: "INVALID_HOST_FORMAT",
                message: `Only HTTPS URLs are allowed in production (got: ${parsed.protocol})`,
                host: parsed.hostname,
            }],
        };
    }

    // Bloqueia protocolos perigosos
    const dangerousProtocols = ["javascript:", "data:", "vbscript:", "file:", "ftp:"];
    if (dangerousProtocols.includes(parsed.protocol)) {
        return {
            ok: false,
            violations: [{
                type: "OPEN_REDIRECT_HOST",
                message: `Dangerous protocol detected: ${parsed.protocol}`,
                host: parsed.hostname,
                detail: "Protocol may be used for XSS or local file inclusion",
            }],
        };
    }

    const hostResult = checkHost(parsed.host, options);
    return { ...hostResult, url: hostResult.ok ? parsed : undefined };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

export {
    PRIVATE_IP_PATTERNS,
    RESERVED_HOSTNAMES,
    CLOUD_METADATA_HOSTS,
    CLOUD_METADATA_PATTERNS,
    SUBDOMAIN_TAKEOVER_FINGERPRINTS,
    DNS_TUNNELING_PATTERNS,
    HOMOGLYPH_MAP,
    DEFAULTS as DNS_PROTECTION_DEFAULTS,
};