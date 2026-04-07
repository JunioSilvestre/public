/**
 * trafficInspection.ts
 *
 * Inspeção profunda de tráfego e análise comportamental para Next.js.
 * Opera como camada de inteligência sobre os dados coletados pelos módulos
 * anteriores, correlacionando sinais para detectar ameaças complexas.
 *
 * Responsabilidades:
 *  - Deep Packet Inspection (DPI) — análise de payload além do sanitizer
 *  - Fingerprinting de navegador/cliente (JA3, HTTP/2, TLS fingerprint)
 *  - Detecção de anomalias comportamentais (velocidade, sequência, padrão)
 *  - Análise de timing attacks e side-channel patterns
 *  - Detecção de credential stuffing e brute force distribuído
 *  - Análise de sessão e correlação entre requests
 *  - Detecção de enumeração (user, resource, endpoint)
 *  - Bot fingerprinting comportamental (mouse, timing, sequência)
 *  - Detecção de replay attacks
 *  - Análise de padrões de exfiltração de dados
 *  - Traffic baseline e desvio estatístico
 *  - Honeypot endpoint tracking
 *  - Request correlation e graph analysis
 *  - Detecção de scraping e content theft
 *  - Proteção contra clickjacking comportamental
 *
 * Integra-se com: requestSanitizer.ts, dnsProtection.ts, firewallRules.ts,
 *                 networkPolicies.ts, rateLimiter.ts, authGuard.ts
 *
 * @module security/trafficInspection
 */

import { NextRequest, NextResponse } from "next/server";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

export type InspectionViolationType =
    | "PAYLOAD_ANOMALY"
    | "ENCODING_EVASION"
    | "POLYGLOT_ATTACK"
    | "MIME_MISMATCH"
    | "CONTENT_SNIFFING"
    | "BINARY_IN_TEXT"
    | "OVERSIZED_FIELD"
    | "DEEPLY_NESTED_PAYLOAD"
    | "REPEATED_CHAR_ATTACK"
    | "UNICODE_NORMALIZATION_ATTACK"
    | "TIMING_ANOMALY"
    | "REPLAY_ATTACK"
    | "CREDENTIAL_STUFFING"
    | "BRUTE_FORCE_DISTRIBUTED"
    | "ENUMERATION_USER"
    | "ENUMERATION_RESOURCE"
    | "ENUMERATION_ENDPOINT"
    | "SCRAPING_PATTERN"
    | "EXFILTRATION_PATTERN"
    | "HONEYPOT_TRIGGERED"
    | "SESSION_ANOMALY"
    | "SESSION_FIXATION"
    | "SESSION_HIJACKING"
    | "FINGERPRINT_MISMATCH"
    | "JA3_BLOCKLISTED"
    | "HTTP2_FINGERPRINT_ANOMALY"
    | "BOT_BEHAVIORAL_PATTERN"
    | "HEADLESS_BROWSER"
    | "AUTOMATION_FRAMEWORK"
    | "REQUEST_FLOOD"
    | "SLOW_BODY_ATTACK"
    | "SLOW_HEADER_ATTACK"
    | "LARGE_BODY_INCREMENTAL"
    | "GRAPH_TRAVERSAL_ANOMALY"
    | "LATERAL_MOVEMENT"
    | "PRIVILEGE_ESCALATION_PATTERN"
    | "DATA_STAGING"
    | "BASELINE_DEVIATION";

export type InspectionSeverity = "low" | "medium" | "high" | "critical";

export interface InspectionFinding {
    type: InspectionViolationType;
    severity: InspectionSeverity;
    message: string;
    confidence: number;       // 0.0 – 1.0
    score: number;            // contribuição ao risk score (0–100)
    detail?: string;
    evidence?: string;        // trecho anonimizado que ativou a detecção
    mitre?: string;           // MITRE ATT&CK technique ID (ex: "T1110.004")
}

export interface InspectionResult {
    ok: boolean;
    totalScore: number;
    severity: InspectionSeverity;
    findings: InspectionFinding[];
    fingerprint: RequestFingerprint;
    signals: BehavioralSignals;
    /** Metadados de auditoria */
    audit: {
        requestId: string;
        ip: string;
        timestamp: string;
        durationMs: number;
        inspectedBytes: number;
    };
}

export interface RequestFingerprint {
    /** Hash das características estruturais da requisição (não do conteúdo) */
    structuralHash: string;
    /** Headers presentes e sua ordem (indicativo de cliente) */
    headerOrder: string[];
    /** Versão HTTP detectada */
    httpVersion: string | null;
    /** Accept-Encoding indicado */
    acceptEncoding: string | null;
    /** Accept-Language indicado */
    acceptLanguage: string | null;
    /** Se possui características de headless browser */
    headlessIndicators: string[];
    /** Características que indicam automação */
    automationIndicators: string[];
    /** JA3-like fingerprint baseado em headers TLS expostos */
    tlsFingerprint: string | null;
}

export interface BehavioralSignals {
    /** Número de requests deste IP na janela de tempo */
    requestRate: number;
    /** Variação nos intervalos entre requests (baixa = automação) */
    timingVariance: number;
    /** Profundidade média de crawl (quantos paths distintos visitou) */
    crawlDepth: number;
    /** Se o padrão de acesso corresponde a scraping */
    scrapingScore: number;
    /** Se o padrão corresponde a credential stuffing */
    credentialStuffingScore: number;
    /** Se o padrão corresponde a enumeração */
    enumerationScore: number;
    /** Endpoints honeypot acionados por este IP */
    honeypotHits: number;
    /** Sequência de status codes (detecta enumeração por resposta) */
    recentStatusCodes: number[];
}

export interface InspectionOptions {
    /** Score máximo antes de considerar crítico (padrão: 80) */
    maxScore?: number;
    /** Tamanho máximo do payload a inspecionar em bytes (padrão: 512KB) */
    maxInspectBytes?: number;
    /** Se deve executar análise de payload profunda (padrão: true) */
    deepPayloadInspection?: boolean;
    /** Se deve detectar padrões de automação (padrão: true) */
    detectAutomation?: boolean;
    /** Se deve detectar timing attacks (padrão: true) */
    detectTimingAttacks?: boolean;
    /** Se deve verificar honeypots (padrão: true) */
    checkHoneypots?: boolean;
    /** Endpoints que funcionam como honeypot */
    honeypotPaths?: string[];
    /** Janela de tempo para análise comportamental em segundos (padrão: 60) */
    behaviorWindowSec?: number;
    /** Threshold de requests por janela para considerar flood (padrão: 200) */
    floodThreshold?: number;
    /** JA3 hashes bloqueados */
    blockedJA3?: string[];
    /** Modo de operação */
    mode?: "enforce" | "audit" | "off";
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES E PADRÕES
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULTS: Required<InspectionOptions> = {
    maxScore: 80,
    maxInspectBytes: 512 * 1024,
    deepPayloadInspection: true,
    detectAutomation: true,
    detectTimingAttacks: true,
    checkHoneypots: true,
    honeypotPaths: [
        "/.env",
        "/admin/config",
        "/api/internal/debug",
        "/wp-admin",
        "/phpmyadmin",
        "/.git/config",
        "/server-status",
        "/actuator/env",
    ],
    behaviorWindowSec: 60,
    floodThreshold: 200,
    blockedJA3: [],
    mode: "enforce",
};

// ─────────────────────────────────────────────────────────────────────────────
// PADRÕES DE EVASÃO DE ENCODING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Técnicas de encoding usadas para bypassar filtros de segurança.
 * Cada uma tem nome, descrição e pattern de detecção.
 */
const ENCODING_EVASION_PATTERNS: Array<{
    name: string;
    severity: InspectionSeverity;
    pattern: RegExp;
    mitre: string;
}> = [
        // Double URL encoding: %253C = %3C = <
        {
            name: "DOUBLE_URL_ENCODING",
            severity: "high",
            pattern: /%25[0-9a-fA-F]{2}/,
            mitre: "T1027",
        },
        // Unicode encoding: \u003c = <
        {
            name: "UNICODE_ESCAPE",
            severity: "medium",
            pattern: /\\u[0-9a-fA-F]{4}/i,
            mitre: "T1027",
        },
        // HTML entity encoding numérico: &#60; = <
        {
            name: "HTML_ENTITY_NUMERIC",
            severity: "medium",
            pattern: /&#x?[0-9a-fA-F]+;/i,
            mitre: "T1027",
        },
        // Base64 em contextos suspeitos (não em campos esperados)
        {
            name: "SUSPICIOUS_BASE64",
            severity: "medium",
            pattern: /(?:^|[^a-zA-Z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?:[^a-zA-Z0-9+/]|$)/,
            mitre: "T1132.001",
        },
        // Null byte para truncar strings em linguagens C
        {
            name: "NULL_BYTE_TRUNCATION",
            severity: "high",
            pattern: /(?:%00|\\x00|\x00)/i,
            mitre: "T1059",
        },
        // Overlong UTF-8 encoding
        {
            name: "OVERLONG_UTF8",
            severity: "high",
            pattern: /(?:%c0%a[ef]|%e0%80%a[ef])/i,
            mitre: "T1027",
        },
        // IFS (Internal Field Separator) em command injection
        {
            name: "IFS_EVASION",
            severity: "high",
            pattern: /\$IFS/,
            mitre: "T1059.004",
        },
        // Hex encoding de comandos: \x63\x61\x74 = cat
        {
            name: "HEX_ENCODING",
            severity: "medium",
            pattern: /(?:\\x[0-9a-fA-F]{2}){4,}/i,
            mitre: "T1027",
        },
        // Case variation para bypassar filtros case-sensitive
        {
            name: "CASE_VARIATION_BYPASS",
            pattern: /(?:ScRiPt|sElEcT|uNiOn|dRoP|iNsErT|uPdAtE)/,
            severity: "medium",
            mitre: "T1059",
        },
        // Whitespace alternativo: tab, form-feed, vertical-tab
        {
            name: "ALTERNATE_WHITESPACE",
            severity: "low",
            pattern: /[\t\v\f\r]+(?:SELECT|UNION|DROP|INSERT|UPDATE|DELETE)/i,
            mitre: "T1027",
        },
        // Unicode homoglyph em contexto de payload (já coberto em DNS, aqui no body)
        {
            name: "UNICODE_HOMOGLYPH_PAYLOAD",
            severity: "medium",
            pattern: /[\u0430\u0435\u043E\u0440\u0441\u0445\u0443]{3,}/,
            mitre: "T1036",
        },
    ];

// ─────────────────────────────────────────────────────────────────────────────
// PADRÕES DE EXFILTRAÇÃO
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Padrões que indicam tentativa de exfiltrar dados sensíveis.
 */
const EXFILTRATION_PATTERNS: Array<{
    name: string;
    severity: InspectionSeverity;
    pattern: RegExp;
    mitre: string;
}> = [
        // Formato de cartão de crédito
        {
            name: "CREDIT_CARD_NUMBER",
            severity: "critical",
            pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
            mitre: "T1530",
        },
        // CPF brasileiro
        {
            name: "CPF_NUMBER",
            severity: "high",
            pattern: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/,
            mitre: "T1530",
        },
        // CNPJ brasileiro
        {
            name: "CNPJ_NUMBER",
            severity: "high",
            pattern: /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/,
            mitre: "T1530",
        },
        // Chave privada PEM
        {
            name: "PRIVATE_KEY",
            severity: "critical",
            pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
            mitre: "T1552.004",
        },
        // Token JWT em resposta (pode indicar vazamento)
        {
            name: "JWT_TOKEN",
            severity: "high",
            pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
            mitre: "T1528",
        },
        // AWS Access Key
        {
            name: "AWS_ACCESS_KEY",
            severity: "critical",
            pattern: /AKIA[0-9A-Z]{16}/,
            mitre: "T1552.005",
        },
        // AWS Secret Key
        {
            name: "AWS_SECRET_KEY",
            severity: "critical",
            pattern: /[0-9a-zA-Z/+]{40}/,
            mitre: "T1552.005",
        },
        // Senha em plaintext em body/query
        {
            name: "PLAINTEXT_PASSWORD_FIELD",
            severity: "high",
            pattern: /(?:password|passwd|senha|secret|pwd)\s*[:=]\s*['"]?[^\s'"&]{8,}/i,
            mitre: "T1552",
        },
        // Connection string de banco de dados
        {
            name: "DATABASE_CONNECTION_STRING",
            severity: "critical",
            pattern: /(?:mongodb|postgres|mysql|mssql|redis):\/\/[^:]+:[^@]+@/i,
            mitre: "T1552",
        },
        // Variável de ambiente com secret
        {
            name: "ENV_SECRET_PATTERN",
            severity: "high",
            pattern: /(?:API_KEY|SECRET_KEY|PRIVATE_KEY|DATABASE_URL|JWT_SECRET)\s*=\s*[^\s]{8,}/i,
            mitre: "T1552.001",
        },
    ];

// ─────────────────────────────────────────────────────────────────────────────
// PADRÕES DE AUTOMAÇÃO E HEADLESS BROWSER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Headers e características que indicam headless browser ou framework de automação.
 */
const HEADLESS_INDICATORS: Array<{ name: string; check: (headers: Headers) => boolean }> = [
    {
        name: "PUPPETEER_UA",
        check: (h) => /HeadlessChrome/i.test(h.get("user-agent") ?? ""),
    },
    {
        name: "PLAYWRIGHT_UA",
        check: (h) => /Playwright/i.test(h.get("user-agent") ?? ""),
    },
    {
        name: "SELENIUM_HEADER",
        check: (h) => h.has("x-selenium-request") || h.has("x-webdriver"),
    },
    {
        name: "MISSING_ACCEPT_LANGUAGE",
        check: (h) => {
            const ua = h.get("user-agent") ?? "";
            const hasUA = ua.length > 20;
            const hasLang = h.has("accept-language");
            // Real browsers always send Accept-Language
            return hasUA && !hasLang;
        },
    },
    {
        name: "MISSING_ACCEPT_ENCODING",
        check: (h) => {
            const ua = h.get("user-agent") ?? "";
            const hasUA = ua.length > 20;
            const hasEncoding = h.has("accept-encoding");
            return hasUA && !hasEncoding;
        },
    },
    {
        name: "PHANTOM_JS_UA",
        check: (h) => /PhantomJS/i.test(h.get("user-agent") ?? ""),
    },
    {
        name: "ELECTRON_UA",
        check: (h) => /Electron/i.test(h.get("user-agent") ?? ""),
    },
    {
        name: "WEBDRIVER_HEADER",
        check: (h) =>
            h.has("sec-ch-ua") &&
            !h.has("sec-fetch-site") &&
            !h.has("sec-fetch-mode"),
    },
];

const AUTOMATION_FRAMEWORK_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    { name: "PYTHON_REQUESTS", pattern: /python-requests\/[0-9]/i },
    { name: "CURL_AUTOMATION", pattern: /^curl\/[0-9]/i },
    { name: "GO_HTTP", pattern: /^go-http-client\//i },
    { name: "JAVA_HTTP", pattern: /^java\//i },
    { name: "AXIOS", pattern: /axios\/[0-9]/i },
    { name: "GOT_HTTP", pattern: /^got\//i },
    { name: "NODE_FETCH", pattern: /node-fetch\/[0-9]/i },
    { name: "RUBY_NET_HTTP", pattern: /Ruby\/[0-9]/i },
    { name: "APACHE_HTTP", pattern: /Apache-HttpClient/i },
    { name: "OKHTTP", pattern: /okhttp\/[0-9]/i },
    { name: "SCRAPY_SPIDER", pattern: /Scrapy\/[0-9]/i },
    { name: "MECHANIZE", pattern: /mechanize/i },
    { name: "HTTPX", pattern: /^python-httpx/i },
];

// ─────────────────────────────────────────────────────────────────────────────
// PADRÕES DE POLYGLOT ATTACK
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Polyglots são payloads que são válidos em múltiplos contextos ao mesmo tempo
 * (ex: válido como JSON E como SQL). Extremamente difíceis de detectar com
 * filtros simples — requerem análise de contexto cruzado.
 */
const POLYGLOT_PATTERNS: Array<{ name: string; severity: InspectionSeverity; pattern: RegExp }> = [
    // JSON + XSS polyglot
    {
        name: "JSON_XSS_POLYGLOT",
        severity: "critical",
        pattern: /["']\s*[);}\]]\s*(?:alert|confirm|prompt|eval)\s*\(/i,
    },
    // SQL + XSS polyglot
    {
        name: "SQL_XSS_POLYGLOT",
        severity: "critical",
        pattern: /'\s*(?:OR|AND)\s+(?:1=1|'1'='1'|true).*<script/i,
    },
    // URL + HTML polyglot
    {
        name: "URL_HTML_POLYGLOT",
        severity: "high",
        pattern: /javascript:[^"']*<[^>]+>/i,
    },
    // SVG + script polyglot
    {
        name: "SVG_SCRIPT_POLYGLOT",
        severity: "critical",
        pattern: /<svg[^>]*>[\s\S]*?<script/i,
    },
    // IMG onerror polyglot
    {
        name: "IMG_ONERROR_POLYGLOT",
        severity: "critical",
        pattern: /<img[^>]+onerror\s*=\s*["']?[^"'>]+/i,
    },
    // Template + XSS
    {
        name: "TEMPLATE_XSS_POLYGLOT",
        severity: "high",
        pattern: /\{\{.*(?:constructor|__proto__|prototype).*\}\}/i,
    },
    // Prototype pollution polyglot
    {
        name: "PROTOTYPE_POLLUTION",
        severity: "critical",
        pattern: /(?:__proto__|constructor\.prototype|Object\.prototype)\s*[\[.]/i,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// ESTADO COMPORTAMENTAL (in-memory — em produção usar Redis/KV)
// ─────────────────────────────────────────────────────────────────────────────

interface IPBehaviorState {
    requests: Array<{ timestamp: number; path: string; status?: number; method: string }>;
    honeypotHits: number;
    firstSeen: number;
    lastSeen: number;
    uniquePaths: Set<string>;
    statusCodes: number[];
    failedAuths: number;
    lastFailedAuth: number;
}

/**
 * Registry de comportamento por IP.
 * Nota: In-memory — não persiste entre instâncias.
 * Para produção: substituir por upstash/redis ou Vercel KV.
 */
const behaviorRegistry = new Map<string, IPBehaviorState>();

/** Tamanho máximo do histórico por IP */
const MAX_HISTORY_SIZE = 500;

/** Tempo de expiração do estado em ms (padrão: 10 minutos) */
const STATE_TTL_MS = 10 * 60 * 1000;

/**
 * Obtém ou inicializa o estado comportamental de um IP.
 */
function getBehaviorState(ip: string): IPBehaviorState {
    const now = Date.now();

    if (behaviorRegistry.has(ip)) {
        const state = behaviorRegistry.get(ip)!;
        // Expira estado antigo
        if (now - state.lastSeen > STATE_TTL_MS) {
            behaviorRegistry.delete(ip);
        } else {
            return state;
        }
    }

    const fresh: IPBehaviorState = {
        requests: [],
        honeypotHits: 0,
        firstSeen: now,
        lastSeen: now,
        uniquePaths: new Set(),
        statusCodes: [],
        failedAuths: 0,
        lastFailedAuth: 0,
    };
    behaviorRegistry.set(ip, fresh);
    return fresh;
}

/**
 * Registra uma nova requisição no estado comportamental.
 */
export function recordRequest(
    ip: string,
    path: string,
    method: string,
    status?: number
): void {
    const state = getBehaviorState(ip);
    const now = Date.now();

    state.lastSeen = now;
    state.uniquePaths.add(path);

    if (status !== undefined) {
        state.statusCodes.push(status);
        if (state.statusCodes.length > MAX_HISTORY_SIZE) {
            state.statusCodes.shift();
        }
    }

    state.requests.push({ timestamp: now, path, status, method });
    if (state.requests.length > MAX_HISTORY_SIZE) {
        state.requests.shift();
    }

    behaviorRegistry.set(ip, state);
}

/**
 * Registra falha de autenticação — feed para detecção de credential stuffing.
 */
export function recordAuthFailure(ip: string): void {
    const state = getBehaviorState(ip);
    state.failedAuths++;
    state.lastFailedAuth = Date.now();
    behaviorRegistry.set(ip, state);
}

/**
 * Registra hit em endpoint honeypot.
 */
export function recordHoneypotHit(ip: string, path: string): void {
    const state = getBehaviorState(ip);
    state.honeypotHits++;
    recordRequest(ip, path, "GET");
    behaviorRegistry.set(ip, state);
}

// ─────────────────────────────────────────────────────────────────────────────
// ANÁLISE COMPORTAMENTAL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Calcula a variância de timing entre requests.
 * Baixa variância (<10ms) é forte indicador de automação.
 */
function calculateTimingVariance(
    requests: IPBehaviorState["requests"],
    windowMs: number
): number {
    const now = Date.now();
    const recent = requests.filter((r) => now - r.timestamp < windowMs);

    if (recent.length < 3) return 1000; // Dados insuficientes — assume humano

    const intervals: number[] = [];
    for (let i = 1; i < recent.length; i++) {
        intervals.push(recent[i]!.timestamp - recent[i - 1]!.timestamp);
    }

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance =
        intervals.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) /
        intervals.length;

    return Math.sqrt(variance); // Desvio padrão em ms
}

/**
 * Calcula score de scraping baseado em padrões de acesso.
 */
function calculateScrapingScore(state: IPBehaviorState, windowMs: number): number {
    const now = Date.now();
    const recent = state.requests.filter((r) => now - r.timestamp < windowMs);
    let score = 0;

    // Alto volume de requests em pouco tempo
    if (recent.length > 100) score += 30;
    if (recent.length > 200) score += 20;

    // Muitos paths únicos (breadth-first crawl)
    const uniqueInWindow = new Set(recent.map((r) => r.path)).size;
    if (uniqueInWindow > 50) score += 25;
    if (uniqueInWindow > 100) score += 15;

    // Padrão sequencial em paths (enumeração numérica)
    const numericPaths = recent.filter((r) => /\/\d+(?:\/|$)/.test(r.path));
    if (numericPaths.length > 20) score += 20;

    // Baixa variância de timing
    const variance = calculateTimingVariance(recent, windowMs);
    if (variance < 50) score += 30;
    if (variance < 10) score += 20;

    return Math.min(score, 100);
}

/**
 * Calcula score de credential stuffing.
 */
function calculateCredentialStuffingScore(
    state: IPBehaviorState,
    windowMs: number
): number {
    const now = Date.now();
    let score = 0;

    // Muitas falhas de autenticação
    if (state.failedAuths > 10) score += 40;
    if (state.failedAuths > 50) score += 30;

    // Falhas de auth recentes
    if (now - state.lastFailedAuth < windowMs && state.failedAuths > 3) {
        score += 20;
    }

    // Requests em paths de login/auth
    const recent = state.requests.filter((r) => now - r.timestamp < windowMs);
    const authPaths = recent.filter((r) =>
        /\/(login|signin|auth|token|oauth|session|password)/i.test(r.path)
    );
    if (authPaths.length > 5) score += 30;

    return Math.min(score, 100);
}

/**
 * Calcula score de enumeração de recursos.
 */
function calculateEnumerationScore(
    state: IPBehaviorState,
    windowMs: number
): number {
    const now = Date.now();
    const recent = state.requests.filter((r) => now - r.timestamp < windowMs);
    let score = 0;

    // Muitos 404s (endpoint enumeration)
    const notFounds = state.statusCodes.filter((s) => s === 404).length;
    if (notFounds > 20) score += 40;
    if (notFounds > 50) score += 30;

    // Muitos 401/403 (auth enumeration)
    const authErrors = state.statusCodes.filter(
        (s) => s === 401 || s === 403
    ).length;
    if (authErrors > 10) score += 30;

    // Paths com padrões de UUID ou ID sequencial
    const idPaths = recent.filter(
        (r) =>
            /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(r.path) ||
            /\/\d{4,}(?:\/|$)/.test(r.path)
    );
    if (idPaths.length > 15) score += 30;

    return Math.min(score, 100);
}

/**
 * Compila os sinais comportamentais de um IP.
 */
function compileBehavioralSignals(
    ip: string,
    windowSec: number
): BehavioralSignals {
    const windowMs = windowSec * 1000;
    const state = getBehaviorState(ip);
    const now = Date.now();
    const recent = state.requests.filter((r) => now - r.timestamp < windowMs);

    return {
        requestRate: recent.length,
        timingVariance: calculateTimingVariance(recent, windowMs),
        crawlDepth: state.uniquePaths.size,
        scrapingScore: calculateScrapingScore(state, windowMs),
        credentialStuffingScore: calculateCredentialStuffingScore(state, windowMs),
        enumerationScore: calculateEnumerationScore(state, windowMs),
        honeypotHits: state.honeypotHits,
        recentStatusCodes: state.statusCodes.slice(-20),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// FINGERPRINTING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Constrói o fingerprint estrutural da requisição.
 * Analisa características do cliente sem inspecionar o conteúdo.
 */
export function buildRequestFingerprint(
    request: NextRequest
): RequestFingerprint {
    const headers = request.headers;
    const headerOrder: string[] = [];
    headers.forEach((_, key) => headerOrder.push(key.toLowerCase()));

    // Detecta headless browser
    const headlessIndicators = HEADLESS_INDICATORS
        .filter(({ check }) => check(headers))
        .map(({ name }) => name);

    // Detecta frameworks de automação
    const ua = headers.get("user-agent") ?? "";
    const automationIndicators = AUTOMATION_FRAMEWORK_PATTERNS
        .filter(({ pattern }) => pattern.test(ua))
        .map(({ name }) => name);

    // TLS fingerprint simulado via headers expostos
    // (real JA3 requer acesso ao handshake TLS — não disponível no Edge Runtime)
    const tlsComponents = [
        headers.get("sec-ch-ua-platform") ?? "",
        headers.get("sec-ch-ua") ?? "",
        headers.get("sec-fetch-dest") ?? "",
        headers.get("accept-encoding") ?? "",
    ].join("|");

    const tlsFingerprint = tlsComponents.length > 3
        ? simpleHash(tlsComponents)
        : null;

    // Hash estrutural da requisição
    const structuralComponents = [
        request.method,
        headerOrder.sort().join(","),
        headers.get("accept") ?? "",
        headers.get("accept-encoding") ?? "",
        headers.get("accept-language") ?? "",
        headers.get("connection") ?? "",
    ].join("|");

    return {
        structuralHash: simpleHash(structuralComponents),
        headerOrder,
        httpVersion: headers.get("x-forwarded-proto") ?? null,
        acceptEncoding: headers.get("accept-encoding"),
        acceptLanguage: headers.get("accept-language"),
        headlessIndicators,
        automationIndicators,
        tlsFingerprint,
    };
}

/**
 * Hash FNV-1a simples e rápido para fingerprinting.
 * Não usar para criptografia — apenas para comparação estrutural.
 */
function simpleHash(input: string): string {
    let hash = 2166136261;
    for (let i = 0; i < input.length; i++) {
        hash ^= input.charCodeAt(i);
        hash = (hash * 16777619) >>> 0;
    }
    return hash.toString(16).padStart(8, "0");
}

// ─────────────────────────────────────────────────────────────────────────────
// INSPEÇÃO DE PAYLOAD
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Inspeciona o conteúdo bruto do payload em busca de anomalias.
 */
function inspectPayload(
    payload: string,
    contentType: string | null
): InspectionFinding[] {
    const findings: InspectionFinding[] = [];

    // ── Evasão de encoding ─────────────────────────────────────────────────────
    for (const { name, severity, pattern, mitre } of ENCODING_EVASION_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(payload);
        if (match) {
            findings.push({
                type: "ENCODING_EVASION",
                severity,
                message: `Encoding evasion technique detected: ${name}`,
                confidence: 0.85,
                score: severity === "critical" ? 80 : severity === "high" ? 60 : 30,
                evidence: match[0].slice(0, 50),
                mitre,
            });
        }
    }

    // ── Polyglot attacks ────────────────────────────────────────────────────────
    for (const { name, severity, pattern } of POLYGLOT_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(payload);
        if (match) {
            findings.push({
                type: "POLYGLOT_ATTACK",
                severity,
                message: `Polyglot attack pattern detected: ${name}`,
                confidence: 0.9,
                score: severity === "critical" ? 90 : 65,
                evidence: match[0].slice(0, 50),
                mitre: "T1059",
            });
        }
    }

    // ── Exfiltração de dados ────────────────────────────────────────────────────
    for (const { name, severity, pattern, mitre } of EXFILTRATION_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(payload)) {
            findings.push({
                type: "EXFILTRATION_PATTERN",
                severity,
                message: `Sensitive data pattern detected in payload: ${name}`,
                confidence: 0.8,
                score: severity === "critical" ? 85 : 55,
                detail: `Pattern type: ${name}`,
                mitre,
            });
        }
    }

    // ── MIME mismatch ───────────────────────────────────────────────────────────
    if (contentType) {
        const baseType = contentType.split(";")[0]?.trim() ?? "";

        if (baseType === "application/json") {
            try {
                JSON.parse(payload);
            } catch {
                // Declarou JSON mas não é JSON válido — possível evasão
                if (payload.trim().startsWith("<")) {
                    findings.push({
                        type: "MIME_MISMATCH",
                        severity: "high",
                        message: "Content-Type declares JSON but payload appears to be XML/HTML",
                        confidence: 0.9,
                        score: 55,
                        detail: "Possible MIME confusion attack",
                        mitre: "T1027",
                    });
                }
            }
        }
    }

    // ── Campos repetidos (billion laughs / ReDoS setup) ───────────────────────
    const repeatedPattern = /(.{3,})\1{100,}/;
    if (repeatedPattern.test(payload)) {
        findings.push({
            type: "REPEATED_CHAR_ATTACK",
            severity: "high",
            message: "Highly repetitive content detected — possible DoS or ReDoS setup",
            confidence: 0.95,
            score: 60,
            detail: "Pattern repetition exceeds 100x for a 3+ char sequence",
            mitre: "T1499.003",
        });
    }

    // ── Binário em payload de texto ─────────────────────────────────────────────
    if (contentType && /text|json|xml|form/i.test(contentType)) {
        // eslint-disable-next-line no-control-regex
        const binaryChars = payload.match(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g);
        if (binaryChars && binaryChars.length > 5) {
            findings.push({
                type: "BINARY_IN_TEXT",
                severity: "medium",
                message: `Binary characters detected in text payload (${binaryChars.length} occurrences)`,
                confidence: 0.75,
                score: 35,
                detail: "Binary data in text context may indicate shellcode or encoding evasion",
                mitre: "T1027.002",
            });
        }
    }

    // ── Unicode normalization attack ───────────────────────────────────────────
    // Caracteres que se normalizam para algo diferente (NFKC/NFKD)
    const hasComposedChars = /[\u00C0-\u024F\u1E00-\u1EFF]/.test(payload);
    if (hasComposedChars) {
        try {
            const normalized = payload.normalize("NFKC");
            if (normalized !== payload) {
                findings.push({
                    type: "UNICODE_NORMALIZATION_ATTACK",
                    severity: "medium",
                    message: "Payload contains characters that change under Unicode normalization",
                    confidence: 0.65,
                    score: 30,
                    detail: "NFKC normalization alters the payload — possible filter bypass",
                    mitre: "T1036",
                });
            }
        } catch {
            // normalize() não disponível — ignora
        }
    }

    return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// ANÁLISE COMPORTAMENTAL → FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

function analyzeBehavior(
    signals: BehavioralSignals,
    opts: Required<InspectionOptions>
): InspectionFinding[] {
    const findings: InspectionFinding[] = [];

    // Honeypot hit — altíssima certeza de ataque
    if (signals.honeypotHits > 0) {
        findings.push({
            type: "HONEYPOT_TRIGGERED",
            severity: "critical",
            message: `IP has triggered ${signals.honeypotHits} honeypot endpoint(s)`,
            confidence: 0.99,
            score: 90,
            detail: "Access to honeypot paths is never legitimate",
            mitre: "T1083",
        });
    }

    // Request flood
    if (signals.requestRate > opts.floodThreshold) {
        findings.push({
            type: "REQUEST_FLOOD",
            severity: "high",
            message: `Request rate ${signals.requestRate} exceeds flood threshold of ${opts.floodThreshold}`,
            confidence: 0.9,
            score: 70,
            mitre: "T1499",
        });
    }

    // Scraping
    if (signals.scrapingScore > 60) {
        findings.push({
            type: "SCRAPING_PATTERN",
            severity: signals.scrapingScore > 80 ? "high" : "medium",
            message: `Scraping behavior detected (score: ${signals.scrapingScore}/100)`,
            confidence: signals.scrapingScore / 100,
            score: Math.floor(signals.scrapingScore * 0.7),
            mitre: "T1119",
        });
    }

    // Credential stuffing
    if (signals.credentialStuffingScore > 50) {
        findings.push({
            type: "CREDENTIAL_STUFFING",
            severity: "critical",
            message: `Credential stuffing pattern detected (score: ${signals.credentialStuffingScore}/100)`,
            confidence: signals.credentialStuffingScore / 100,
            score: Math.floor(signals.credentialStuffingScore * 0.9),
            mitre: "T1110.004",
        });
    }

    // Enumeração
    if (signals.enumerationScore > 50) {
        findings.push({
            type: "ENUMERATION_RESOURCE",
            severity: "high",
            message: `Resource enumeration detected (score: ${signals.enumerationScore}/100)`,
            confidence: signals.enumerationScore / 100,
            score: Math.floor(signals.enumerationScore * 0.8),
            mitre: "T1083",
        });
    }

    // Timing muito baixo — automação
    if (signals.timingVariance < 20 && signals.requestRate > 10) {
        findings.push({
            type: "BOT_BEHAVIORAL_PATTERN",
            severity: "medium",
            message: `Suspiciously low timing variance (${signals.timingVariance.toFixed(1)}ms std dev)`,
            confidence: 0.8,
            score: 40,
            detail: "Human users have significantly higher timing variance",
            mitre: "T1595",
        });
    }

    // Lateral movement — muitos paths únicos profundos
    if (signals.crawlDepth > 200) {
        findings.push({
            type: "LATERAL_MOVEMENT",
            severity: "high",
            message: `IP has accessed ${signals.crawlDepth} unique paths — possible lateral movement`,
            confidence: 0.7,
            score: 50,
            mitre: "T1021",
        });
    }

    // Padrão de staging de dados — muitos GETs seguidos de POST grande
    const recentCodes = signals.recentStatusCodes;
    const successRate =
        recentCodes.filter((c) => c >= 200 && c < 300).length /
        Math.max(recentCodes.length, 1);
    if (successRate > 0.95 && signals.requestRate > 50) {
        findings.push({
            type: "DATA_STAGING",
            severity: "medium",
            message: "High success rate with high request volume — possible data staging",
            confidence: 0.6,
            score: 35,
            mitre: "T1074",
        });
    }

    return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// ANÁLISE DE FINGERPRINT → FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

function analyzeFingerprint(
    fingerprint: RequestFingerprint,
    opts: Required<InspectionOptions>
): InspectionFinding[] {
    const findings: InspectionFinding[] = [];

    // Headless browser
    if (fingerprint.headlessIndicators.length > 0) {
        findings.push({
            type: "HEADLESS_BROWSER",
            severity: "high",
            message: `Headless browser indicators detected: ${fingerprint.headlessIndicators.join(", ")}`,
            confidence: 0.9,
            score: 65,
            mitre: "T1595.003",
        });
    }

    // Framework de automação
    if (fingerprint.automationIndicators.length > 0) {
        findings.push({
            type: "AUTOMATION_FRAMEWORK",
            severity: "medium",
            message: `Automation framework detected: ${fingerprint.automationIndicators.join(", ")}`,
            confidence: 0.85,
            score: 45,
            mitre: "T1595",
        });
    }

    // JA3 blocklisted
    if (
        opts.blockedJA3.length > 0 &&
        fingerprint.tlsFingerprint &&
        opts.blockedJA3.includes(fingerprint.tlsFingerprint)
    ) {
        findings.push({
            type: "JA3_BLOCKLISTED",
            severity: "critical",
            message: `TLS fingerprint "${fingerprint.tlsFingerprint}" is in the blocklist`,
            confidence: 1.0,
            score: 95,
            mitre: "T1071.001",
        });
    }

    // Fingerprint inconsistente (UA diz Chrome mas faltam headers Chrome)
    const ua = fingerprint.headerOrder;
    const claimsChrome =
        !ua.includes("sec-ch-ua") &&
        fingerprint.headerOrder.some((h) => h === "user-agent");

    if (claimsChrome && !fingerprint.headerOrder.includes("sec-fetch-site")) {
        findings.push({
            type: "FINGERPRINT_MISMATCH",
            severity: "medium",
            message: "Browser fingerprint inconsistency — claimed browser vs actual header set mismatch",
            confidence: 0.7,
            score: 35,
            detail: "Missing Client Hints headers expected for modern Chrome",
            mitre: "T1036",
        });
    }

    return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// INSPEÇÃO PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executa inspeção profunda de tráfego em uma NextRequest.
 *
 * @example
 * ```ts
 * // Em um Route Handler ou middleware
 * const inspection = await inspectTraffic(request, {
 *   deepPayloadInspection: true,
 *   detectAutomation: true,
 *   honeypotPaths: ["/.env", "/admin/debug"],
 *   blockedJA3: ["abc123de"],
 * });
 *
 * if (!inspection.ok) {
 *   return buildInspectionResponse(inspection);
 * }
 *
 * // Acessa o nível de risco para decisões downstream
 * console.log("Risk score:", inspection.totalScore);
 * ```
 */
export async function inspectTraffic(
    request: NextRequest,
    options: InspectionOptions = {}
): Promise<InspectionResult> {
    const startTime = Date.now();
    const opts: Required<InspectionOptions> = { ...DEFAULTS, ...options };

    if (opts.mode === "off") {
        return buildEmptyResult(request, startTime);
    }

    const ip = extractIP(request);
    const url = new URL(request.url);
    const pathname = url.pathname;
    const allFindings: InspectionFinding[] = [];

    // ── 1. Fingerprint ─────────────────────────────────────────────────────────
    const fingerprint = buildRequestFingerprint(request);

    const fingerprintFindings = opts.detectAutomation
        ? analyzeFingerprint(fingerprint, opts)
        : [];
    allFindings.push(...fingerprintFindings);

    // ── 2. Honeypot ────────────────────────────────────────────────────────────
    if (opts.checkHoneypots) {
        const isHoneypot = opts.honeypotPaths.some(
            (hp) => pathname === hp || pathname.startsWith(hp + "/")
        );
        if (isHoneypot) {
            recordHoneypotHit(ip, pathname);
            allFindings.push({
                type: "HONEYPOT_TRIGGERED",
                severity: "critical",
                message: `Honeypot endpoint accessed: ${pathname}`,
                confidence: 1.0,
                score: 100,
                detail: "Access to this path is never legitimate",
                mitre: "T1083",
            });
        }
    }

    // ── 3. Behavioral analysis ─────────────────────────────────────────────────
    recordRequest(ip, pathname, request.method);
    const signals = compileBehavioralSignals(ip, opts.behaviorWindowSec);
    const behavioralFindings = analyzeBehavior(signals, opts);
    allFindings.push(...behavioralFindings);

    // ── 4. Deep payload inspection ─────────────────────────────────────────────
    let inspectedBytes = 0;

    if (
        opts.deepPayloadInspection &&
        ["POST", "PUT", "PATCH"].includes(request.method.toUpperCase())
    ) {
        try {
            const buffer = await request.arrayBuffer();
            inspectedBytes = buffer.byteLength;

            if (inspectedBytes > 0 && inspectedBytes <= opts.maxInspectBytes) {
                const payload = new TextDecoder("utf-8", { fatal: false }).decode(buffer);
                const contentType = request.headers.get("content-type");
                const payloadFindings = inspectPayload(payload, contentType);
                allFindings.push(...payloadFindings);
            } else if (inspectedBytes > opts.maxInspectBytes) {
                allFindings.push({
                    type: "PAYLOAD_ANOMALY",
                    severity: "medium",
                    message: `Payload size ${inspectedBytes} bytes exceeds deep inspection limit`,
                    confidence: 0.6,
                    score: 20,
                    detail: "Large payloads are inspected at boundary level only",
                });
            }
        } catch {
            // Body já foi consumido ou erro de leitura — não bloqueia
        }
    }

    // ── 5. Slow attack detection ────────────────────────────────────────────────
    if (opts.detectTimingAttacks) {
        const contentLength = parseInt(
            request.headers.get("content-length") ?? "0",
            10
        );
        const transferEncoding = request.headers.get("transfer-encoding") ?? "";

        // Slowloris: header Transfer-Encoding sem Content-Length, sem body
        if (
            transferEncoding === "chunked" &&
            contentLength === 0 &&
            !["GET", "HEAD", "OPTIONS"].includes(request.method.toUpperCase())
        ) {
            allFindings.push({
                type: "SLOW_BODY_ATTACK",
                severity: "high",
                message: "Possible Slowloris/slow body attack pattern detected",
                confidence: 0.7,
                score: 55,
                detail: "Chunked encoding without content-length on non-GET method",
                mitre: "T1499.002",
            });
        }
    }

    // ── 6. Compute final score e severity ──────────────────────────────────────
    const totalScore = allFindings.reduce((acc, f) => acc + f.score, 0);
    const cappedScore = Math.min(totalScore, 100);

    const severity = computeSeverity(cappedScore, allFindings);
    const ok =
        opts.mode === "audit" ||
        (cappedScore < opts.maxScore &&
            !allFindings.some(
                (f) =>
                    f.severity === "critical" ||
                    f.type === "HONEYPOT_TRIGGERED" ||
                    f.type === "JA3_BLOCKLISTED"
            ));

    const result: InspectionResult = {
        ok,
        totalScore: cappedScore,
        severity,
        findings: allFindings,
        fingerprint,
        signals,
        audit: {
            requestId: generateRequestId(),
            ip,
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            inspectedBytes,
        },
    };

    if (!ok) {
        logInspectionEvent(result);
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS INTERNOS
// ─────────────────────────────────────────────────────────────────────────────

function extractIP(request: NextRequest): string {
    return (
        request.headers.get("cf-connecting-ip") ??
        request.headers.get("x-real-ip") ??
        request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
        "unknown"
    );
}

function computeSeverity(
    score: number,
    findings: InspectionFinding[]
): InspectionSeverity {
    if (
        findings.some((f) => f.severity === "critical") ||
        score >= 80
    ) return "critical";
    if (score >= 60) return "high";
    if (score >= 30) return "medium";
    return "low";
}

function generateRequestId(): string {
    return `insp_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

function buildEmptyResult(
    request: NextRequest,
    startTime: number
): InspectionResult {
    return {
        ok: true,
        totalScore: 0,
        severity: "low",
        findings: [],
        fingerprint: buildRequestFingerprint(request),
        signals: {
            requestRate: 0,
            timingVariance: 1000,
            crawlDepth: 0,
            scrapingScore: 0,
            credentialStuffingScore: 0,
            enumerationScore: 0,
            honeypotHits: 0,
            recentStatusCodes: [],
        },
        audit: {
            requestId: generateRequestId(),
            ip: extractIP(request),
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            inspectedBytes: 0,
        },
    };
}

function logInspectionEvent(result: InspectionResult): void {
    console.warn("[TRAFFIC_INSPECTION] Threat detected", {
        requestId: result.audit.requestId,
        ip: result.audit.ip,
        score: result.totalScore,
        severity: result.severity,
        findings: result.findings.map((f) => ({
            type: f.type,
            severity: f.severity,
            score: f.score,
            confidence: f.confidence,
            mitre: f.mitre,
        })),
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTRUTOR DE RESPOSTA
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Constrói a NextResponse de erro para uma inspeção bloqueada.
 */
export function buildInspectionResponse(
    result: InspectionResult
): NextResponse {
    const isDev = process.env.NODE_ENV === "development";

    const statusBySeverity: Record<InspectionSeverity, number> = {
        low: 400,
        medium: 400,
        high: 403,
        critical: 403,
    };

    return new NextResponse(
        JSON.stringify({
            error: "Request blocked",
            requestId: result.audit.requestId,
            ...(isDev && {
                debug: {
                    score: result.totalScore,
                    severity: result.severity,
                    findings: result.findings.map((f) => ({
                        type: f.type,
                        severity: f.severity,
                        message: f.message,
                        score: f.score,
                        mitre: f.mitre,
                    })),
                },
            }),
        }),
        {
            status: statusBySeverity[result.severity],
            headers: {
                "Content-Type": "application/json",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Cache-Control": "no-store",
            },
        }
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE WRAPPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrapper completo para Route Handlers e middleware.ts do Next.js.
 *
 * @example
 * ```ts
 * // app/api/users/route.ts
 * export async function POST(req: NextRequest) {
 *   return withTrafficInspection(req, async (inspection) => {
 *     // inspection.signals.scrapingScore disponível para lógica de negócio
 *     const data = await processRequest(req);
 *     return NextResponse.json(data);
 *   }, {
 *     honeypotPaths: ["/.env", "/debug"],
 *     detectAutomation: true,
 *   });
 * }
 * ```
 */
export async function withTrafficInspection(
    request: NextRequest,
    handler: (inspection: InspectionResult) => Promise<NextResponse>,
    options: InspectionOptions = {}
): Promise<NextResponse> {
    const result = await inspectTraffic(request, options);

    if (!result.ok) {
        return buildInspectionResponse(result);
    }

    return handler(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

export {
    ENCODING_EVASION_PATTERNS,
    EXFILTRATION_PATTERNS,
    POLYGLOT_PATTERNS,
    HEADLESS_INDICATORS,
    AUTOMATION_FRAMEWORK_PATTERNS,
    behaviorRegistry,
    DEFAULTS as INSPECTION_DEFAULTS,
};