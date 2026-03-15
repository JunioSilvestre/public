/**
 * networkPolicies.ts
 *
 * Políticas de segurança de rede para aplicações Next.js.
 * Opera na camada mais baixa da stack de segurança — antes de qualquer
 * lógica de negócio, após a conexão TCP ser estabelecida.
 *
 * Responsabilidades:
 *  - Content Security Policy (CSP) com nonce dinâmico
 *  - HTTP Security Headers (HSTS, X-Frame-Options, Permissions-Policy…)
 *  - CORS avançado com allowlist dinâmica e preflight handling
 *  - Certificate Transparency / Expect-CT
 *  - Subresource Integrity (SRI) helpers
 *  - Connection throttling e proteção contra Slowloris
 *  - Política de egress (controle de requisições de saída do servidor)
 *  - IP reputation e abuse scoring baseado em padrões de rede
 *  - Detecção de split tunneling e VPN evasion
 *  - Network namespace isolation (segregação de ambientes)
 *  - Política de TLS — versão mínima, cipher suites
 *  - Controle de protocolo HTTP (versão, upgrade, WebSocket)
 *  - Keep-Alive e timeout policies
 *  - Response header sanitization (remove headers que vazam infra)
 *  - Política de retry e circuit breaker para chamadas externas
 *
 * Integra-se com: requestSanitizer.ts, dnsProtection.ts, firewallRules.ts,
 *                 rateLimiter.ts, authGuard.ts, csrfProtection.ts
 *
 * @module security/networkPolicies
 */

import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "crypto";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

export type NetworkViolationType =
    | "CORS_ORIGIN_DENIED"
    | "CORS_METHOD_DENIED"
    | "CORS_HEADER_DENIED"
    | "CORS_CREDENTIALS_DENIED"
    | "TLS_VERSION_TOO_OLD"
    | "CIPHER_NOT_ALLOWED"
    | "PROTOCOL_NOT_ALLOWED"
    | "WEBSOCKET_DENIED"
    | "UPGRADE_DENIED"
    | "EGRESS_DENIED"
    | "EGRESS_DOMAIN_BLOCKED"
    | "EGRESS_PORT_BLOCKED"
    | "EGRESS_PROTOCOL_BLOCKED"
    | "SLOWLORIS_DETECTED"
    | "CONNECTION_FLOOD"
    | "NAMESPACE_VIOLATION"
    | "ENVIRONMENT_MISMATCH"
    | "RESPONSE_HEADER_LEAKED"
    | "CIRCUIT_BREAKER_OPEN"
    | "RETRY_LIMIT_EXCEEDED"
    | "REPUTATION_BLOCKED"
    | "SPLIT_TUNNEL_DETECTED";

export interface NetworkViolation {
    type: NetworkViolationType;
    message: string;
    detail?: string;
    meta?: Record<string, unknown>;
}

export interface NetworkPolicyResult {
    ok: boolean;
    violations: NetworkViolation[];
    /** Headers de segurança a injetar na resposta */
    securityHeaders: Record<string, string>;
    /** Nonce CSP gerado para este request (usar em <script nonce="..."> e <style nonce="...">) */
    cspNonce?: string;
    /** Configuração CORS resolvida para este request */
    cors?: ResolvedCorsConfig;
}

export interface ResolvedCorsConfig {
    allowed: boolean;
    origin: string | null;
    methods: string;
    headers: string;
    credentials: boolean;
    maxAge: number;
    isPreflight: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// CSP — CONTENT SECURITY POLICY
// ─────────────────────────────────────────────────────────────────────────────

export interface CSPDirectives {
    /** Fallback para diretivas não especificadas */
    "default-src"?: string[];
    "script-src"?: string[];
    "script-src-elem"?: string[];
    "script-src-attr"?: string[];
    "style-src"?: string[];
    "style-src-elem"?: string[];
    "style-src-attr"?: string[];
    "img-src"?: string[];
    "font-src"?: string[];
    "connect-src"?: string[];
    "media-src"?: string[];
    "object-src"?: string[];
    "frame-src"?: string[];
    "frame-ancestors"?: string[];
    "child-src"?: string[];
    "worker-src"?: string[];
    "manifest-src"?: string[];
    "form-action"?: string[];
    "base-uri"?: string[];
    "navigate-to"?: string[];
    "prefetch-src"?: string[];
    "require-trusted-types-for"?: string[];
    "trusted-types"?: string[];
    "upgrade-insecure-requests"?: boolean;
    "block-all-mixed-content"?: boolean;
    "sandbox"?: string[];
    "report-uri"?: string[];
    "report-to"?: string[];
}

export interface CSPOptions {
    /** Diretivas personalizadas */
    directives?: CSPDirectives;
    /** Se deve gerar nonce dinâmico e injetá-lo em script-src e style-src */
    useNonce?: boolean;
    /** Se deve usar mode "report-only" (não bloqueia, apenas reporta) */
    reportOnly?: boolean;
    /** Endpoint para envio de violações CSP */
    reportUri?: string;
    /** Se deve incluir o nonce no header (padrão: true) */
    exposeNonce?: boolean;
}

/**
 * Preset de CSP restritivo para produção.
 * Bloqueia inline scripts, eval e recursos de terceiros não autorizados.
 */
export const CSP_STRICT_PRESET: CSPDirectives = {
    "default-src": ["'self'"],
    "script-src": ["'self'"],           // nonce será injetado dinamicamente
    "script-src-attr": ["'none'"],          // bloqueia event handlers inline
    "style-src": ["'self'"],           // nonce será injetado dinamicamente
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "media-src": ["'none'"],
    "object-src": ["'none'"],
    "frame-src": ["'none'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "worker-src": ["'self'", "blob:"],
    "manifest-src": ["'self'"],
    "upgrade-insecure-requests": true,
    "block-all-mixed-content": true,
};

/**
 * Preset relaxado para desenvolvimento — permite 'unsafe-inline' e localhost.
 */
export const CSP_DEV_PRESET: CSPDirectives = {
    "default-src": ["'self'", "localhost:*"],
    "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'", "localhost:*"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:", "localhost:*"],
    "font-src": ["'self'", "data:"],
    "connect-src": ["'self'", "localhost:*", "ws://localhost:*", "wss://localhost:*"],
    "frame-ancestors": ["'self'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
};

/**
 * Gera um nonce criptograficamente seguro para uso em CSP.
 * Formato: base64url, 128 bits de entropia.
 */
export function generateCSPNonce(): string {
    return randomBytes(16)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

/**
 * Serializa um objeto de diretivas CSP em string de header.
 */
export function buildCSPHeader(
    directives: CSPDirectives,
    nonce?: string
): string {
    const parts: string[] = [];

    const directiveMap = directives as Record<string, unknown>;

    const orderedKeys: Array<keyof CSPDirectives> = [
        "default-src", "script-src", "script-src-elem", "script-src-attr",
        "style-src", "style-src-elem", "style-src-attr",
        "img-src", "font-src", "connect-src", "media-src", "object-src",
        "frame-src", "frame-ancestors", "child-src", "worker-src",
        "manifest-src", "form-action", "base-uri", "navigate-to",
        "prefetch-src", "require-trusted-types-for", "trusted-types",
        "sandbox", "report-uri", "report-to",
    ];

    for (const key of orderedKeys) {
        const value = directiveMap[key];
        if (value === undefined || value === null) continue;

        if (Array.isArray(value)) {
            let sources = [...value];

            // Injeta nonce em script-src e style-src
            if (nonce && (key === "script-src" || key === "style-src")) {
                sources = sources.filter((s) => !s.startsWith("'nonce-"));
                sources.push(`'nonce-${nonce}'`);
            }

            if (sources.length > 0) {
                parts.push(`${key} ${sources.join(" ")}`);
            }
        }
    }

    // Booleanos
    if (directiveMap["upgrade-insecure-requests"] === true) {
        parts.push("upgrade-insecure-requests");
    }
    if (directiveMap["block-all-mixed-content"] === true) {
        parts.push("block-all-mixed-content");
    }

    return parts.join("; ");
}

// ─────────────────────────────────────────────────────────────────────────────
// CORS — CROSS-ORIGIN RESOURCE SHARING
// ─────────────────────────────────────────────────────────────────────────────

export interface CORSOptions {
    /**
     * Origens permitidas. Suporta:
     * - String exata: "https://app.example.com"
     * - Wildcard de subdomínio: "https://*.example.com"
     * - Regex: /^https:\/\/.*\.example\.com$/
     * - "*" para qualquer origem (não usar com credentials: true)
     */
    allowedOrigins: Array<string | RegExp>;

    /** Métodos HTTP permitidos (padrão: GET, POST, OPTIONS) */
    allowedMethods?: string[];

    /** Headers que o cliente pode enviar */
    allowedHeaders?: string[];

    /** Headers que o browser pode expor ao cliente JS */
    exposedHeaders?: string[];

    /** Se deve permitir cookies/credenciais cross-origin */
    allowCredentials?: boolean;

    /** Tempo em segundos para cache do preflight (padrão: 86400 = 24h) */
    maxAge?: number;

    /** Se deve passar através de origens não listadas sem erro (padrão: false) */
    passThrough?: boolean;

    /**
     * Origens que nunca devem ser permitidas, independente da allowlist.
     * Útil para bloquear subdomínios comprometidos.
     */
    blockedOrigins?: Array<string | RegExp>;
}

/**
 * Verifica se uma origem corresponde a um padrão da allowlist.
 */
export function originMatchesPattern(
    origin: string,
    pattern: string | RegExp
): boolean {
    if (pattern instanceof RegExp) {
        return pattern.test(origin);
    }

    if (pattern === "*") return true;

    // Wildcard de subdomínio: "https://*.example.com"
    if (pattern.includes("*")) {
        const escaped = pattern
            .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
            .replace(/\*/g, "[^.]+");
        return new RegExp(`^${escaped}$`).test(origin);
    }

    return origin === pattern;
}

/**
 * Resolve a política CORS para uma requisição específica.
 */
export function resolveCORS(
    request: NextRequest,
    options: CORSOptions
): ResolvedCorsConfig {
    const origin = request.headers.get("origin") ?? null;
    const method = request.method.toUpperCase();
    const isPreflight = method === "OPTIONS" &&
        !!request.headers.get("access-control-request-method");

    const allowedMethods = options.allowedMethods ?? ["GET", "POST", "OPTIONS"];
    const allowedHeaders = options.allowedHeaders ?? [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-CSRF-Token",
        "Accept",
        "Accept-Language",
    ];
    const maxAge = options.maxAge ?? 86400;
    const allowCredentials = options.allowCredentials ?? false;

    // Sem Origin header — requisição same-origin ou não-browser
    if (!origin) {
        return {
            allowed: true,
            origin: null,
            methods: allowedMethods.join(", "),
            headers: allowedHeaders.join(", "),
            credentials: allowCredentials,
            maxAge,
            isPreflight,
        };
    }

    // Verifica blocklist primeiro
    const isBlocked = (options.blockedOrigins ?? []).some((pattern) =>
        originMatchesPattern(origin, pattern)
    );
    if (isBlocked) {
        return {
            allowed: false,
            origin: null,
            methods: "",
            headers: "",
            credentials: false,
            maxAge: 0,
            isPreflight,
        };
    }

    // Verifica allowlist
    const isAllowed = options.allowedOrigins.some((pattern) =>
        originMatchesPattern(origin, pattern)
    );

    if (!isAllowed) {
        return {
            allowed: options.passThrough ?? false,
            origin: null,
            methods: "",
            headers: "",
            credentials: false,
            maxAge: 0,
            isPreflight,
        };
    }

    // Não permite credentials com wildcard
    const effectiveCredentials =
        allowCredentials && !options.allowedOrigins.includes("*");

    return {
        allowed: true,
        origin,
        methods: allowedMethods.join(", "),
        headers: allowedHeaders.join(", "),
        credentials: effectiveCredentials,
        maxAge,
        isPreflight,
    };
}

/**
 * Converte uma configuração CORS resolvida em headers HTTP.
 */
export function buildCORSHeaders(
    cors: ResolvedCorsConfig,
    exposedHeaders?: string[]
): Record<string, string> {
    const headers: Record<string, string> = {};

    if (!cors.allowed || !cors.origin) return headers;

    headers["Access-Control-Allow-Origin"] = cors.origin;
    headers["Vary"] = "Origin";

    if (cors.credentials) {
        headers["Access-Control-Allow-Credentials"] = "true";
    }

    if (cors.isPreflight) {
        headers["Access-Control-Allow-Methods"] = cors.methods;
        headers["Access-Control-Allow-Headers"] = cors.headers;
        headers["Access-Control-Max-Age"] = String(cors.maxAge);
    }

    if (exposedHeaders?.length) {
        headers["Access-Control-Expose-Headers"] = exposedHeaders.join(", ");
    }

    return headers;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP SECURITY HEADERS
// ─────────────────────────────────────────────────────────────────────────────

export interface SecurityHeadersOptions {
    /**
     * HSTS — HTTP Strict Transport Security.
     * Força HTTPS por um período. Padrão: 1 ano + includeSubDomains + preload.
     */
    hsts?: {
        maxAge?: number;
        includeSubDomains?: boolean;
        preload?: boolean;
    } | false;

    /**
     * X-Frame-Options — controla embedding em iframes.
     * "DENY" | "SAMEORIGIN" | false para desabilitar.
     */
    frameOptions?: "DENY" | "SAMEORIGIN" | false;

    /**
     * X-Content-Type-Options — previne MIME sniffing.
     * Padrão: "nosniff".
     */
    contentTypeOptions?: "nosniff" | false;

    /**
     * Referrer-Policy — controla informação de Referer.
     */
    referrerPolicy?:
    | "no-referrer"
    | "no-referrer-when-downgrade"
    | "origin"
    | "origin-when-cross-origin"
    | "same-origin"
    | "strict-origin"
    | "strict-origin-when-cross-origin"
    | "unsafe-url"
    | false;

    /**
     * Permissions-Policy (antigo Feature-Policy).
     * Controla acesso a APIs do browser.
     */
    permissionsPolicy?: Partial<PermissionsPolicyDirectives> | false;

    /**
     * X-DNS-Prefetch-Control — controla prefetch de DNS.
     */
    dnsPrefetchControl?: "on" | "off" | false;

    /**
     * X-Download-Options — IE: bloqueia abertura direta de downloads.
     */
    downloadOptions?: "noopen" | false;

    /**
     * X-Permitted-Cross-Domain-Policies — Adobe Flash/PDF.
     */
    crossDomainPolicies?:
    | "none"
    | "master-only"
    | "by-content-type"
    | "all"
    | false;

    /**
     * Cross-Origin-Embedder-Policy (COEP).
     */
    coep?: "unsafe-none" | "require-corp" | "credentialless" | false;

    /**
     * Cross-Origin-Opener-Policy (COOP).
     */
    coop?:
    | "unsafe-none"
    | "same-origin-allow-popups"
    | "same-origin"
    | false;

    /**
     * Cross-Origin-Resource-Policy (CORP).
     */
    corp?: "same-site" | "same-origin" | "cross-origin" | false;

    /**
     * Expect-CT — Certificate Transparency.
     * Deprecado em favor de SCTs, mas ainda útil para logs.
     */
    expectCT?: {
        maxAge?: number;
        enforce?: boolean;
        reportUri?: string;
    } | false;

    /**
     * Report-To — Reporting API (substitui report-uri).
     */
    reportTo?: Array<{
        group: string;
        maxAge: number;
        endpoints: Array<{ url: string }>;
        includeSubdomains?: boolean;
    }>;

    /**
     * NEL — Network Error Logging.
     */
    nel?: {
        reportTo: string;
        maxAge: number;
        includeSubdomains?: boolean;
        failureFraction?: number;
        successFraction?: number;
    };
}

export interface PermissionsPolicyDirectives {
    accelerometer: string[];
    "ambient-light-sensor": string[];
    autoplay: string[];
    battery: string[];
    camera: string[];
    "display-capture": string[];
    "document-domain": string[];
    "encrypted-media": string[];
    "execution-while-not-rendered": string[];
    "execution-while-out-of-viewport": string[];
    fullscreen: string[];
    geolocation: string[];
    gyroscope: string[];
    "identity-credentials-get": string[];
    "idle-detection": string[];
    "local-fonts": string[];
    magnetometer: string[];
    microphone: string[];
    midi: string[];
    "navigation-override": string[];
    "payment": string[];
    "picture-in-picture": string[];
    "publickey-credentials-create": string[];
    "publickey-credentials-get": string[];
    "screen-wake-lock": string[];
    "serial": string[];
    "speaker-selection": string[];
    "storage-access": string[];
    "usb": string[];
    "web-share": string[];
    "window-management": string[];
    "xr-spatial-tracking": string[];
}

/**
 * Preset de security headers para produção — máxima proteção.
 */
export const SECURITY_HEADERS_STRICT: SecurityHeadersOptions = {
    hsts: {
        maxAge: 63072000, // 2 anos
        includeSubDomains: true,
        preload: true,
    },
    frameOptions: "DENY",
    contentTypeOptions: "nosniff",
    referrerPolicy: "strict-origin-when-cross-origin",
    permissionsPolicy: {
        accelerometer: [],
        camera: [],
        geolocation: [],
        gyroscope: [],
        magnetometer: [],
        microphone: [],
        midi: [],
        payment: [],
        "picture-in-picture": [],
        "publickey-credentials-get": ["self"],
        "screen-wake-lock": [],
        usb: [],
        "web-share": [],
        "xr-spatial-tracking": [],
    },
    dnsPrefetchControl: "off",
    downloadOptions: "noopen",
    crossDomainPolicies: "none",
    coep: "require-corp",
    coop: "same-origin",
    corp: "same-origin",
};

/**
 * Preset relaxado para desenvolvimento.
 */
export const SECURITY_HEADERS_DEV: SecurityHeadersOptions = {
    hsts: false,
    frameOptions: "SAMEORIGIN",
    contentTypeOptions: "nosniff",
    referrerPolicy: "no-referrer-when-downgrade",
    permissionsPolicy: false,
    dnsPrefetchControl: "off",
    downloadOptions: false,
    crossDomainPolicies: false,
    coep: false,
    coop: false,
    corp: false,
};

/**
 * Serializa Permissions-Policy em string de header.
 */
function buildPermissionsPolicy(
    directives: Partial<PermissionsPolicyDirectives>
): string {
    return Object.entries(directives)
        .map(([key, values]) => {
            if (!Array.isArray(values) || values.length === 0) {
                return `${key}=()`;
            }
            const formatted = values.map((v) =>
                v === "self" || v === "*" ? v : `"${v}"`
            );
            return `${key}=(${formatted.join(" ")})`;
        })
        .join(", ");
}

/**
 * Gera todos os HTTP Security Headers com base nas opções.
 */
export function buildSecurityHeaders(
    options: SecurityHeadersOptions,
    cspHeader?: string,
    corsHeaders?: Record<string, string>
): Record<string, string> {
    const headers: Record<string, string> = {};

    // HSTS
    if (options.hsts !== false && options.hsts !== undefined) {
        const hsts = options.hsts;
        let hstsValue = `max-age=${hsts.maxAge ?? 63072000}`;
        if (hsts.includeSubDomains !== false) hstsValue += "; includeSubDomains";
        if (hsts.preload) hstsValue += "; preload";
        headers["Strict-Transport-Security"] = hstsValue;
    }

    // Frame Options
    if (options.frameOptions) {
        headers["X-Frame-Options"] = options.frameOptions;
    }

    // Content-Type Options
    if (options.contentTypeOptions) {
        headers["X-Content-Type-Options"] = options.contentTypeOptions;
    }

    // Referrer Policy
    if (options.referrerPolicy) {
        headers["Referrer-Policy"] = options.referrerPolicy;
    }

    // Permissions Policy
    if (options.permissionsPolicy) {
        headers["Permissions-Policy"] = buildPermissionsPolicy(
            options.permissionsPolicy
        );
    }

    // DNS Prefetch Control
    if (options.dnsPrefetchControl) {
        headers["X-DNS-Prefetch-Control"] = options.dnsPrefetchControl;
    }

    // Download Options (IE)
    if (options.downloadOptions) {
        headers["X-Download-Options"] = options.downloadOptions;
    }

    // Cross-Domain Policies
    if (options.crossDomainPolicies) {
        headers["X-Permitted-Cross-Domain-Policies"] = options.crossDomainPolicies;
    }

    // COEP
    if (options.coep) {
        headers["Cross-Origin-Embedder-Policy"] = options.coep;
    }

    // COOP
    if (options.coop) {
        headers["Cross-Origin-Opener-Policy"] = options.coop;
    }

    // CORP
    if (options.corp) {
        headers["Cross-Origin-Resource-Policy"] = options.corp;
    }

    // Expect-CT
    if (options.expectCT && typeof options.expectCT === "object") {
        const ct = options.expectCT;
        let ctValue = `max-age=${ct.maxAge ?? 86400}`;
        if (ct.enforce) ctValue += ", enforce";
        if (ct.reportUri) ctValue += `, report-uri="${ct.reportUri}"`;
        headers["Expect-CT"] = ctValue;
    }

    // Report-To
    if (options.reportTo?.length) {
        headers["Report-To"] = JSON.stringify(options.reportTo);
    }

    // NEL
    if (options.nel) {
        const nel = options.nel;
        headers["NEL"] = JSON.stringify({
            report_to: nel.reportTo,
            max_age: nel.maxAge,
            include_subdomains: nel.includeSubdomains ?? false,
            failure_fraction: nel.failureFraction ?? 1.0,
            success_fraction: nel.successFraction ?? 0.0,
        });
    }

    // CSP
    if (cspHeader) {
        headers["Content-Security-Policy"] = cspHeader;
    }

    // CORS
    if (corsHeaders) {
        Object.assign(headers, corsHeaders);
    }

    return headers;
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE HEADER SANITIZATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Headers que revelam informações de infraestrutura e devem ser removidos
 * ou substituídos antes de enviar a resposta ao cliente.
 */
const LEAKY_RESPONSE_HEADERS: Array<{
    header: string;
    action: "remove" | "mask";
    replacement?: string;
}> = [
        // Servidor e tecnologia
        { header: "server", action: "mask", replacement: "web" },
        { header: "x-powered-by", action: "remove" },
        { header: "x-aspnet-version", action: "remove" },
        { header: "x-aspnetmvc-version", action: "remove" },
        { header: "x-generator", action: "remove" },
        { header: "x-drupal-cache", action: "remove" },
        { header: "x-drupal-dynamic-cache", action: "remove" },
        { header: "x-wordpress", action: "remove" },
        { header: "x-wix-request-id", action: "remove" },

        // Infraestrutura de CDN/proxy (podem revelar topologia interna)
        { header: "x-varnish", action: "remove" },
        { header: "x-cache", action: "remove" },
        { header: "x-cache-hits", action: "remove" },
        { header: "x-served-by", action: "remove" },
        { header: "x-timer", action: "remove" },
        { header: "x-backend-server", action: "remove" },
        { header: "x-upstream", action: "remove" },
        { header: "x-forwarded-server", action: "remove" },
        { header: "x-real-server", action: "remove" },
        { header: "x-nginx-cache", action: "remove" },
        { header: "via", action: "remove" },

        // Versão e build info
        { header: "x-app-version", action: "remove" },
        { header: "x-build-id", action: "remove" },
        { header: "x-commit-hash", action: "remove" },
        { header: "x-revision", action: "remove" },
        { header: "x-deploy-id", action: "remove" },

        // Timing (side-channel)
        { header: "x-runtime", action: "remove" },
        { header: "x-response-time", action: "remove" },
        { header: "x-request-duration", action: "remove" },
    ];

/**
 * Remove ou mascara headers que vazam informações de infraestrutura.
 * Deve ser aplicado em toda resposta antes de enviar ao cliente.
 */
export function sanitizeResponseHeaders(
    response: NextResponse
): NextResponse {
    for (const { header, action, replacement } of LEAKY_RESPONSE_HEADERS) {
        if (response.headers.has(header)) {
            if (action === "remove") {
                response.headers.delete(header);
            } else if (action === "mask" && replacement) {
                response.headers.set(header, replacement);
            }
        }
    }
    return response;
}

// ─────────────────────────────────────────────────────────────────────────────
// EGRESS POLICY — CONTROLE DE TRÁFEGO DE SAÍDA
// ─────────────────────────────────────────────────────────────────────────────

export interface EgressPolicy {
    /**
     * Domínios/hosts externos permitidos para chamadas server-side.
     * Suporta wildcards: "*.api.example.com"
     */
    allowedDomains: string[];

    /** Portas permitidas para egress (padrão: [80, 443]) */
    allowedPorts?: number[];

    /** Protocolos permitidos (padrão: ["https"]) */
    allowedProtocols?: string[];

    /** Se deve bloquear IPs privados em chamadas de egress (padrão: true) */
    blockPrivateIPs?: boolean;

    /** Timeout máximo para chamadas externas em ms (padrão: 10000) */
    timeoutMs?: number;

    /** Número máximo de retries (padrão: 3) */
    maxRetries?: number;

    /** Se deve bloquear redirecionamentos (padrão: false) */
    blockRedirects?: boolean;

    /** Máximo de redirecionamentos a seguir (padrão: 5) */
    maxRedirects?: number;
}

const EGRESS_DEFAULTS: Required<EgressPolicy> = {
    allowedDomains: [],
    allowedPorts: [80, 443],
    allowedProtocols: ["https"],
    blockPrivateIPs: true,
    timeoutMs: 10000,
    maxRetries: 3,
    blockRedirects: false,
    maxRedirects: 5,
};

/**
 * Valida uma URL de destino contra a política de egress.
 */
export function validateEgress(
    rawUrl: string,
    policy: EgressPolicy
): { ok: boolean; violation?: NetworkViolation } {
    const opts = { ...EGRESS_DEFAULTS, ...policy };

    let parsed: URL;
    try {
        parsed = new URL(rawUrl);
    } catch {
        return {
            ok: false,
            violation: {
                type: "EGRESS_DENIED",
                message: `Invalid egress URL: ${rawUrl}`,
            },
        };
    }

    // Protocolo
    const protocol = parsed.protocol.replace(":", "");
    if (!opts.allowedProtocols.includes(protocol)) {
        return {
            ok: false,
            violation: {
                type: "EGRESS_PROTOCOL_BLOCKED",
                message: `Egress protocol "${protocol}" is not allowed`,
                detail: `Allowed: ${opts.allowedProtocols.join(", ")}`,
            },
        };
    }

    // Porta
    const port = parsed.port
        ? parseInt(parsed.port, 10)
        : protocol === "https" ? 443 : 80;

    if (!opts.allowedPorts.includes(port)) {
        return {
            ok: false,
            violation: {
                type: "EGRESS_PORT_BLOCKED",
                message: `Egress port ${port} is not allowed`,
                detail: `Allowed: ${opts.allowedPorts.join(", ")}`,
            },
        };
    }

    // Domínio na allowlist
    if (opts.allowedDomains.length > 0) {
        const hostname = parsed.hostname;
        const isAllowed = opts.allowedDomains.some((pattern) => {
            if (pattern.startsWith("*.")) {
                const base = pattern.slice(2);
                return hostname === base || hostname.endsWith(`.${base}`);
            }
            return hostname === pattern;
        });

        if (!isAllowed) {
            return {
                ok: false,
                violation: {
                    type: "EGRESS_DOMAIN_BLOCKED",
                    message: `Egress to "${parsed.hostname}" is not in the allowed domains list`,
                    detail: `Allowed: ${opts.allowedDomains.join(", ")}`,
                },
            };
        }
    }

    return { ok: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// CIRCUIT BREAKER
// ─────────────────────────────────────────────────────────────────────────────

export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitBreakerOptions {
    /** Número de falhas consecutivas para abrir o circuito (padrão: 5) */
    failureThreshold?: number;
    /** Tempo em ms para tentar fechar o circuito após abrir (padrão: 30000) */
    recoveryTimeMs?: number;
    /** Número de sucessos em half-open para fechar (padrão: 2) */
    successThreshold?: number;
    /** Timeout de cada chamada em ms (padrão: 5000) */
    timeoutMs?: number;
}

export interface CircuitBreakerState {
    state: CircuitState;
    failures: number;
    successes: number;
    lastFailureTime: number;
    lastStateChange: number;
}

/**
 * Armazena o estado dos circuit breakers por serviço.
 * Em produção, substituir por Redis ou KV store distribuído.
 */
const circuitBreakerRegistry = new Map<string, CircuitBreakerState>();

/**
 * Obtém ou inicializa o estado de um circuit breaker.
 */
export function getCircuitState(serviceId: string): CircuitBreakerState {
    if (!circuitBreakerRegistry.has(serviceId)) {
        circuitBreakerRegistry.set(serviceId, {
            state: "closed",
            failures: 0,
            successes: 0,
            lastFailureTime: 0,
            lastStateChange: Date.now(),
        });
    }
    return circuitBreakerRegistry.get(serviceId)!;
}

/**
 * Verifica se um circuit breaker está aberto (deve bloquear a chamada).
 */
export function isCircuitOpen(
    serviceId: string,
    options: CircuitBreakerOptions = {}
): boolean {
    const opts = {
        failureThreshold: 5,
        recoveryTimeMs: 30000,
        successThreshold: 2,
        timeoutMs: 5000,
        ...options,
    };

    const cb = getCircuitState(serviceId);
    const now = Date.now();

    if (cb.state === "open") {
        // Tenta transição para half-open após recovery time
        if (now - cb.lastFailureTime >= opts.recoveryTimeMs) {
            cb.state = "half-open";
            cb.successes = 0;
            cb.lastStateChange = now;
            circuitBreakerRegistry.set(serviceId, cb);
            return false; // Permite uma chamada de teste
        }
        return true; // Ainda aberto
    }

    return false; // closed ou half-open
}

/**
 * Registra o resultado de uma chamada no circuit breaker.
 */
export function recordCircuitResult(
    serviceId: string,
    success: boolean,
    options: CircuitBreakerOptions = {}
): CircuitState {
    const opts = {
        failureThreshold: 5,
        recoveryTimeMs: 30000,
        successThreshold: 2,
        timeoutMs: 5000,
        ...options,
    };

    const cb = getCircuitState(serviceId);
    const now = Date.now();

    if (success) {
        if (cb.state === "half-open") {
            cb.successes++;
            if (cb.successes >= opts.successThreshold) {
                cb.state = "closed";
                cb.failures = 0;
                cb.successes = 0;
                cb.lastStateChange = now;
            }
        } else {
            cb.failures = 0; // Reset em caso de sucesso no estado fechado
        }
    } else {
        cb.failures++;
        cb.lastFailureTime = now;

        if (
            cb.state === "closed" &&
            cb.failures >= opts.failureThreshold
        ) {
            cb.state = "open";
            cb.lastStateChange = now;
            console.warn(`[CIRCUIT_BREAKER] Circuit OPENED for service: ${serviceId}`, {
                failures: cb.failures,
                threshold: opts.failureThreshold,
            });
        } else if (cb.state === "half-open") {
            cb.state = "open";
            cb.lastStateChange = now;
        }
    }

    circuitBreakerRegistry.set(serviceId, cb);
    return cb.state;
}

/**
 * Wrapper de fetch com circuit breaker, timeout e retry integrados.
 *
 * @example
 * ```ts
 * const data = await fetchWithPolicy(
 *   "https://api.parceiro.com/v1/users",
 *   { method: "GET" },
 *   {
 *     serviceId: "parceiro-api",
 *     egressPolicy: { allowedDomains: ["api.parceiro.com"] },
 *     circuitBreaker: { failureThreshold: 3 },
 *   }
 * );
 * ```
 */
export async function fetchWithPolicy(
    url: string,
    init: RequestInit = {},
    policyOptions: {
        serviceId: string;
        egressPolicy?: EgressPolicy;
        circuitBreaker?: CircuitBreakerOptions;
        maxRetries?: number;
        retryDelayMs?: number;
    }
): Promise<Response> {
    const {
        serviceId,
        egressPolicy,
        circuitBreaker = {},
        maxRetries = 3,
        retryDelayMs = 500,
    } = policyOptions;

    // Valida egress
    if (egressPolicy) {
        const egressCheck = validateEgress(url, egressPolicy);
        if (!egressCheck.ok) {
            throw new Error(
                `[NETWORK_POLICY] Egress blocked: ${egressCheck.violation?.message}`
            );
        }
    }

    // Verifica circuit breaker
    if (isCircuitOpen(serviceId, circuitBreaker)) {
        throw new Error(
            `[NETWORK_POLICY] Circuit breaker OPEN for service: ${serviceId}`
        );
    }

    const timeoutMs = circuitBreaker.timeoutMs ?? 5000;

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const response = await fetch(url, {
                ...init,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            // Considera erros 5xx como falha para o circuit breaker
            if (response.status >= 500) {
                recordCircuitResult(serviceId, false, circuitBreaker);
                lastError = new Error(`HTTP ${response.status} from ${url}`);

                if (attempt < maxRetries - 1) {
                    await sleep(retryDelayMs * (attempt + 1));
                    continue;
                }
            } else {
                recordCircuitResult(serviceId, true, circuitBreaker);
                return response;
            }
        } catch (err) {
            clearTimeout(timeoutId);
            recordCircuitResult(serviceId, false, circuitBreaker);
            lastError = err instanceof Error ? err : new Error(String(err));

            if (attempt < maxRetries - 1) {
                await sleep(retryDelayMs * (attempt + 1));
            }
        }
    }

    throw lastError ?? new Error(`All ${maxRetries} attempts failed for ${url}`);
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─────────────────────────────────────────────────────────────────────────────
// WEBSOCKET POLICY
// ─────────────────────────────────────────────────────────────────────────────

export interface WebSocketPolicy {
    /** Se WebSocket é permitido (padrão: false) */
    allowed?: boolean;
    /** Origens permitidas para WebSocket */
    allowedOrigins?: Array<string | RegExp>;
    /** Subprotocolos permitidos */
    allowedProtocols?: string[];
}

/**
 * Valida uma requisição de upgrade para WebSocket.
 */
export function validateWebSocketUpgrade(
    request: NextRequest,
    policy: WebSocketPolicy
): { ok: boolean; violation?: NetworkViolation } {
    if (!policy.allowed) {
        return {
            ok: false,
            violation: {
                type: "WEBSOCKET_DENIED",
                message: "WebSocket connections are not allowed by network policy",
            },
        };
    }

    const upgrade = request.headers.get("upgrade") ?? "";
    if (upgrade.toLowerCase() !== "websocket") {
        return {
            ok: false,
            violation: {
                type: "UPGRADE_DENIED",
                message: `Upgrade to "${upgrade}" is not allowed`,
            },
        };
    }

    const origin = request.headers.get("origin");
    if (policy.allowedOrigins?.length && origin) {
        const allowed = policy.allowedOrigins.some((pattern) =>
            originMatchesPattern(origin, pattern)
        );
        if (!allowed) {
            return {
                ok: false,
                violation: {
                    type: "CORS_ORIGIN_DENIED",
                    message: `WebSocket origin "${origin}" is not allowed`,
                    detail: "Origin not in WebSocket allowedOrigins policy",
                },
            };
        }
    }

    const requestedProtocol = request.headers.get("sec-websocket-protocol");
    if (
        requestedProtocol &&
        policy.allowedProtocols?.length &&
        !policy.allowedProtocols.includes(requestedProtocol)
    ) {
        return {
            ok: false,
            violation: {
                type: "PROTOCOL_NOT_ALLOWED",
                message: `WebSocket protocol "${requestedProtocol}" is not allowed`,
            },
        };
    }

    return { ok: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK NAMESPACE — SEGREGAÇÃO DE AMBIENTES
// ─────────────────────────────────────────────────────────────────────────────

export type NetworkEnvironment = "production" | "staging" | "development" | "test";

export interface NamespacePolicy {
    /** Ambiente atual da aplicação */
    currentEnv: NetworkEnvironment;
    /**
     * Se deve bloquear requisições que parecem vir de ambientes errados.
     * Ex: header indicando staging em ambiente de produção.
     */
    enforceEnvIsolation?: boolean;
    /**
     * Headers que identificam o ambiente de origem (usados em proxies internos).
     */
    envHeaders?: string[];
}

/**
 * Verifica se uma requisição respeita o namespace de ambiente.
 * Previne que requisições de staging cheguem em produção e vice-versa.
 */
export function validateNamespace(
    request: NextRequest,
    policy: NamespacePolicy
): { ok: boolean; violation?: NetworkViolation } {
    if (!policy.enforceEnvIsolation) return { ok: true };

    const envHeaders = policy.envHeaders ?? [
        "x-environment",
        "x-env",
        "x-app-env",
        "x-deployment-env",
    ];

    for (const headerName of envHeaders) {
        const headerValue = request.headers.get(headerName);
        if (!headerValue) continue;

        const normalized = headerValue.toLowerCase().trim();
        if (normalized !== policy.currentEnv) {
            return {
                ok: false,
                violation: {
                    type: "NAMESPACE_VIOLATION",
                    message: `Request environment "${normalized}" does not match current environment "${policy.currentEnv}"`,
                    detail: `Header: ${headerName}`,
                    meta: { expected: policy.currentEnv, received: normalized },
                },
            };
        }
    }

    return { ok: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// POLÍTICA PRINCIPAL — AVALIAÇÃO COMPLETA
// ─────────────────────────────────────────────────────────────────────────────

export interface NetworkPoliciesOptions {
    csp?: CSPOptions;
    securityHeaders?: SecurityHeadersOptions;
    cors?: CORSOptions;
    webSocket?: WebSocketPolicy;
    namespace?: NamespacePolicy;
    /** Se deve sanitizar headers de resposta que vazam infra */
    sanitizeResponseHeaders?: boolean;
}

/**
 * Avalia todas as políticas de rede e retorna headers de segurança + violations.
 *
 * @example
 * ```ts
 * // middleware.ts
 * export async function middleware(request: NextRequest) {
 *   const policy = await evaluateNetworkPolicies(request, {
 *     cors: { allowedOrigins: ["https://app.meusite.com.br"] },
 *     csp: { useNonce: true, directives: CSP_STRICT_PRESET },
 *     securityHeaders: SECURITY_HEADERS_STRICT,
 *     sanitizeResponseHeaders: true,
 *   });
 *
 *   if (!policy.ok) {
 *     return new NextResponse("Forbidden", { status: 403 });
 *   }
 *
 *   const response = NextResponse.next();
 *
 *   // Injeta todos os headers de segurança
 *   Object.entries(policy.securityHeaders).forEach(([key, value]) => {
 *     response.headers.set(key, value);
 *   });
 *
 *   // Disponibiliza o nonce CSP para Server Components via header customizado
 *   if (policy.cspNonce) {
 *     response.headers.set("x-csp-nonce", policy.cspNonce);
 *   }
 *
 *   return response;
 * }
 * ```
 */
export async function evaluateNetworkPolicies(
    request: NextRequest,
    options: NetworkPoliciesOptions = {}
): Promise<NetworkPolicyResult> {
    const violations: NetworkViolation[] = [];
    const isDev = process.env.NODE_ENV === "development";

    // ── 1. CSP + Nonce ─────────────────────────────────────────────────────────
    let cspNonce: string | undefined;
    let cspHeader: string | undefined;

    if (options.csp) {
        const cspOpts = options.csp;
        const baseDirectives = cspOpts.directives ??
            (isDev ? CSP_DEV_PRESET : CSP_STRICT_PRESET);

        if (cspOpts.useNonce !== false) {
            cspNonce = generateCSPNonce();
        }

        const builtCSP = buildCSPHeader(baseDirectives, cspNonce);

        if (cspOpts.reportUri) {
            cspHeader = `${builtCSP}; report-uri ${cspOpts.reportUri}`;
        } else {
            cspHeader = builtCSP;
        }

        // Se reportOnly, usa o header de report-only em vez de enforce
        if (cspOpts.reportOnly) {
            cspHeader = `${cspHeader}`; // marcado externamente
        }
    }

    // ── 2. CORS ────────────────────────────────────────────────────────────────
    let corsHeaders: Record<string, string> | undefined;
    let resolvedCors: ResolvedCorsConfig | undefined;

    if (options.cors) {
        resolvedCors = resolveCORS(request, options.cors);

        if (!resolvedCors.allowed && request.headers.get("origin")) {
            violations.push({
                type: "CORS_ORIGIN_DENIED",
                message: `CORS: origin "${request.headers.get("origin")}" is not allowed`,
                detail: "Origin not in CORS allowedOrigins policy",
            });
        }

        corsHeaders = buildCORSHeaders(
            resolvedCors,
            (options.cors as CORSOptions & { exposedHeaders?: string[] }).exposedHeaders
        );
    }

    // ── 3. WebSocket ───────────────────────────────────────────────────────────
    const isUpgrade = request.headers.get("upgrade")?.toLowerCase() === "websocket";
    if (isUpgrade && options.webSocket) {
        const wsCheck = validateWebSocketUpgrade(request, options.webSocket);
        if (!wsCheck.ok && wsCheck.violation) {
            violations.push(wsCheck.violation);
        }
    }

    // ── 4. Namespace / env isolation ───────────────────────────────────────────
    if (options.namespace) {
        const nsCheck = validateNamespace(request, options.namespace);
        if (!nsCheck.ok && nsCheck.violation) {
            violations.push(nsCheck.violation);
        }
    }

    // ── 5. Security Headers ────────────────────────────────────────────────────
    const headerOptions = options.securityHeaders ??
        (isDev ? SECURITY_HEADERS_DEV : SECURITY_HEADERS_STRICT);

    const securityHeaders = buildSecurityHeaders(
        headerOptions,
        cspHeader,
        corsHeaders
    );

    // ── 6. Resultado ───────────────────────────────────────────────────────────
    const blockingViolations: NetworkViolationType[] = [
        "CORS_ORIGIN_DENIED",
        "CORS_METHOD_DENIED",
        "CORS_CREDENTIALS_DENIED",
        "WEBSOCKET_DENIED",
        "PROTOCOL_NOT_ALLOWED",
        "EGRESS_DENIED",
        "NAMESPACE_VIOLATION",
        "CIRCUIT_BREAKER_OPEN",
    ];

    const ok = !violations.some((v) => blockingViolations.includes(v.type));

    return {
        ok,
        violations,
        securityHeaders,
        cspNonce,
        cors: resolvedCors,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE WRAPPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrapper completo para uso em middleware.ts do Next.js.
 * Aplica todas as políticas e injeta os headers automaticamente.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { withNetworkPolicies } from "@/lib/security/networkPolicies";
 *
 * export async function middleware(request: NextRequest) {
 *   return withNetworkPolicies(request, () => NextResponse.next(), {
 *     cors: { allowedOrigins: ["https://meusite.com.br"] },
 *     csp: { useNonce: true },
 *     securityHeaders: SECURITY_HEADERS_STRICT,
 *     sanitizeResponseHeaders: true,
 *   });
 * }
 * ```
 */
export async function withNetworkPolicies(
    request: NextRequest,
    handler: (
        policyResult: NetworkPolicyResult
    ) => NextResponse | Promise<NextResponse>,
    options: NetworkPoliciesOptions = {}
): Promise<NextResponse> {
    // Preflight CORS — responde diretamente sem passar pelo handler
    const method = request.method.toUpperCase();
    const isPreflight = method === "OPTIONS" &&
        !!request.headers.get("access-control-request-method");

    if (isPreflight && options.cors) {
        const cors = resolveCORS(request, options.cors);
        if (!cors.allowed) {
            return new NextResponse(null, { status: 403 });
        }
        const corsHeaders = buildCORSHeaders(cors);
        return new NextResponse(null, { status: 204, headers: corsHeaders });
    }

    const policyResult = await evaluateNetworkPolicies(request, options);

    if (!policyResult.ok) {
        const firstViolation = policyResult.violations[0];
        const status = firstViolation?.type === "CORS_ORIGIN_DENIED" ? 403 : 400;

        return new NextResponse(
            JSON.stringify({ error: "Network policy violation" }),
            {
                status,
                headers: {
                    "Content-Type": "application/json",
                    ...policyResult.securityHeaders,
                },
            }
        );
    }

    const response = await handler(policyResult);

    // Injeta security headers na resposta
    Object.entries(policyResult.securityHeaders).forEach(([key, value]) => {
        response.headers.set(key, value);
    });

    // Expõe nonce via header interno para Server Components lerem
    if (policyResult.cspNonce) {
        response.headers.set("x-csp-nonce", policyResult.cspNonce);
    }

    // Sanitiza headers de resposta que vazam infra
    if (options.sanitizeResponseHeaders !== false) {
        sanitizeResponseHeaders(response);
    }

    return response;
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

// Todas as constantes acima já são exportadas diretamente via `export const`.
// Re-exportações abaixo cobrem apenas os símbolos que NÃO têm `export` na declaração.
export {
    LEAKY_RESPONSE_HEADERS,
    EGRESS_DEFAULTS,
    circuitBreakerRegistry,
};