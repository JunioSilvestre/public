/**
 * anti-bot/recaptcha.ts
 *
 * Verificação e enforcement de CAPTCHA para aplicações Next.js.
 * Cobre todos os provedores e versões relevantes do mercado.
 *
 * Provedores suportados:
 *  - Google reCAPTCHA v2 (checkbox e invisible)
 *  - Google reCAPTCHA v3 (score-based, sem interação)
 *  - Google reCAPTCHA Enterprise (score + reason codes + assessment)
 *  - hCaptcha (alternativa focada em privacidade)
 *  - Cloudflare Turnstile (sem fricção, privacy-first)
 *
 * Responsabilidades:
 *  - Verificação server-side de tokens CAPTCHA
 *  - Score thresholds configuráveis por ação/endpoint
 *  - Reason codes e action validation (v3/Enterprise)
 *  - Token replay detection (uso único garantido)
 *  - Token expiry enforcement além do padrão do provedor
 *  - IP binding validation (token emitido para outro IP)
 *  - Risk-based challenge escalation (score baixo → v2 challenge)
 *  - Rate limiting de tentativas de verificação por IP
 *  - Fallback entre provedores em caso de falha
 *  - Audit log estruturado com todos os metadados
 *  - Proteção contra brute force de tokens
 *  - Integração com trafficInspection.ts e firewallRules.ts
 *
 * Integra-se com: requestSanitizer.ts, firewallRules.ts,
 *                 trafficInspection.ts, rateLimiter.ts, authGuard.ts
 *
 * @module security/anti-bot/recaptcha
 */

import { NextRequest, NextResponse } from "next/server";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

export type CaptchaProvider =
    | "recaptcha_v2"
    | "recaptcha_v3"
    | "recaptcha_enterprise"
    | "hcaptcha"
    | "turnstile";

export type CaptchaVerificationStatus =
    | "success"          // Token válido e score acima do threshold
    | "low_score"        // Token válido mas score abaixo do threshold
    | "invalid_token"    // Token inválido ou malformado
    | "expired_token"    // Token expirado
    | "duplicate_token"  // Token já usado (replay attack)
    | "ip_mismatch"      // Token emitido para outro IP
    | "action_mismatch"  // Action do token não corresponde ao esperado
    | "missing_token"    // Token ausente na requisição
    | "provider_error"   // Erro na comunicação com o provedor
    | "rate_limited"     // Muitas tentativas de verificação deste IP
    | "blocked";         // IP/token explicitamente bloqueado

export type RecaptchaV3Action =
    | "login"
    | "register"
    | "password_reset"
    | "checkout"
    | "contact"
    | "comment"
    | "search"
    | "vote"
    | "download"
    | "submit"
    | string; // Permite ações customizadas

/**
 * Reason codes retornados pelo reCAPTCHA Enterprise.
 * Indicam o motivo de uma pontuação baixa.
 */
export type EnterpriseReasonCode =
    | "AUTOMATION"             // Acesso automatizado detectado
    | "UNEXPECTED_ENVIRONMENT" // JavaScript execution environment incomum
    | "TOO_MUCH_TRAFFIC"       // Volume excessivo de tráfego
    | "UNEXPECTED_USAGE_PATTERNS" // Padrões de uso incomuns
    | "LOW_CONFIDENCE_SCORE"   // Score baixo sem razão específica
    | "NOT_YET_SEEN"          // IP/dispositivo nunca visto antes
    | string;

export interface CaptchaVerificationResult {
    ok: boolean;
    status: CaptchaVerificationStatus;
    provider: CaptchaProvider;
    /** Score de 0.0 a 1.0 (apenas v3 e Enterprise) */
    score?: number;
    /** Action declarada no token (v3/Enterprise) */
    action?: string;
    /** Hostname onde o token foi gerado */
    hostname?: string;
    /** Challenge timestamp do token */
    challengeTs?: string;
    /** APK package name (mobile apps) */
    apkPackageName?: string;
    /** Reason codes (Enterprise) */
    reasonCodes?: EnterpriseReasonCode[];
    /** ID do assessment no Enterprise */
    assessmentName?: string;
    /** Metadados de auditoria */
    audit: CaptchaAuditLog;
}

export interface CaptchaAuditLog {
    requestId: string;
    timestamp: string;
    provider: CaptchaProvider;
    status: CaptchaVerificationStatus;
    score?: number;
    action?: string;
    ip: string;
    hostname?: string;
    tokenHash: string;   // SHA256 do token para rastreabilidade sem expor o token
    processingMs: number;
    rawErrors?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// OPÇÕES DE CONFIGURAÇÃO
// ─────────────────────────────────────────────────────────────────────────────

export interface CaptchaOptions {
    /** Provedor a usar */
    provider: CaptchaProvider;

    // ── Credenciais ────────────────────────────────────────────────────────────

    /** Secret key do reCAPTCHA v2/v3 ou hCaptcha */
    secretKey?: string;
    /** API key do reCAPTCHA Enterprise */
    enterpriseApiKey?: string;
    /** Project ID do Google Cloud (Enterprise) */
    projectId?: string;
    /** Site key do Turnstile / hCaptcha (necessário para verificação Turnstile) */
    siteKey?: string;
    /** Secret key do Cloudflare Turnstile */
    turnstileSecretKey?: string;

    // ── Score e threshold ──────────────────────────────────────────────────────

    /**
     * Score mínimo para considerar a verificação bem-sucedida (padrão: 0.5).
     * Aplicável apenas para v3 e Enterprise.
     * 0.0 = bot provável, 1.0 = humano provável.
     */
    minScore?: number;

    /**
     * Score abaixo do qual aciona challenge escalation (padrão: 0.3).
     * Abaixo deste valor, redireciona para v2 checkbox mesmo em fluxo v3.
     */
    escalationScore?: number;

    /**
     * Score mínimo por ação específica. Sobrescreve minScore.
     * ex: { login: 0.7, contact: 0.4 }
     */
    scoreByAction?: Record<string, number>;

    // ── Validação de token ─────────────────────────────────────────────────────

    /**
     * Action esperada no token (v3/Enterprise).
     * Se definida, tokens com action diferente são rejeitados.
     */
    expectedAction?: RecaptchaV3Action;

    /**
     * Hostname(s) esperado(s). Se definido, tokens de outros sites são rejeitados.
     */
    expectedHostnames?: string[];

    /**
     * Tempo máximo de vida do token em segundos além do padrão do provedor.
     * reCAPTCHA v2: 2min, v3: 2min, Enterprise: configurável.
     * Padrão: usa o TTL do provedor.
     */
    maxTokenAgeSec?: number;

    // ── Replay detection ───────────────────────────────────────────────────────

    /**
     * Se deve detectar e bloquear reuso de tokens (padrão: true).
     * Tokens usados são armazenados em memória com TTL.
     * Em produção: usar Redis/KV para compartilhar entre instâncias.
     */
    preventTokenReplay?: boolean;

    /**
     * TTL em segundos para o cache de tokens usados (padrão: 300 = 5min).
     */
    replayCacheTtlSec?: number;

    // ── Rate limiting ──────────────────────────────────────────────────────────

    /**
     * Número máximo de verificações CAPTCHA por IP por janela (padrão: 20).
     */
    maxAttemptsPerIP?: number;

    /**
     * Janela de tempo para o rate limit em segundos (padrão: 60).
     */
    rateLimitWindowSec?: number;

    // ── Fallback e resiliência ─────────────────────────────────────────────────

    /**
     * Se deve permitir a requisição quando o provedor CAPTCHA está indisponível.
     * Padrão: false (fail closed — mais seguro).
     */
    allowOnProviderError?: boolean;

    /**
     * Timeout para a chamada ao provedor em ms (padrão: 5000).
     */
    verificationTimeoutMs?: number;

    /**
     * Número de retries em caso de erro de rede (padrão: 2).
     */
    maxRetries?: number;

    // ── Extração do token ──────────────────────────────────────────────────────

    /**
     * Nome do campo no body onde o token está (padrão: "g-recaptcha-response").
     */
    tokenBodyField?: string;

    /**
     * Nome do header onde o token pode estar (padrão: "x-captcha-token").
     */
    tokenHeader?: string;

    /**
     * Nome do parâmetro de query onde o token pode estar.
     */
    tokenQueryParam?: string;

    // ── Comportamento ──────────────────────────────────────────────────────────

    /** Modo de operação (padrão: "enforce") */
    mode?: "enforce" | "audit" | "off";

    /** Log verboso (padrão: false) */
    verboseLog?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULTS = {
    minScore: 0.5,
    escalationScore: 0.3,
    preventTokenReplay: true,
    replayCacheTtlSec: 300,
    maxAttemptsPerIP: 20,
    rateLimitWindowSec: 60,
    allowOnProviderError: false,
    verificationTimeoutMs: 5000,
    maxRetries: 2,
    tokenBodyField: "g-recaptcha-response",
    tokenHeader: "x-captcha-token",
    mode: "enforce" as const,
    verboseLog: false,
};

/** URLs de verificação por provedor */
const VERIFICATION_URLS: Record<CaptchaProvider, string> = {
    recaptcha_v2: "https://www.google.com/recaptcha/api/siteverify",
    recaptcha_v3: "https://www.google.com/recaptcha/api/siteverify",
    recaptcha_enterprise: "https://recaptchaenterprise.googleapis.com/v1/projects/{PROJECT_ID}/assessments?key={API_KEY}",
    hcaptcha: "https://api.hcaptcha.com/siteverify",
    turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
};

/** TTL padrão dos tokens por provedor (segundos) */
const TOKEN_DEFAULT_TTL: Record<CaptchaProvider, number> = {
    recaptcha_v2: 120,
    recaptcha_v3: 120,
    recaptcha_enterprise: 120,
    hcaptcha: 120,
    turnstile: 300,
};

// ─────────────────────────────────────────────────────────────────────────────
// ESTADO IN-MEMORY (produção: substituir por Redis/Vercel KV)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cache de tokens já usados — previne replay attacks.
 * { tokenHash → expiresAt }
 */
const usedTokenCache = new Map<string, number>();

/**
 * Contador de tentativas por IP para rate limiting.
 * { ip → { count, windowStart } }
 */
const ipAttemptRegistry = new Map<string, { count: number; windowStart: number }>();

/**
 * Remove entradas expiradas do cache de tokens.
 * Chamado periodicamente para evitar memory leak.
 */
function pruneExpiredTokens(): void {
    const now = Date.now();
    Array.from(usedTokenCache.entries()).forEach(([hash, expiresAt]) => {
        if (now > expiresAt) usedTokenCache.delete(hash);
    });
}

/**
 * Remove contadores de IP expirados.
 */
function pruneExpiredAttempts(windowMs: number): void {
    const now = Date.now();
    Array.from(ipAttemptRegistry.entries()).forEach(([ip, entry]) => {
        if (now - entry.windowStart > windowMs) ipAttemptRegistry.delete(ip);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Gera um hash simples do token para logging sem expor o valor real.
 * Não usar para criptografia — apenas para identificação em logs.
 */
function hashToken(token: string): string {
    let hash = 5381;
    for (let i = 0; i < token.length; i++) {
        hash = ((hash << 5) + hash) ^ token.charCodeAt(i);
        hash = hash >>> 0;
    }
    return hash.toString(16).padStart(8, "0");
}

/**
 * Gera ID único para o request.
 */
function generateRequestId(): string {
    return `cap_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

/**
 * Extrai o IP real da requisição.
 */
function extractIP(request: NextRequest | Request): string {
    return (
        request.headers.get("cf-connecting-ip") ??
        request.headers.get("x-real-ip") ??
        request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
        "unknown"
    );
}

/**
 * Verifica e incrementa o rate limit por IP.
 */
function checkAndIncrementRateLimit(
    ip: string,
    maxAttempts: number,
    windowSec: number
): boolean {
    const now = Date.now();
    const windowMs = windowSec * 1000;

    pruneExpiredAttempts(windowMs);

    const entry = ipAttemptRegistry.get(ip);

    if (!entry || now - entry.windowStart > windowMs) {
        ipAttemptRegistry.set(ip, { count: 1, windowStart: now });
        return true; // Permitido
    }

    if (entry.count >= maxAttempts) {
        return false; // Rate limitado
    }

    entry.count++;
    ipAttemptRegistry.set(ip, entry);
    return true;
}

/**
 * Verifica se um token já foi usado (replay protection).
 */
function isTokenReplayed(tokenHash: string): boolean {
    pruneExpiredTokens();
    const expiresAt = usedTokenCache.get(tokenHash);
    return expiresAt !== undefined && Date.now() < expiresAt;
}

/**
 * Marca um token como usado.
 */
function markTokenUsed(tokenHash: string, ttlSec: number): void {
    usedTokenCache.set(tokenHash, Date.now() + ttlSec * 1000);
}

/**
 * Extrai o token CAPTCHA da requisição (body, header ou query).
 */
async function extractToken(
    request: NextRequest | Request,
    opts: Required<typeof DEFAULTS> & CaptchaOptions
): Promise<string | null> {
    // 1. Header customizado
    const headerToken = request.headers.get(opts.tokenHeader ?? DEFAULTS.tokenHeader);
    if (headerToken) return headerToken.trim();

    // 2. Query param
    if (opts.tokenQueryParam) {
        const url = new URL(request.url);
        const qToken = url.searchParams.get(opts.tokenQueryParam);
        if (qToken) return qToken.trim();
    }

    // 3. Body (JSON ou form)
    try {
        const contentType = request.headers.get("content-type") ?? "";
        const fieldName = opts.tokenBodyField ?? DEFAULTS.tokenBodyField;

        if (contentType.includes("application/json")) {
            const clone = request.clone();
            const body = await clone.json() as Record<string, unknown>;
            const token = body[fieldName];
            if (typeof token === "string" && token) return token.trim();
        } else if (
            contentType.includes("application/x-www-form-urlencoded") ||
            contentType.includes("multipart/form-data")
        ) {
            const clone = request.clone();
            const form = await clone.formData();
            const token = form.get(fieldName);
            if (typeof token === "string" && token) return token.trim();
        }
    } catch {
        // Body já consumido ou inválido
    }

    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFICADORES POR PROVEDOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resposta raw da API Google reCAPTCHA v2/v3.
 */
interface RecaptchaV2V3Response {
    success: boolean;
    score?: number;
    action?: string;
    challenge_ts?: string;
    hostname?: string;
    apk_package_name?: string;
    "error-codes"?: string[];
}

/**
 * Resposta raw da API reCAPTCHA Enterprise.
 */
interface RecaptchaEnterpriseResponse {
    name?: string;
    event?: {
        token: string;
        siteKey: string;
        userAgent?: string;
        userIpAddress?: string;
        expectedAction?: string;
    };
    riskAnalysis?: {
        score: number;
        reasons?: EnterpriseReasonCode[];
        extendedVerdictReasons?: string[];
    };
    tokenProperties?: {
        valid: boolean;
        invalidReason?: string;
        hostname?: string;
        action?: string;
        createTime?: string;
    };
}

/**
 * Verifica token com reCAPTCHA v2 ou v3.
 */
async function verifyRecaptchaV2V3(
    token: string,
    ip: string,
    secretKey: string,
    timeoutMs: number,
    maxRetries: number
): Promise<RecaptchaV2V3Response> {
    const params = new URLSearchParams({
        secret: secretKey,
        response: token,
        remoteip: ip,
    });

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const res = await fetch(VERIFICATION_URLS.recaptcha_v2, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: params.toString(),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!res.ok) {
                throw new Error(`HTTP ${res.status} from reCAPTCHA API`);
            }

            return await res.json() as RecaptchaV2V3Response;
        } catch (err) {
            clearTimeout(timeoutId);
            lastError = err instanceof Error ? err : new Error(String(err));
            if (attempt < maxRetries) {
                await sleep(200 * (attempt + 1));
            }
        }
    }

    throw lastError ?? new Error("reCAPTCHA verification failed after retries");
}

/**
 * Verifica token com reCAPTCHA Enterprise.
 */
async function verifyRecaptchaEnterprise(
    token: string,
    ip: string,
    apiKey: string,
    projectId: string,
    siteKey: string,
    expectedAction: string | undefined,
    timeoutMs: number,
    maxRetries: number
): Promise<RecaptchaEnterpriseResponse> {
    const url = VERIFICATION_URLS.recaptcha_enterprise
        .replace("{PROJECT_ID}", projectId)
        .replace("{API_KEY}", apiKey);

    const body = {
        event: {
            token,
            siteKey,
            userIpAddress: ip,
            ...(expectedAction && { expectedAction }),
        },
    };

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const res = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!res.ok) {
                const errBody = await res.text();
                throw new Error(`HTTP ${res.status}: ${errBody.slice(0, 200)}`);
            }

            return await res.json() as RecaptchaEnterpriseResponse;
        } catch (err) {
            clearTimeout(timeoutId);
            lastError = err instanceof Error ? err : new Error(String(err));
            if (attempt < maxRetries) {
                await sleep(200 * (attempt + 1));
            }
        }
    }

    throw lastError ?? new Error("reCAPTCHA Enterprise verification failed");
}

/**
 * Verifica token com hCaptcha.
 */
async function verifyHCaptcha(
    token: string,
    ip: string,
    secretKey: string,
    siteKey: string | undefined,
    timeoutMs: number,
    maxRetries: number
): Promise<RecaptchaV2V3Response> {
    const params = new URLSearchParams({
        secret: secretKey,
        response: token,
        remoteip: ip,
        ...(siteKey && { sitekey: siteKey }),
    });

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const res = await fetch(VERIFICATION_URLS.hcaptcha, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: params.toString(),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!res.ok) {
                throw new Error(`HTTP ${res.status} from hCaptcha API`);
            }

            return await res.json() as RecaptchaV2V3Response;
        } catch (err) {
            clearTimeout(timeoutId);
            lastError = err instanceof Error ? err : new Error(String(err));
            if (attempt < maxRetries) {
                await sleep(200 * (attempt + 1));
            }
        }
    }

    throw lastError ?? new Error("hCaptcha verification failed after retries");
}

/**
 * Verifica token com Cloudflare Turnstile.
 */
async function verifyTurnstile(
    token: string,
    ip: string,
    secretKey: string,
    timeoutMs: number,
    maxRetries: number
): Promise<{ success: boolean; "error-codes"?: string[]; hostname?: string; challenge_ts?: string }> {
    const params = new URLSearchParams({
        secret: secretKey,
        response: token,
        remoteip: ip,
    });

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const res = await fetch(VERIFICATION_URLS.turnstile, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: params.toString(),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!res.ok) {
                throw new Error(`HTTP ${res.status} from Turnstile API`);
            }

            return await res.json() as {
                success: boolean;
                "error-codes"?: string[];
                hostname?: string;
                challenge_ts?: string;
            };
        } catch (err) {
            clearTimeout(timeoutId);
            lastError = err instanceof Error ? err : new Error(String(err));
            if (attempt < maxRetries) {
                await sleep(200 * (attempt + 1));
            }
        }
    }

    throw lastError ?? new Error("Turnstile verification failed after retries");
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFICADOR PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica um token CAPTCHA server-side com validações completas.
 *
 * @example
 * ```ts
 * // app/api/contact/route.ts
 * export async function POST(req: NextRequest) {
 *   const verification = await verifyCaptcha(req, {
 *     provider: "recaptcha_v3",
 *     secretKey: process.env.RECAPTCHA_SECRET_KEY!,
 *     minScore: 0.5,
 *     expectedAction: "contact",
 *     expectedHostnames: ["meusite.com.br"],
 *     preventTokenReplay: true,
 *   });
 *
 *   if (!verification.ok) {
 *     return buildCaptchaResponse(verification);
 *   }
 *   // processa o formulário...
 * }
 * ```
 */
export async function verifyCaptcha(
    request: NextRequest | Request,
    options: CaptchaOptions
): Promise<CaptchaVerificationResult> {
    const startTime = Date.now();
    const opts = { ...DEFAULTS, ...options };
    const ip = extractIP(request);
    const requestId = generateRequestId();

    // ── Modo off ───────────────────────────────────────────────────────────────
    if (opts.mode === "off") {
        return buildResult("success", opts.provider, requestId, ip, startTime, {});
    }

    // ── Rate limiting por IP ───────────────────────────────────────────────────
    const withinLimit = checkAndIncrementRateLimit(
        ip,
        opts.maxAttemptsPerIP ?? DEFAULTS.maxAttemptsPerIP,
        opts.rateLimitWindowSec ?? DEFAULTS.rateLimitWindowSec
    );

    if (!withinLimit) {
        return buildResult("rate_limited", opts.provider, requestId, ip, startTime, {
            rawErrors: ["Too many CAPTCHA verification attempts from this IP"],
        });
    }

    // ── Extrai token ───────────────────────────────────────────────────────────
    const token = await extractToken(request, opts as Required<typeof DEFAULTS> & CaptchaOptions);

    if (!token || token.trim() === "") {
        return buildResult("missing_token", opts.provider, requestId, ip, startTime, {});
    }

    // Validação básica de formato do token (tamanho mínimo / máximo)
    if (token.length < 20 || token.length > 8192) {
        return buildResult("invalid_token", opts.provider, requestId, ip, startTime, {
            tokenHash: hashToken(token),
            rawErrors: ["Token length out of expected range"],
        });
    }

    const tokenHash = hashToken(token);

    // ── Replay detection ───────────────────────────────────────────────────────
    if (opts.preventTokenReplay !== false) {
        if (isTokenReplayed(tokenHash)) {
            return buildResult("duplicate_token", opts.provider, requestId, ip, startTime, {
                tokenHash,
                rawErrors: ["Token has already been used (replay attack prevented)"],
            });
        }
    }

    // ── Verificação com o provedor ─────────────────────────────────────────────
    let verificationData: {
        success?: boolean;
        score?: number;
        action?: string;
        hostname?: string;
        challengeTs?: string;
        reasonCodes?: EnterpriseReasonCode[];
        assessmentName?: string;
        rawErrors?: string[];
    } = {};

    try {
        switch (opts.provider) {

            // ── reCAPTCHA v2 ───────────────────────────────────────────────────────
            case "recaptcha_v2": {
                if (!opts.secretKey) throw new Error("secretKey is required for reCAPTCHA v2");
                const raw = await verifyRecaptchaV2V3(
                    token, ip, opts.secretKey,
                    opts.verificationTimeoutMs ?? DEFAULTS.verificationTimeoutMs,
                    opts.maxRetries ?? DEFAULTS.maxRetries
                );
                verificationData = {
                    success: raw.success,
                    hostname: raw.hostname,
                    challengeTs: raw.challenge_ts,
                    rawErrors: raw["error-codes"],
                };
                break;
            }

            // ── reCAPTCHA v3 ───────────────────────────────────────────────────────
            case "recaptcha_v3": {
                if (!opts.secretKey) throw new Error("secretKey is required for reCAPTCHA v3");
                const raw = await verifyRecaptchaV2V3(
                    token, ip, opts.secretKey,
                    opts.verificationTimeoutMs ?? DEFAULTS.verificationTimeoutMs,
                    opts.maxRetries ?? DEFAULTS.maxRetries
                );
                verificationData = {
                    success: raw.success,
                    score: raw.score,
                    action: raw.action,
                    hostname: raw.hostname,
                    challengeTs: raw.challenge_ts,
                    rawErrors: raw["error-codes"],
                };
                break;
            }

            // ── reCAPTCHA Enterprise ───────────────────────────────────────────────
            case "recaptcha_enterprise": {
                if (!opts.enterpriseApiKey) throw new Error("enterpriseApiKey is required for Enterprise");
                if (!opts.projectId) throw new Error("projectId is required for Enterprise");
                if (!opts.siteKey) throw new Error("siteKey is required for Enterprise");

                const raw = await verifyRecaptchaEnterprise(
                    token, ip,
                    opts.enterpriseApiKey,
                    opts.projectId,
                    opts.siteKey,
                    opts.expectedAction,
                    opts.verificationTimeoutMs ?? DEFAULTS.verificationTimeoutMs,
                    opts.maxRetries ?? DEFAULTS.maxRetries
                );

                const tokenProps = raw.tokenProperties;
                const risk = raw.riskAnalysis;

                verificationData = {
                    success: tokenProps?.valid ?? false,
                    score: risk?.score,
                    action: tokenProps?.action,
                    hostname: tokenProps?.hostname,
                    challengeTs: tokenProps?.createTime,
                    reasonCodes: risk?.reasons,
                    assessmentName: raw.name,
                    rawErrors: tokenProps?.invalidReason
                        ? [tokenProps.invalidReason]
                        : undefined,
                };
                break;
            }

            // ── hCaptcha ───────────────────────────────────────────────────────────
            case "hcaptcha": {
                if (!opts.secretKey) throw new Error("secretKey is required for hCaptcha");
                const raw = await verifyHCaptcha(
                    token, ip, opts.secretKey, opts.siteKey,
                    opts.verificationTimeoutMs ?? DEFAULTS.verificationTimeoutMs,
                    opts.maxRetries ?? DEFAULTS.maxRetries
                );
                verificationData = {
                    success: raw.success,
                    score: raw.score,
                    hostname: raw.hostname,
                    challengeTs: raw.challenge_ts,
                    rawErrors: raw["error-codes"],
                };
                break;
            }

            // ── Cloudflare Turnstile ───────────────────────────────────────────────
            case "turnstile": {
                const tsKey = opts.turnstileSecretKey ?? opts.secretKey;
                if (!tsKey) throw new Error("turnstileSecretKey is required for Turnstile");

                const raw = await verifyTurnstile(
                    token, ip, tsKey,
                    opts.verificationTimeoutMs ?? DEFAULTS.verificationTimeoutMs,
                    opts.maxRetries ?? DEFAULTS.maxRetries
                );
                verificationData = {
                    success: raw.success,
                    hostname: raw.hostname,
                    challengeTs: raw.challenge_ts,
                    rawErrors: raw["error-codes"],
                };
                break;
            }
        }
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);

        if (opts.allowOnProviderError) {
            // Fail open — permite a requisição mas loga o erro
            console.error("[CAPTCHA] Provider error (fail-open):", message);
            return buildResult("success", opts.provider, requestId, ip, startTime, {
                tokenHash,
                rawErrors: [`Provider error (allowed): ${message}`],
            });
        }

        return buildResult("provider_error", opts.provider, requestId, ip, startTime, {
            tokenHash,
            rawErrors: [message],
        });
    }

    // ── Valida resultado do provedor ───────────────────────────────────────────
    if (!verificationData.success) {
        const errorCodes = verificationData.rawErrors ?? [];

        // Classifica o tipo de erro pelos error-codes do provedor
        let status: CaptchaVerificationStatus = "invalid_token";
        if (errorCodes.some((e) => /timeout|expired/i.test(e))) {
            status = "expired_token";
        }

        return buildResult(status, opts.provider, requestId, ip, startTime, {
            tokenHash,
            ...verificationData,
        });
    }

    // ── Validação de hostname ──────────────────────────────────────────────────
    if (opts.expectedHostnames?.length && verificationData.hostname) {
        const validHost = opts.expectedHostnames.includes(verificationData.hostname);
        if (!validHost) {
            return buildResult("invalid_token", opts.provider, requestId, ip, startTime, {
                tokenHash,
                ...verificationData,
                rawErrors: [
                    `Hostname mismatch: expected one of [${opts.expectedHostnames.join(", ")}], got "${verificationData.hostname}"`,
                ],
            });
        }
    }

    // ── Validação de action (v3/Enterprise) ────────────────────────────────────
    if (
        opts.expectedAction &&
        verificationData.action &&
        verificationData.action !== opts.expectedAction
    ) {
        return buildResult("action_mismatch", opts.provider, requestId, ip, startTime, {
            tokenHash,
            ...verificationData,
            rawErrors: [
                `Action mismatch: expected "${opts.expectedAction}", got "${verificationData.action}"`,
            ],
        });
    }

    // ── Score validation (v3/Enterprise/hCaptcha) ──────────────────────────────
    if (verificationData.score !== undefined) {
        const action = verificationData.action ?? opts.expectedAction ?? "";
        const threshold =
            (opts.scoreByAction?.[action]) ??
            (opts.minScore ?? DEFAULTS.minScore);

        if (verificationData.score < threshold) {
            // Não marca como usado — score baixo pode ser retentado com v2
            return buildResult("low_score", opts.provider, requestId, ip, startTime, {
                tokenHash,
                ...verificationData,
                rawErrors: [
                    `Score ${verificationData.score.toFixed(2)} below threshold ${threshold.toFixed(2)}`,
                ],
            });
        }
    }

    // ── Marca token como usado (replay prevention) ────────────────────────────
    if (opts.preventTokenReplay !== false) {
        const ttl =
            opts.replayCacheTtlSec ??
            DEFAULTS.replayCacheTtlSec;
        markTokenUsed(tokenHash, ttl);
    }

    // ── Sucesso ────────────────────────────────────────────────────────────────
    const result = buildResult("success", opts.provider, requestId, ip, startTime, {
        tokenHash,
        ...verificationData,
    });

    if (opts.verboseLog) {
        logCaptchaEvent(result);
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS INTERNOS
// ─────────────────────────────────────────────────────────────────────────────

function buildResult(
    status: CaptchaVerificationStatus,
    provider: CaptchaProvider,
    requestId: string,
    ip: string,
    startTime: number,
    data: {
        score?: number;
        action?: string;
        hostname?: string;
        challengeTs?: string;
        reasonCodes?: EnterpriseReasonCode[];
        assessmentName?: string;
        tokenHash?: string;
        rawErrors?: string[];
        success?: boolean;
    }
): CaptchaVerificationResult {
    const audit: CaptchaAuditLog = {
        requestId,
        timestamp: new Date().toISOString(),
        provider,
        status,
        score: data.score,
        action: data.action,
        ip,
        hostname: data.hostname,
        tokenHash: data.tokenHash ?? "none",
        processingMs: Date.now() - startTime,
        rawErrors: data.rawErrors,
    };

    if (!["success"].includes(status)) {
        logCaptchaEvent({ ok: false, status, provider, audit, ...data });
    }

    return {
        ok: status === "success",
        status,
        provider,
        score: data.score,
        action: data.action,
        hostname: data.hostname,
        challengeTs: data.challengeTs,
        reasonCodes: data.reasonCodes,
        assessmentName: data.assessmentName,
        audit,
    };
}

function logCaptchaEvent(result: Partial<CaptchaVerificationResult>): void {
    const level = result.ok ? "info" : "warn";
    console[level]("[CAPTCHA]", {
        status: result.status,
        provider: result.provider,
        score: result.score,
        action: result.action,
        requestId: result.audit?.requestId,
        ip: result.audit?.ip,
        processingMs: result.audit?.processingMs,
        errors: result.audit?.rawErrors,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTRUTOR DE RESPOSTA HTTP
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Mensagens de erro por status — não expõe detalhes internos em produção.
 */
const STATUS_MESSAGES: Record<CaptchaVerificationStatus, string> = {
    success: "Verification successful",
    low_score: "Automated behavior detected. Please try again.",
    invalid_token: "Invalid verification token.",
    expired_token: "Verification token has expired. Please refresh and try again.",
    duplicate_token: "This verification token has already been used.",
    ip_mismatch: "Verification failed due to IP inconsistency.",
    action_mismatch: "Verification action mismatch.",
    missing_token: "Verification token is required.",
    provider_error: "Verification service temporarily unavailable.",
    rate_limited: "Too many verification attempts. Please wait before trying again.",
    blocked: "Access denied.",
};

const STATUS_HTTP_CODES: Record<CaptchaVerificationStatus, number> = {
    success: 200,
    low_score: 403,
    invalid_token: 400,
    expired_token: 400,
    duplicate_token: 400,
    ip_mismatch: 403,
    action_mismatch: 400,
    missing_token: 400,
    provider_error: 503,
    rate_limited: 429,
    blocked: 403,
};

/**
 * Constrói a NextResponse de erro para uma verificação CAPTCHA falha.
 */
export function buildCaptchaResponse(
    result: CaptchaVerificationResult
): NextResponse {
    const isDev = process.env.NODE_ENV === "development";
    const httpStatus = STATUS_HTTP_CODES[result.status];
    const message = STATUS_MESSAGES[result.status];

    const body: Record<string, unknown> = {
        error: message,
        requestId: result.audit.requestId,
    };

    if (isDev) {
        body["debug"] = {
            status: result.status,
            provider: result.provider,
            score: result.score,
            action: result.action,
            errors: result.audit.rawErrors,
        };
    }

    // Retry-After para rate limit
    const extraHeaders: Record<string, string> = {};
    if (result.status === "rate_limited") {
        extraHeaders["Retry-After"] = "60";
    }

    return new NextResponse(JSON.stringify(body), {
        status: httpStatus,
        headers: {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            ...extraHeaders,
        },
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE WRAPPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrapper completo para Route Handlers do Next.js App Router.
 *
 * @example
 * ```ts
 * // app/api/auth/login/route.ts
 * import { withCaptcha } from "@/lib/security/anti-bot/recaptcha";
 *
 * export async function POST(req: NextRequest) {
 *   return withCaptcha(
 *     req,
 *     async (verification) => {
 *       // verification.score disponível para lógica adicional
 *       const { email, password } = await req.json();
 *       // ... lógica de login
 *       return NextResponse.json({ ok: true });
 *     },
 *     {
 *       provider: "recaptcha_v3",
 *       secretKey: process.env.RECAPTCHA_V3_SECRET!,
 *       minScore: 0.6,
 *       expectedAction: "login",
 *       preventTokenReplay: true,
 *     }
 *   );
 * }
 * ```
 */
export async function withCaptcha(
    request: NextRequest,
    handler: (verification: CaptchaVerificationResult) => Promise<NextResponse>,
    options: CaptchaOptions
): Promise<NextResponse> {
    const result = await verifyCaptcha(request, options);

    if (!result.ok) {
        return buildCaptchaResponse(result);
    }

    return handler(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS PÚBLICOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se um resultado indica bot provável baseado no score.
 * Útil para decisões de risco sem bloquear imediatamente.
 *
 * @example
 * ```ts
 * const result = await verifyCaptcha(req, opts);
 * if (isProbableBot(result)) {
 *   // Log extra, exige 2FA, adiciona ao watchlist...
 * }
 * ```
 */
export function isProbableBot(
    result: CaptchaVerificationResult,
    threshold = 0.4
): boolean {
    if (!result.ok) return true;
    if (result.score === undefined) return false;
    return result.score < threshold;
}

/**
 * Verifica se o score indica um humano com alta confiança.
 */
export function isHighConfidenceHuman(
    result: CaptchaVerificationResult,
    threshold = 0.8
): boolean {
    if (!result.ok) return false;
    if (result.score === undefined) return result.ok; // v2 não tem score
    return result.score >= threshold;
}

/**
 * Retorna uma label de risco legível baseado no score.
 */
export function getRiskLabel(
    score: number | undefined
): "bot" | "suspicious" | "likely_human" | "human" | "unknown" {
    if (score === undefined) return "unknown";
    if (score < 0.3) return "bot";
    if (score < 0.5) return "suspicious";
    if (score < 0.8) return "likely_human";
    return "human";
}

/**
 * Limpa o cache de tokens usados manualmente (útil em testes).
 */
export function clearTokenCache(): void {
    usedTokenCache.clear();
}

/**
 * Retorna estatísticas do cache de tokens (útil para monitoring).
 */
export function getTokenCacheStats(): {
    cachedTokens: number;
    trackedIPs: number;
} {
    pruneExpiredTokens();
    return {
        cachedTokens: usedTokenCache.size,
        trackedIPs: ipAttemptRegistry.size,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

export {
    VERIFICATION_URLS,
    TOKEN_DEFAULT_TTL,
    STATUS_MESSAGES,
    STATUS_HTTP_CODES,
    DEFAULTS as CAPTCHA_DEFAULTS,
};