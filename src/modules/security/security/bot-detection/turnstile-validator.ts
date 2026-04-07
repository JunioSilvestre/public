/**
 * anti-bot/turnstile-validator.ts
 *
 * Adapter de conveniência sobre recaptcha.ts para Cloudflare Turnstile.
 *
 * ── Por que este arquivo existe ──────────────────────────────────────────
 *
 * O recaptcha.ts já implementa Turnstile completamente:
 *   - POST para https://challenges.cloudflare.com/turnstile/v0/siteverify
 *   - AbortController com timeout configurável (padrão: 5000ms)
 *   - Retry com backoff exponencial (padrão: 2 retries)
 *   - Replay detection via token cache
 *   - Rate limiting por IP
 *
 * Este arquivo existe para três finalidades:
 *
 *  1. Compatibilidade: código legado que importa TurnstileValidator
 *     continua funcionando sem alteração
 *
 *  2. API simplificada: validate(token, secret, ip?) sem precisar
 *     construir um NextRequest ou passar CaptchaOptions completo
 *
 *  3. Tipo TurnstileVerificationResponse: contrato público que outros
 *     módulos podem importar para tipar respostas da API Cloudflare
 *
 * ── O que NÃO está aqui ───────────────────────────────────────────────────
 *
 * Toda a lógica real está em recaptcha.ts.
 * NÃO reimplemente fetch, timeout, retry ou token cache aqui.
 *
 * Integra-se com: recaptcha.ts, captcha-handler.ts, bot-detection.ts
 *
 * @module security/anti-bot/turnstile-validator
 */

import {
    verifyCaptcha,
    buildCaptchaResponse,
    type CaptchaVerificationResult,
    type CaptchaVerificationStatus,
    CAPTCHA_DEFAULTS,
} from "../anti-bot/recaptcha";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS PÚBLICOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resposta raw da API Cloudflare Turnstile.
 * Mantida para compatibilidade e para quem precisar tipar a resposta direta.
 *
 * Documentação oficial:
 * https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
 */
export interface TurnstileVerificationResponse {
    /** true se o token é válido. */
    success: boolean;
    /** Códigos de erro quando success = false. */
    "error-codes"?: TurnstileErrorCode[];
    /** Timestamp ISO 8601 de quando o challenge foi resolvido. */
    challenge_ts?: string;
    /** Hostname onde o widget foi renderizado. */
    hostname?: string;
    /** Action configurada no widget (se definida). */
    action?: string;
    /** Custom data passado pelo cliente (cdata). */
    cdata?: string;
}

/**
 * Códigos de erro retornados pela API Turnstile.
 * https://developers.cloudflare.com/turnstile/get-started/server-side-validation/#error-codes
 */
export type TurnstileErrorCode =
    | "missing-input-secret"     // Secret key ausente
    | "invalid-input-secret"     // Secret key inválida
    | "missing-input-response"   // Token ausente
    | "invalid-input-response"   // Token inválido ou expirado
    | "invalid-widget-id"        // Widget ID inválido
    | "invalid-parsed-secret"    // Falha ao parsear o secret
    | "bad-request"              // Request malformado
    | "timeout-or-duplicate"     // Token expirado ou já usado
    | "internal-error"           // Erro interno da Cloudflare
    | string;                    // Outros erros não documentados

/** Opções para TurnstileValidator.validate(). */
export interface TurnstileValidateOptions {
    /**
     * IP do cliente para binding de token.
     * Recomendado para aumentar a segurança — Cloudflare rejeita tokens
     * usados de IPs diferentes do que foram gerados.
     */
    remoteIp?: string;

    /**
     * Timeout para a chamada à API em ms (padrão: 5000).
     */
    timeoutMs?: number;

    /**
     * Número de retries em caso de erro de rede (padrão: 2).
     */
    maxRetries?: number;

    /**
     * Hostname esperado — tokens gerados em outros sites são rejeitados.
     * Fortemente recomendado em produção.
     */
    expectedHostname?: string;

    /**
     * Se deve bloquear reuso do mesmo token (padrão: true).
     */
    preventReplay?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES
// ─────────────────────────────────────────────────────────────────────────────

/** URL de verificação da API Turnstile. */
export const TURNSTILE_VERIFY_URL =
    "https://challenges.cloudflare.com/turnstile/v0/siteverify" as const;

/** TTL do token Turnstile em segundos (300s = 5 minutos). */
export const TURNSTILE_TOKEN_TTL_SEC = 300 as const;

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Valida um token Turnstile junto à API da Cloudflare.
 *
 * Delega para verifyCaptcha() de recaptcha.ts — toda a lógica de
 * HTTP, timeout, retry e replay detection está lá.
 *
 * @example
 * ```ts
 * // Uso direto (sem NextRequest — útil fora de Route Handlers)
 * const result = await TurnstileValidator.validate(token, secretKey, {
 *   remoteIp: clientIP,
 *   expectedHostname: "meusite.com.br",
 * });
 *
 * if (!result.success) {
 *   console.error("Turnstile falhou:", result["error-codes"]);
 * }
 * ```
 */
export const TurnstileValidator = {
    /**
     * Valida o token Turnstile chamando a API da Cloudflare.
     * Retorna TurnstileVerificationResponse para compatibilidade com código legado.
     *
     * Para uso em Route Handlers Next.js, prefira TurnstileValidator.verifyRequest()
     * ou handleCaptcha() de captcha-handler.ts — ambos usam verifyCaptcha() diretamente
     * com o NextRequest completo.
     */
    async validate(
        token: string,
        secretKey: string,
        options: TurnstileValidateOptions | string = {}
    ): Promise<TurnstileVerificationResponse> {
        // Suporte ao signature legado: validate(token, secret, remoteIp?: string)
        const opts: TurnstileValidateOptions =
            typeof options === "string" ? { remoteIp: options } : options;

        // Constrói um Request sintético para verifyCaptcha()
        // O token é injetado via header para não precisar de body parsing
        const syntheticRequest = buildSyntheticRequest(token, opts.remoteIp);

        let result: CaptchaVerificationResult;
        try {
            result = await verifyCaptcha(syntheticRequest, {
                provider: "turnstile",
                turnstileSecretKey: secretKey,
                secretKey,
                preventTokenReplay: opts.preventReplay ?? true,
                verificationTimeoutMs: opts.timeoutMs ?? CAPTCHA_DEFAULTS.verificationTimeoutMs,
                maxRetries: opts.maxRetries ?? CAPTCHA_DEFAULTS.maxRetries,
                ...(opts.expectedHostname && {
                    expectedHostnames: [opts.expectedHostname],
                }),
            });
        } catch {
            return {
                success: false,
                "error-codes": ["internal-error"],
            };
        }

        // Converte CaptchaVerificationResult → TurnstileVerificationResponse
        return captchaResultToTurnstileResponse(result);
    },

    /**
     * Verifica um token Turnstile a partir de um NextRequest completo.
     * Retorna CaptchaVerificationResult — mais rico que TurnstileVerificationResponse.
     *
     * Prefira este método em Route Handlers — o token é extraído automaticamente
     * do body (campo "cf-turnstile-response") ou do header "x-captcha-token".
     *
     * @example
     * ```ts
     * // app/api/contato/route.ts
     * import { TurnstileValidator } from "@/lib/security/anti-bot/turnstile-validator";
     *
     * export async function POST(request: NextRequest) {
     *   const result = await TurnstileValidator.verifyRequest(request, {
     *     secretKey:        process.env.TURNSTILE_SECRET_KEY!,
     *     expectedHostname: "meusite.com.br",
     *   });
     *
     *   if (!result.ok) {
     *     return buildCaptchaResponse(result);
     *   }
     * }
     * ```
     */
    async verifyRequest(
        request: Request,
        options: {
            secretKey: string;
            expectedHostname?: string;
            preventReplay?: boolean;
            timeoutMs?: number;
            maxRetries?: number;
        }
    ): Promise<CaptchaVerificationResult> {
        // verifyCaptcha aceita Request | NextRequest — sem cast necessário
        return verifyCaptcha(request, {
            provider: "turnstile",
            turnstileSecretKey: options.secretKey,
            secretKey: options.secretKey,
            preventTokenReplay: options.preventReplay ?? true,
            verificationTimeoutMs: options.timeoutMs ?? CAPTCHA_DEFAULTS.verificationTimeoutMs,
            maxRetries: options.maxRetries ?? CAPTCHA_DEFAULTS.maxRetries,
            tokenBodyField: "cf-turnstile-response",
            ...(options.expectedHostname && {
                expectedHostnames: [options.expectedHostname],
            }),
        });
    },
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS INTERNOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Constrói um Request sintético com o token no header.
 * Necessário porque verifyCaptcha() espera um objeto Request/NextRequest.
 * O token no header é extraído por extractToken() em recaptcha.ts.
 */
function buildSyntheticRequest(token: string, remoteIp?: string): Request {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "x-captcha-token": token,           // campo padrão de CAPTCHA_DEFAULTS.tokenHeader
    };

    if (remoteIp) {
        headers["x-real-ip"] = remoteIp;
    }

    return new Request("https://internal/turnstile-validate", {
        method: "POST",
        headers,
        body: JSON.stringify({}),
    });
}

/**
 * Converte CaptchaVerificationResult para TurnstileVerificationResponse.
 * Mantém compatibilidade com código que já usa TurnstileVerificationResponse.
 */
function captchaResultToTurnstileResponse(
    result: CaptchaVerificationResult
): TurnstileVerificationResponse {
    if (result.ok) {
        return {
            success: true,
            challenge_ts: result.challengeTs,
            hostname: result.hostname,
            action: result.action,
        };
    }

    // Mapeia CaptchaVerificationStatus → TurnstileErrorCode
    const errorMap: Partial<Record<CaptchaVerificationStatus, TurnstileErrorCode>> = {
        missing_token: "missing-input-response",
        invalid_token: "invalid-input-response",
        expired_token: "timeout-or-duplicate",
        duplicate_token: "timeout-or-duplicate",
        provider_error: "internal-error",
    };

    const errorCode: TurnstileErrorCode =
        errorMap[result.status] ?? result.status.replace(/_/g, "-");

    return {
        success: false,
        "error-codes": [errorCode, ...(result.audit.rawErrors ?? [])],
        hostname: result.hostname,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS PÚBLICOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se uma resposta Turnstile indica sucesso.
 * Sugar para verificações inline sem precisar importar o validator.
 *
 * @example
 * ```ts
 * const response = await TurnstileValidator.validate(token, secret);
 * if (!isTurnstileSuccess(response)) { ... }
 * ```
 */
export function isTurnstileSuccess(
    response: TurnstileVerificationResponse
): boolean {
    return response.success === true;
}

/**
 * Retorna os códigos de erro de uma resposta Turnstile como string legível.
 *
 * @example
 * ```ts
 * console.error("[Turnstile]", getTurnstileErrors(response));
 * // "[Turnstile] timeout-or-duplicate, invalid-input-response"
 * ```
 */
export function getTurnstileErrors(
    response: TurnstileVerificationResponse
): string {
    const codes = response["error-codes"];
    if (!codes || codes.length === 0) return "no-error-codes";
    return codes.join(", ");
}

/**
 * Converte TurnstileVerificationResponse para score de risco (0–100).
 * Compatível com o sistema de score do bot-detection.ts.
 *
 * Turnstile não retorna score numérico — resultado é binário.
 * 0 = passou, 80 = falhou (não 100 porque não sabemos se é bot ou erro).
 */
export function turnstileRiskScore(
    response: TurnstileVerificationResponse
): number {
    if (response.success) return 0;

    const codes = response["error-codes"] ?? [];

    // Token expirado/duplicado tem score mais alto — indica tentativa suspeita
    if (codes.includes("timeout-or-duplicate")) return 85;

    // Erro interno da Cloudflare — pode ser falso positivo
    if (codes.includes("internal-error")) return 20;

    // Outros erros de validação
    return 80;
}

// Re-export para compatibilidade com imports existentes
export { buildCaptchaResponse as buildTurnstileResponse };