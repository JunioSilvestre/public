/**
 * anti-bot/captcha-handler.ts
 *
 * Adapter de conveniência sobre recaptcha.ts.
 *
 * ── Por que este arquivo existe ──────────────────────────────────────────
 *
 * O recaptcha.ts é a implementação completa e autoritativa de verificação
 * CAPTCHA. Ele expõe uma API poderosa mas com muitas opções — adequada
 * para uso direto em Route Handlers.
 *
 * Este adapter fornece uma API simplificada para dois casos de uso
 * específicos que aparecem frequentemente no projeto:
 *
 *  1. Verificação rápida a partir de um token e secret já extraídos
 *     (ex: usado pelo bot-detection.ts para orquestração)
 *
 *  2. Preset de configurações por contexto de uso
 *     (ex: "login" usa score mais alto que "contact")
 *
 * ── O que NÃO está aqui ───────────────────────────────────────────────────
 *
 * Toda a lógica de verificação real está em recaptcha.ts:
 *   - Chamadas HTTP para Google/hCaptcha/Cloudflare
 *   - Replay detection e token cache
 *   - Rate limiting por IP
 *   - Score thresholds e action validation
 *
 * NÃO duplique essas lógicas aqui. Se precisar de controle fino,
 * use verifyCaptcha() de recaptcha.ts diretamente.
 *
 * Integra-se com: recaptcha.ts, bot-detection.ts
 *
 * @module security/anti-bot/captcha-handler
 */

import { NextRequest } from "next/server";

import {
    verifyCaptcha,
    buildCaptchaResponse,
    isProbableBot,
    isHighConfidenceHuman,
    getRiskLabel,
    type CaptchaProvider,
    type CaptchaOptions,
    type CaptchaVerificationResult,
    type CaptchaVerificationStatus,
    type RecaptchaV3Action,
} from "../anti-bot/recaptcha";

// ─────────────────────────────────────────────────────────────────────────────
// RE-EXPORTS — contrato público deste adapter
// ─────────────────────────────────────────────────────────────────────────────

// O bot-detection.ts e outros consumidores importam esses tipos daqui,
// sem precisar conhecer o caminho interno do recaptcha.ts
export type {
    CaptchaProvider,
    CaptchaOptions,
    CaptchaVerificationResult,
    CaptchaVerificationStatus,
    RecaptchaV3Action,
};

export { buildCaptchaResponse, isProbableBot, isHighConfidenceHuman, getRiskLabel };

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS LOCAIS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Contexto de uso do CAPTCHA.
 * Cada contexto tem um score mínimo diferente pré-configurado.
 */
export type CaptchaContext =
    | "login"           // Score alto — alvo frequente de credential stuffing
    | "register"        // Score alto — criação de contas em massa
    | "password_reset"  // Score alto — conta recovery é alvo de takeover
    | "checkout"        // Score muito alto — fraude de pagamento
    | "contact"         // Score médio — spam de formulário
    | "comment"         // Score médio — spam de conteúdo
    | "newsletter"      // Score baixo — baixo risco
    | "search"          // Score baixo — uso legítimo frequente
    | "download"        // Score médio — abuso de bandwidth
    | "vote"            // Score alto — manipulação de resultados
    | "custom";         // Score customizado via minScore

/**
 * Opções simplificadas para o verify() desta classe.
 * Subset de CaptchaOptions com valores sensatos pré-preenchidos.
 */
export interface CaptchaHandlerOptions {
    /** Provedor CAPTCHA a usar. */
    provider: CaptchaProvider;

    /** Secret key do provedor (nunca exponha no cliente). */
    secretKey: string;

    /**
     * Contexto de uso — define o score mínimo automaticamente.
     * Use "custom" para definir minScore manualmente.
     * Padrão: "contact"
     */
    context?: CaptchaContext;

    /**
     * Score mínimo para aprovar (0.0–1.0).
     * Ignorado se `context` não for "custom".
     * Padrão do contexto será usado se não fornecido.
     */
    minScore?: number;

    /**
     * Action esperada no token (v3/Enterprise).
     * Se não fornecida, usa o nome do contexto como action.
     */
    expectedAction?: RecaptchaV3Action;

    /**
     * Hostnames aceitos para o token.
     * Recomendado em produção para evitar tokens gerados em outros sites.
     */
    expectedHostnames?: string[];

    /**
     * Se deve bloquear reuso do mesmo token (padrão: true).
     */
    preventTokenReplay?: boolean;

    /**
     * Credenciais extras para provedores específicos.
     */
    enterpriseApiKey?: string;
    projectId?: string;
    siteKey?: string;
    turnstileSecretKey?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// SCORE POR CONTEXTO
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Score mínimo recomendado por contexto de uso.
 * Calibrado com base em práticas do setor e tolerância a falso-positivo.
 *
 * Ajuste conforme o perfil de usuários da sua aplicação.
 */
export const CONTEXT_MIN_SCORES: Record<CaptchaContext, number> = {
    login: 0.7,  // Credenciais — alto risco
    register: 0.6,  // Cadastro em massa — alto risco
    password_reset: 0.7,  // Account takeover — alto risco
    checkout: 0.8,  // Fraude financeira — máximo rigor
    contact: 0.4,  // Spam — tolerância maior
    comment: 0.4,  // Spam de conteúdo — tolerância maior
    newsletter: 0.3,  // Baixo risco — permissivo
    search: 0.3,  // Legítimo — muito permissivo
    download: 0.5,  // Bandwidth abuse — moderado
    vote: 0.7,  // Manipulação — alto risco
    custom: 0.5,  // Valor padrão se minScore não for fornecido
};

// ─────────────────────────────────────────────────────────────────────────────
// FUNÇÃO PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica um token CAPTCHA usando configuração simplificada por contexto.
 *
 * Delega para verifyCaptcha() de recaptcha.ts com opções pré-configuradas.
 *
 * @example
 * ```ts
 * // Uso básico — contexto "login" com score 0.7 automático
 * const result = await handleCaptcha(request, {
 *   provider: "recaptcha_v3",
 *   secretKey: process.env.RECAPTCHA_SECRET_KEY!,
 *   context: "login",
 *   expectedHostnames: ["meusite.com.br"],
 * });
 *
 * if (!result.ok) {
 *   return buildCaptchaResponse(result);
 * }
 * ```
 *
 * @example
 * ```ts
 * // Score customizado
 * const result = await handleCaptcha(request, {
 *   provider: "turnstile",
 *   turnstileSecretKey: process.env.TURNSTILE_SECRET_KEY!,
 *   secretKey: process.env.TURNSTILE_SECRET_KEY!,
 *   context: "custom",
 *   minScore: 0.45,
 * });
 * ```
 */
export async function handleCaptcha(
    request: NextRequest,
    options: CaptchaHandlerOptions
): Promise<CaptchaVerificationResult> {
    const context = options.context ?? "contact";
    const minScore = context === "custom"
        ? (options.minScore ?? CONTEXT_MIN_SCORES.custom)
        : CONTEXT_MIN_SCORES[context];

    // A action padrão é o nome do contexto, exceto "custom"
    const expectedAction: RecaptchaV3Action | undefined =
        options.expectedAction ??
        (context !== "custom" ? context : undefined);

    const captchaOptions: CaptchaOptions = {
        provider: options.provider,
        secretKey: options.secretKey,
        minScore,
        expectedAction,
        expectedHostnames: options.expectedHostnames,
        preventTokenReplay: options.preventTokenReplay ?? true,

        // Credenciais extras para Enterprise / Turnstile
        ...(options.enterpriseApiKey && { enterpriseApiKey: options.enterpriseApiKey }),
        ...(options.projectId && { projectId: options.projectId }),
        ...(options.siteKey && { siteKey: options.siteKey }),
        ...(options.turnstileSecretKey && { turnstileSecretKey: options.turnstileSecretKey }),
    };

    return verifyCaptcha(request, captchaOptions);
}

// ─────────────────────────────────────────────────────────────────────────────
// PRESETS POR PROVEDOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria uma função de verificação pré-configurada para reCAPTCHA v3.
 * Útil quando o mesmo provedor é usado em muitos endpoints.
 *
 * @example
 * ```ts
 * // Cria uma vez no nível do módulo
 * const recaptcha = createRecaptchaV3Handler(
 *   process.env.RECAPTCHA_SECRET_KEY!,
 *   ["meusite.com.br"],
 * );
 *
 * // Usa nos Route Handlers
 * export async function POST(req: NextRequest) {
 *   const result = await recaptcha(req, "login");
 *   if (!result.ok) return buildCaptchaResponse(result);
 * }
 * ```
 */
export function createRecaptchaV3Handler(
    secretKey: string,
    expectedHostnames?: string[]
) {
    return (
        request: NextRequest,
        context: CaptchaContext = "contact"
    ): Promise<CaptchaVerificationResult> =>
        handleCaptcha(request, {
            provider: "recaptcha_v3",
            secretKey,
            context,
            expectedHostnames,
        });
}

/**
 * Cria uma função de verificação pré-configurada para Cloudflare Turnstile.
 *
 * @example
 * ```ts
 * const turnstile = createTurnstileHandler(
 *   process.env.TURNSTILE_SECRET_KEY!,
 * );
 *
 * export async function POST(req: NextRequest) {
 *   const result = await turnstile(req, "contact");
 *   if (!result.ok) return buildCaptchaResponse(result);
 * }
 * ```
 */
export function createTurnstileHandler(turnstileSecretKey: string) {
    return (
        request: NextRequest,
        context: CaptchaContext = "contact"
    ): Promise<CaptchaVerificationResult> =>
        handleCaptcha(request, {
            provider: "turnstile",
            secretKey: turnstileSecretKey,
            turnstileSecretKey,
            context,
        });
}

/**
 * Cria uma função de verificação pré-configurada para hCaptcha.
 *
 * @example
 * ```ts
 * const hcaptcha = createHCaptchaHandler(
 *   process.env.HCAPTCHA_SECRET_KEY!,
 *   process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY!,
 * );
 * ```
 */
export function createHCaptchaHandler(
    secretKey: string,
    siteKey?: string
) {
    return (
        request: NextRequest,
        context: CaptchaContext = "contact"
    ): Promise<CaptchaVerificationResult> =>
        handleCaptcha(request, {
            provider: "hcaptcha",
            secretKey,
            siteKey,
            context,
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica rapidamente se um resultado indica bot — sem score.
 * Funciona para v2 e Turnstile que não retornam score numérico.
 */
export function isCaptchaFailed(result: CaptchaVerificationResult): boolean {
    return !result.ok && result.status !== "provider_error";
}

/**
 * Retorna o score normalizado (0–100) para uso no pipeline de risco.
 * Compatível com o sistema de score do bot-detection.ts.
 *
 * - Provedor sem score (v2, Turnstile): retorna 0 se ok, 100 se falhou.
 * - v3/Enterprise/hCaptcha: converte 0.0–1.0 → 0–100 invertido (risco).
 */
export function captchaRiskScore(result: CaptchaVerificationResult): number {
    if (!result.ok) {
        return result.status === "provider_error" ? 20 : 80;
    }
    if (result.score === undefined) {
        return 0; // CAPTCHA passou sem score — sem risco
    }
    // Inverte: score 1.0 (humano) → risco 0; score 0.0 (bot) → risco 100
    return Math.round((1 - result.score) * 100);
}

/**
 * Descreve o resultado do CAPTCHA em linguagem natural para logging.
 */
export function describeCaptchaResult(result: CaptchaVerificationResult): string {
    const providerLabel: Record<CaptchaProvider, string> = {
        recaptcha_v2: "reCAPTCHA v2",
        recaptcha_v3: "reCAPTCHA v3",
        recaptcha_enterprise: "reCAPTCHA Enterprise",
        hcaptcha: "hCaptcha",
        turnstile: "Cloudflare Turnstile",
    };

    const provider = providerLabel[result.provider];
    const status = result.status;

    if (result.ok) {
        const scoreStr = result.score !== undefined
            ? ` (score: ${result.score.toFixed(2)} — ${getRiskLabel(Math.round((1 - result.score) * 100))})`
            : "";
        return `${provider}: verificação bem-sucedida${scoreStr}`;
    }

    const statusMessages: Partial<Record<CaptchaVerificationStatus, string>> = {
        low_score: "score abaixo do mínimo",
        invalid_token: "token inválido",
        expired_token: "token expirado",
        duplicate_token: "token reutilizado (replay)",
        missing_token: "token ausente",
        action_mismatch: "action incorreta",
        ip_mismatch: "IP diferente do token",
        rate_limited: "limite de tentativas excedido",
        provider_error: "erro no serviço do provedor",
    };

    const reason = statusMessages[status] ?? status;
    return `${provider}: falhou — ${reason}`;
}