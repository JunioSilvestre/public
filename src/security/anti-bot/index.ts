/**
 * anti-bot/index.ts
 *
 * Ponto de entrada público do módulo anti-bot.
 * Re-exporta toda a API pública de honeypot.ts e recaptcha.ts
 * com namespacing explícito para evitar colisões de nomes.
 *
 * @module security/anti-bot
 */

// ─────────────────────────────────────────────────────────────────────────────
// RE-EXPORTS — RECAPTCHA
// ─────────────────────────────────────────────────────────────────────────────

// Tipos e interfaces
export type {
    CaptchaProvider,
    CaptchaVerificationStatus,
    CaptchaVerificationResult,
    CaptchaAuditLog,
    CaptchaOptions,
    RecaptchaV3Action,
    EnterpriseReasonCode,
} from "./recaptcha";

// Funções principais
export {
    verifyCaptcha,
    withCaptcha,
    buildCaptchaResponse,
} from "./recaptcha";

// Helpers de decisão de risco
export {
    isProbableBot,
    isHighConfidenceHuman,
    getRiskLabel,
} from "./recaptcha";

// Utilitários de cache e monitoring
export {
    clearTokenCache,
    getTokenCacheStats,
} from "./recaptcha";

// Constantes
export {
    VERIFICATION_URLS,
    TOKEN_DEFAULT_TTL,
    STATUS_MESSAGES,
    STATUS_HTTP_CODES,
    CAPTCHA_DEFAULTS,
} from "./recaptcha";

// ─────────────────────────────────────────────────────────────────────────────
// RE-EXPORTS — HONEYPOT
// ─────────────────────────────────────────────────────────────────────────────

// Tipos e interfaces
export type {
    HoneypotResult,
    HoneypotTrigger,
    HoneypotConfig,
    HoneypotSignalWeights,
    HoneypotStore,
    HoneypotRequest,
} from "./honeypot";

// Funções principais e middleware
export {
    HoneypotMiddleware,
    MemoryHoneypotStore,
    createExpressRouteTrap,
    createExpressFormCheck,
    createNextRouteTrap,
    createDefaultHoneypot,
    createStrictHoneypot,
} from "./honeypot";

// ─────────────────────────────────────────────────────────────────────────────
// NAMESPACE API — acesso agrupado por módulo
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Namespace do módulo reCAPTCHA/CAPTCHA.
 */
export * as Captcha from "./recaptcha";

/**
 * Namespace do módulo Honeypot.
 */
export * as Honeypot from "./honeypot";