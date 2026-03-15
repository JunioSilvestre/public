/**
 * anti-bot/index.ts
 *
 * Ponto de entrada público do módulo anti-bot.
 *
 * Regra: cada identificador é exportado de UMA única fonte.
 * Os blocos "export * as Namespace" não geram nomes no escopo flat.
 *
 * Formas de uso:
 *
 *   // Nomeada (tree-shakeable)
 *   import { detectBot, analyzeBehavior } from "@/lib/security/anti-bot";
 *
 *   // Namespace agrupado
 *   import { BotDetection, Behavioral, Captcha, HoneypotField, Turnstile }
 *     from "@/lib/security/anti-bot";
 *
 * @module security/anti-bot
 */

// ─────────────────────────────────────────────────────────────────────────────
// BOT DETECTION — fonte: bot-detection.ts
// ─────────────────────────────────────────────────────────────────────────────

export type {
    BotDetectionAction,
    BotDetectionViolation,
    BotDetectionSignal,
    BotDetectionResult,
    BotDetectionOptions,
} from "./bot-detection";

export {
    detectBot,
    withBotDetection,
    buildBotResponse,
    getRiskLabel as getBotRiskLabel,
    isDefinitelyBot,
    BOT_DETECTION_DEFAULTS,
    HONEYPOT_TRIGGER_MAP,
} from "./bot-detection";

// ─────────────────────────────────────────────────────────────────────────────
// BEHAVIORAL ANALYSIS — fonte: behavioral-analysis.ts
// ─────────────────────────────────────────────────────────────────────────────

export type {
    MousePoint,
    ClickEvent,
    KeystrokeInterval,
    ScrollEvent,
    UserTelemetry,
    EnvironmentSignals,
    BehavioralSignalName,
    BehavioralSignal,
    BehavioralVerdict,
    BehavioralResult,
    BehavioralAnalysisConfig,
} from "./behavioral-analysis";

export {
    analyzeBehavior,
    BehavioralCollector,
    getVerdictLabel,
    combineScores,
    BEHAVIORAL_ANALYSIS_DEFAULTS,
} from "./behavioral-analysis";

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA — fonte: captcha-handler.ts
// (captcha-handler re-exporta os tipos de recaptcha.ts — não importar de recaptcha.ts aqui)
// ─────────────────────────────────────────────────────────────────────────────

export type {
    CaptchaProvider,
    CaptchaOptions,
    CaptchaVerificationResult,
    CaptchaVerificationStatus,
    RecaptchaV3Action,
    CaptchaContext,
    CaptchaHandlerOptions,
} from "./captcha-handler";

export {
    handleCaptcha,
    createRecaptchaV3Handler,
    createTurnstileHandler,
    createHCaptchaHandler,
    buildCaptchaResponse,
    isProbableBot as isCaptchaProbableBot,
    isHighConfidenceHuman,
    getRiskLabel as getCaptchaRiskLabel,
    isCaptchaFailed,
    captchaRiskScore,
    describeCaptchaResult,
    CONTEXT_MIN_SCORES,
} from "./captcha-handler";

// ─────────────────────────────────────────────────────────────────────────────
// HONEYPOT FIELD — fonte: honeypot-field.ts
// (honeypot-field re-exporta os tipos de honeypot.ts — não importar de honeypot.ts aqui)
// ─────────────────────────────────────────────────────────────────────────────

export type {
    FormType,
    HoneypotFieldOptions,
    HoneypotFieldResult,
    HoneypotResult,
    HoneypotRequest,
    HoneypotConfig,
    HoneypotTrigger,
} from "./honeypot-field";

export {
    isHoneypotFilled,
    checkSubmitTiming,
    checkHoneypotField,
    getHoneypotInputProps,
    getHoneypotFormProps,
    honeypotRiskScore,
    describeHoneypotResult,
    isDefinitelyHoneypotBot,
    HONEYPOT_DEFAULTS,
    HoneypotFieldName,
    createDefaultHoneypot,
    createStrictHoneypot,
    FORM_TYPE_PRESETS,
} from "./honeypot-field";

// ─────────────────────────────────────────────────────────────────────────────
// TURNSTILE — fonte: turnstile-validator.ts
// ─────────────────────────────────────────────────────────────────────────────

export type {
    TurnstileVerificationResponse,
    TurnstileErrorCode,
    TurnstileValidateOptions,
} from "./turnstile-validator";

export {
    TurnstileValidator,
    TURNSTILE_VERIFY_URL,
    TURNSTILE_TOKEN_TTL_SEC,
    isTurnstileSuccess,
    getTurnstileErrors,
    turnstileRiskScore,
    buildTurnstileResponse,
} from "./turnstile-validator";

// ─────────────────────────────────────────────────────────────────────────────
// NAMESPACE API
// export * as não gera identificadores no escopo flat — zero colisão.
// ─────────────────────────────────────────────────────────────────────────────

/** @example const r = await BotDetection.detectBot(req, opts); */
export * as BotDetection from "./bot-detection";

/** @example const r = Behavioral.analyzeBehavior(telemetry); */
export * as Behavioral from "./behavioral-analysis";

/** @example const r = await Captcha.handleCaptcha(req, { provider: "turnstile", ... }); */
export * as Captcha from "./captcha-handler";

/** @example const f = HoneypotField.isHoneypotFilled(body); */
export * as HoneypotField from "./honeypot-field";

/** @example const r = await Turnstile.TurnstileValidator.validate(token, secret); */
export * as Turnstile from "./turnstile-validator";