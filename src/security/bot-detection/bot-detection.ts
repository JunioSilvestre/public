/**
 * anti-bot/bot-detection.ts
 *
 * Orquestrador central de detecção de bots — agrega e pondera os resultados
 * de todos os módulos anti-bot em um único veredito final.
 *
 * ── Responsabilidades ─────────────────────────────────────────────────────
 *
 *  Este módulo NÃO implementa detecção por conta própria.
 *  Ele delega para os módulos especializados e combina os resultados:
 *
 *    honeypot.ts            → armadilhas passivas (campos hidden, timing, token)
 *    behavioral-analysis.ts → análise de padrão de interação (mouse, teclado, scroll)
 *    recaptcha.ts           → verificação ativa via CAPTCHA externo
 *
 *  Pipeline de execução:
 *
 *    Request
 *      │
 *      ├─ 1. Honeypot (mais rápido — sem I/O)       → peso: 40%
 *      │      Campo preenchido? Timing suspeito?
 *      │      Token inválido/faltando?
 *      │
 *      ├─ 2. Behavioral (sem I/O, client-side data) → peso: 35%
 *      │      Mouse linear? Keystroke uniforme?
 *      │      WebDriver? Headless?
 *      │
 *      └─ 3. CAPTCHA (I/O — chamada de rede)        → peso: 25%
 *             reCAPTCHA v2/v3/Enterprise, hCaptcha,
 *             Turnstile — apenas se configurado
 *
 *  Veredito final:
 *    riskScore 0–100  →  isBot = riskScore ≥ threshold (padrão: 70)
 *    action           →  "allow" | "block" | "challenge" | "monitor"
 *
 * ── Princípio de segurança ────────────────────────────────────────────────
 *
 *  1. Falha aberta vs fechada: configurável por use-case
 *     - Formulário de contato: falha aberta (não bloqueia se CAPTCHA cair)
 *     - Login / pagamento:     falha fechada (bloqueia se qualquer check falhar)
 *
 *  2. Resposta opaca: NUNCA retorne ao cliente qual check falhou.
 *     Use o resultado internamente; responda 200 falso para bots.
 *
 *  3. Short-circuit: honeypot com score 100 encerra o pipeline imediatamente
 *     — sem chamar a API do Google desnecessariamente.
 *
 * Integra-se com: requestSanitizer.ts, firewallRules.ts, trafficInspection.ts
 *
 * @module security/anti-bot/bot-detection
 */

import { NextRequest, NextResponse } from "next/server";

import {
    type HoneypotResult,
    type HoneypotRequest,
    type HoneypotConfig,
    HoneypotMiddleware,
    MemoryHoneypotStore,
} from "../anti-bot/honeypot";

import {
    type UserTelemetry,
    type BehavioralResult,
    type BehavioralAnalysisConfig,
    analyzeBehavior,
    combineScores,
} from "./behavioral-analysis";

import {
    type CaptchaVerificationResult,
    type CaptchaOptions,
    verifyCaptcha,
} from "../anti-bot/recaptcha";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

export type BotDetectionAction =
    | "allow"      // Requisição legítima — prosseguir normalmente
    | "block"      // Bot detectado com alta confiança — bloquear
    | "challenge"  // Suspeito — pedir verificação adicional (CAPTCHA v2, 2FA)
    | "monitor";   // Sinais fracos — permitir mas logar para análise

export type BotDetectionViolation =
    | "HONEYPOT_FIELD_FILLED"
    | "HONEYPOT_TIMING_FAST"
    | "HONEYPOT_TOKEN_INVALID"
    | "HONEYPOT_TOKEN_MISSING"
    | "HONEYPOT_TOKEN_REPLAYED"
    | "BEHAVIORAL_BOT_DETECTED"
    | "BEHAVIORAL_SUSPICIOUS"
    | "BEHAVIORAL_WEBDRIVER"
    | "CAPTCHA_INVALID"
    | "CAPTCHA_LOW_SCORE"
    | "CAPTCHA_MISSING"
    | "CAPTCHA_PROVIDER_ERROR"
    | "PIPELINE_ERROR";

export interface BotDetectionSignal {
    violation: BotDetectionViolation;
    /** Contribuição para o riskScore (0–100). */
    weight: number;
    /** Confiança no sinal (0.0–1.0). */
    confidence: number;
    source: "honeypot" | "behavioral" | "captcha" | "pipeline";
    detail?: string;
}

export interface BotDetectionResult {
    /** true se a requisição deve ser tratada como bot. */
    isBot: boolean;

    /** Ação recomendada pelo orquestrador. */
    action: BotDetectionAction;

    /**
     * Score de risco agregado (0–100).
     * 0 = definitivamente humano, 100 = definitivamente bot.
     * (Oposto ao humanScore do behavioral-analysis.)
     */
    riskScore: number;

    /** Sinais individuais que contribuíram para o score. */
    signals: BotDetectionSignal[];

    /**
     * Resultados brutos de cada módulo.
     * Útil para logging detalhado e debugging.
     * NUNCA exponha ao cliente.
     */
    details: {
        honeypot: HoneypotResult | null;
        behavioral: BehavioralResult | null;
        captcha: CaptchaVerificationResult | null;
    };

    /** Metadados de auditoria. */
    audit: {
        requestId: string;
        timestamp: string;
        ip: string;
        path: string;
        method: string;
        processingMs: number;
        checksRun: Array<"honeypot" | "behavioral" | "captcha">;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// OPÇÕES DE CONFIGURAÇÃO
// ─────────────────────────────────────────────────────────────────────────────

export interface BotDetectionOptions {
    // ── Controle do pipeline ───────────────────────────────────────────────────

    /**
     * Score de risco mínimo para considerar bot (padrão: 70).
     * Abaixo = "allow" ou "monitor". Acima = "block" ou "challenge".
     */
    blockThreshold?: number;

    /**
     * Score a partir do qual aciona "challenge" em vez de "block" (padrão: 50).
     * Entre challengeThreshold e blockThreshold → "challenge".
     * Abaixo de challengeThreshold → "allow" ou "monitor".
     */
    challengeThreshold?: number;

    /**
     * Score a partir do qual aciona "monitor" (padrão: 30).
     * Entre monitorThreshold e challengeThreshold → "monitor".
     */
    monitorThreshold?: number;

    /**
     * Se um módulo lançar exceção, qual ação tomar (padrão: "continue").
     * "continue" = ignora o módulo com erro e segue o pipeline.
     * "block"    = falha fechada — bloqueia se qualquer módulo falhar.
     */
    onModuleError?: "continue" | "block";

    /**
     * Se deve usar short-circuit: interrompe o pipeline quando um módulo
     * retorna score ≥ blockThreshold (padrão: true).
     * Economiza chamadas de rede desnecessárias ao CAPTCHA.
     */
    shortCircuit?: boolean;

    // ── Configurações por módulo ───────────────────────────────────────────────

    /**
     * Configuração do Honeypot.
     * Se não fornecida, usa defaults do HoneypotMiddleware.
     * Se `false`, desabilita o check de honeypot.
     */
    honeypot?: HoneypotConfig | false;

    /**
     * Configuração da análise comportamental.
     * Se `false`, desabilita o check comportamental.
     */
    behavioral?: BehavioralAnalysisConfig | false;

    /**
     * Configuração do CAPTCHA.
     * Se não fornecida, o check de CAPTCHA é pulado.
     * Se fornecida, o CAPTCHA é obrigatório.
     */
    captcha?: CaptchaOptions | false;

    // ── Pesos de contribuição ──────────────────────────────────────────────────

    /**
     * Pesos relativos de cada módulo no score final.
     * Devem somar 1.0 (padrão: honeypot 0.40, behavioral 0.35, captcha 0.25).
     */
    weights?: {
        honeypot?: number;
        behavioral?: number;
        captcha?: number;
    };

    // ── Callback de auditoria ──────────────────────────────────────────────────

    /**
     * Callback chamado sempre que um bot é detectado.
     * Use para: logging, alertas, integração com SIEM.
     *
     * @example
     * ```ts
     * onBotDetected: async (result, request) => {
     *   await logger.warn("bot_detected", {
     *     ip: result.audit.ip,
     *     score: result.riskScore,
     *     signals: result.signals.map(s => s.violation),
     *   });
     * }
     * ```
     */
    onBotDetected?: (
        result: BotDetectionResult,
        request: NextRequest
    ) => void | Promise<void>;

    /** Log verboso para debugging. Padrão: false */
    verboseLog?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES E DEFAULTS
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULTS = {
    blockThreshold: 70,
    challengeThreshold: 50,
    monitorThreshold: 30,
    onModuleError: "continue" as const,
    shortCircuit: true,
    weights: {
        honeypot: 0.40,
        behavioral: 0.35,
        captcha: 0.25,
    },
    verboseLog: false,
};

/**
 * Mapeamento de HoneypotTrigger → BotDetectionViolation + peso.
 * Define quanto cada trigger do honeypot contribui ao riskScore.
 */
const HONEYPOT_TRIGGER_MAP: Record<string, { violation: BotDetectionViolation; weight: number; confidence: number }> = {
    FIELD_FILLED: { violation: "HONEYPOT_FIELD_FILLED", weight: 90, confidence: 0.97 },
    LURE_FIELD_FILLED: { violation: "HONEYPOT_FIELD_FILLED", weight: 85, confidence: 0.90 },
    TIMING_TOO_FAST: { violation: "HONEYPOT_TIMING_FAST", weight: 65, confidence: 0.75 },
    TOKEN_MISSING: { violation: "HONEYPOT_TOKEN_MISSING", weight: 55, confidence: 0.65 },
    TOKEN_INVALID: { violation: "HONEYPOT_TOKEN_INVALID", weight: 75, confidence: 0.85 },
    TOKEN_REPLAYED: { violation: "HONEYPOT_TOKEN_REPLAYED", weight: 90, confidence: 0.97 },
    TRAP_ROUTE_HIT: { violation: "HONEYPOT_FIELD_FILLED", weight: 100, confidence: 0.99 },
    CRAWLER_TRAP_HIT: { violation: "HONEYPOT_FIELD_FILLED", weight: 100, confidence: 0.99 },
    MULTIPLE_SIGNALS: { violation: "HONEYPOT_TIMING_FAST", weight: 70, confidence: 0.80 },
};

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS INTERNOS
// ─────────────────────────────────────────────────────────────────────────────

function extractIP(request: NextRequest): string {
    return (
        request.headers.get("cf-connecting-ip") ??
        request.headers.get("x-real-ip") ??
        request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
        "unknown"
    );
}

function generateRequestId(): string {
    return `bd_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

function scoreToAction(
    score: number,
    opts: {
        blockThreshold: number;
        challengeThreshold: number;
        monitorThreshold: number;
    }
): BotDetectionAction {
    if (score >= opts.blockThreshold) return "block";
    if (score >= opts.challengeThreshold) return "challenge";
    if (score >= opts.monitorThreshold) return "monitor";
    return "allow";
}

/**
 * Converte o resultado do Honeypot em sinais para o orquestrador.
 */
function honeypotToSignals(result: HoneypotResult): BotDetectionSignal[] {
    if (result.clean) return [];

    const signals: BotDetectionSignal[] = [];
    const trigger = result.triggered ?? "MULTIPLE_SIGNALS";
    const mapped = HONEYPOT_TRIGGER_MAP[trigger];

    if (mapped) {
        signals.push({
            violation: mapped.violation,
            weight: mapped.weight,
            confidence: mapped.confidence,
            source: "honeypot",
            detail: result.detail,
        });
    }

    // Sinais individuais do honeypot com peso menor
    result.signals.forEach((raw) => {
        const [name] = raw.split(":");
        if (name?.startsWith("timing")) {
            signals.push({
                violation: "HONEYPOT_TIMING_FAST",
                weight: 30,
                confidence: 0.60,
                source: "honeypot",
                detail: raw,
            });
        }
    });

    return signals;
}

/**
 * Converte o resultado do Behavioral em sinais para o orquestrador.
 */
function behavioralToSignals(result: BehavioralResult): BotDetectionSignal[] {
    const signals: BotDetectionSignal[] = [];

    // Converte humanScore (0–100 pró-humano) para riskScore (0–100 pró-bot)
    const riskScore = 100 - result.humanScore;

    if (result.botSignals.includes("WEBDRIVER_DETECTED")) {
        signals.push({
            violation: "BEHAVIORAL_WEBDRIVER",
            weight: 95,
            confidence: 0.99,
            source: "behavioral",
            detail: "navigator.webdriver detected",
        });
    }

    if (result.verdict === "bot" || result.verdict === "likely_bot") {
        signals.push({
            violation: "BEHAVIORAL_BOT_DETECTED",
            weight: riskScore,
            confidence: result.confidence,
            source: "behavioral",
            detail: `Behavioral verdict: ${result.verdict} (humanScore: ${result.humanScore})`,
        });
    } else if (result.verdict === "suspicious") {
        signals.push({
            violation: "BEHAVIORAL_SUSPICIOUS",
            weight: Math.round(riskScore * 0.6),
            confidence: result.confidence,
            source: "behavioral",
            detail: `Behavioral verdict: suspicious (humanScore: ${result.humanScore})`,
        });
    }

    return signals;
}

/**
 * Converte o resultado do CAPTCHA em sinais para o orquestrador.
 */
function captchaToSignals(result: CaptchaVerificationResult): BotDetectionSignal[] {
    const signals: BotDetectionSignal[] = [];

    switch (result.status) {
        case "success":
            break; // Nenhum sinal negativo

        case "low_score":
            signals.push({
                violation: "CAPTCHA_LOW_SCORE",
                weight: 50,
                confidence: 0.75,
                source: "captcha",
                detail: `CAPTCHA score ${result.score?.toFixed(2)} below threshold`,
            });
            break;

        case "missing_token":
            signals.push({
                violation: "CAPTCHA_MISSING",
                weight: 45,
                confidence: 0.70,
                source: "captcha",
                detail: "CAPTCHA token not provided",
            });
            break;

        case "provider_error":
            signals.push({
                violation: "CAPTCHA_PROVIDER_ERROR",
                weight: 20,   // Peso baixo — pode ser problema do servidor
                confidence: 0.30,
                source: "captcha",
                detail: "CAPTCHA provider returned an error",
            });
            break;

        default:
            signals.push({
                violation: "CAPTCHA_INVALID",
                weight: 70,
                confidence: 0.85,
                source: "captcha",
                detail: `CAPTCHA verification failed: ${result.status}`,
            });
    }

    return signals;
}

/**
 * Calcula o score final ponderado pelos pesos de cada módulo.
 * Cada módulo contribui com seu score máximo × seu peso.
 */
function calculateWeightedScore(
    honeypotScore: number,  // 0–100
    behavioralScore: number,  // 0–100 (risk, não human)
    captchaScore: number,  // 0–100
    weights: Required<typeof DEFAULTS>["weights"],
    checksRun: Array<"honeypot" | "behavioral" | "captcha">
): number {
    // Redistribui os pesos para os checks que foram executados
    const activeWeights: Record<string, number> = {};
    let totalWeight = 0;

    if (checksRun.includes("honeypot")) {
        activeWeights["honeypot"] = weights.honeypot;
        totalWeight += weights.honeypot;
    }
    if (checksRun.includes("behavioral")) {
        activeWeights["behavioral"] = weights.behavioral;
        totalWeight += weights.behavioral;
    }
    if (checksRun.includes("captcha")) {
        activeWeights["captcha"] = weights.captcha;
        totalWeight += weights.captcha;
    }

    if (totalWeight === 0) return 0;

    // Normaliza os pesos para somar 1.0
    const norm = 1 / totalWeight;

    let score = 0;
    if (activeWeights["honeypot"] !== undefined) score += honeypotScore * activeWeights["honeypot"] * norm;
    if (activeWeights["behavioral"] !== undefined) score += behavioralScore * activeWeights["behavioral"] * norm;
    if (activeWeights["captcha"] !== undefined) score += captchaScore * activeWeights["captcha"] * norm;

    return Math.round(Math.min(100, score));
}

// ─────────────────────────────────────────────────────────────────────────────
// ORQUESTRADOR PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executa o pipeline completo de detecção de bots em uma NextRequest.
 *
 * @example
 * ```ts
 * // app/api/contato/route.ts
 * import { detectBot, buildBotResponse } from "@/lib/security/anti-bot/bot-detection";
 * import { honeypot } from "@/lib/security/anti-bot/instance";
 *
 * export async function POST(request: NextRequest) {
 *   const body = await request.json();
 *
 *   const result = await detectBot(request, {
 *     honeypot: { secret: process.env.HONEYPOT_SECRET },
 *     behavioral: { minHumanScore: 40 },
 *     captcha: {
 *       provider:  "recaptcha_v3",
 *       secretKey: process.env.RECAPTCHA_SECRET_KEY!,
 *       minScore:  0.5,
 *       expectedAction: "contact",
 *     },
 *     blockThreshold:     70,
 *     challengeThreshold: 50,
 *   });
 *
 *   if (result.isBot) {
 *     // Resposta opaca — não revela que foi detectado
 *     return NextResponse.json({ success: true });
 *   }
 *
 *   if (result.action === "challenge") {
 *     return NextResponse.json({ challenge: true }, { status: 401 });
 *   }
 *
 *   // Processa normalmente...
 * }
 * ```
 */
export async function detectBot(
    request: NextRequest,
    options: BotDetectionOptions = {}
): Promise<BotDetectionResult> {
    const startTime = Date.now();
    const requestId = generateRequestId();
    const ip = extractIP(request);
    const url = new URL(request.url);

    const opts = {
        blockThreshold: options.blockThreshold ?? DEFAULTS.blockThreshold,
        challengeThreshold: options.challengeThreshold ?? DEFAULTS.challengeThreshold,
        monitorThreshold: options.monitorThreshold ?? DEFAULTS.monitorThreshold,
        onModuleError: options.onModuleError ?? DEFAULTS.onModuleError,
        shortCircuit: options.shortCircuit ?? DEFAULTS.shortCircuit,
        verboseLog: options.verboseLog ?? DEFAULTS.verboseLog,
        weights: {
            honeypot: options.weights?.honeypot ?? DEFAULTS.weights.honeypot,
            behavioral: options.weights?.behavioral ?? DEFAULTS.weights.behavioral,
            captcha: options.weights?.captcha ?? DEFAULTS.weights.captcha,
        },
    };

    // Estado do pipeline
    const allSignals: BotDetectionSignal[] = [];
    const checksRun: Array<"honeypot" | "behavioral" | "captcha"> = [];
    let honeypotResult: HoneypotResult | null = null;
    let behavioralResult: BehavioralResult | null = null;
    let captchaResult: CaptchaVerificationResult | null = null;
    let honeypotScore = 0;
    let behavioralScore = 0;
    let captchaScore = 0;
    let earlyExit = false;

    // Extrai o body uma única vez (clonando para não consumir o stream)
    let parsedBody: Record<string, unknown> = {};
    try {
        const clone = request.clone();
        parsedBody = await clone.json() as Record<string, unknown>;
    } catch {
        // Body vazio ou não-JSON — não é erro, continua
    }

    // ── 1. HONEYPOT ─────────────────────────────────────────────────────────────
    if (options.honeypot !== false) {
        checksRun.push("honeypot");
        try {
            const honeypotConfig = typeof options.honeypot === "object"
                ? options.honeypot
                : {};

            const hp = new HoneypotMiddleware({
                ...honeypotConfig,
                store: honeypotConfig.store ?? new MemoryHoneypotStore(),
            });

            const hpRequest: HoneypotRequest = {
                ip,
                method: request.method,
                path: url.pathname,
                headers: Object.fromEntries(request.headers.entries()),
                body: parsedBody,
            };

            honeypotResult = await hp.checkForm(hpRequest);

            if (!honeypotResult.clean) {
                const hpSignals = honeypotToSignals(honeypotResult);
                allSignals.push(...hpSignals);
                // Score do honeypot = o maior peso entre os sinais detectados
                honeypotScore = hpSignals.reduce(
                    (max, s) => Math.max(max, s.weight), 0
                );

                // Short-circuit: honeypot com score máximo encerra o pipeline
                if (opts.shortCircuit && honeypotScore >= opts.blockThreshold) {
                    earlyExit = true;
                }
            }
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (opts.onModuleError === "block") {
                allSignals.push({
                    violation: "PIPELINE_ERROR",
                    weight: opts.blockThreshold,
                    confidence: 1.0,
                    source: "pipeline",
                    detail: `Honeypot module error: ${msg}`,
                });
                earlyExit = true;
            }
            if (opts.verboseLog) {
                console.error("[BOT_DETECTION] Honeypot module error:", msg);
            }
        }
    }

    // ── 2. BEHAVIORAL ────────────────────────────────────────────────────────────
    if (!earlyExit && options.behavioral !== false) {
        // Telemetria pode vir no body como campo "telemetry"
        const telemetry = parsedBody["telemetry"] as UserTelemetry | undefined;

        if (telemetry) {
            checksRun.push("behavioral");
            try {
                const behavioralConfig = typeof options.behavioral === "object"
                    ? options.behavioral
                    : {};

                behavioralResult = analyzeBehavior(telemetry, behavioralConfig);
                const bSignals = behavioralToSignals(behavioralResult);
                allSignals.push(...bSignals);
                behavioralScore = 100 - behavioralResult.humanScore; // inverte para risco

                if (opts.shortCircuit && behavioralScore >= opts.blockThreshold) {
                    earlyExit = true;
                }
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                if (opts.onModuleError === "block") {
                    allSignals.push({
                        violation: "PIPELINE_ERROR",
                        weight: opts.blockThreshold,
                        confidence: 1.0,
                        source: "pipeline",
                        detail: `Behavioral module error: ${msg}`,
                    });
                    earlyExit = true;
                }
                if (opts.verboseLog) {
                    console.error("[BOT_DETECTION] Behavioral module error:", msg);
                }
            }
        }
    }

    // ── 3. CAPTCHA ───────────────────────────────────────────────────────────────
    if (!earlyExit && options.captcha && typeof options.captcha === "object") {
        const captchaOpts: CaptchaOptions = options.captcha;
        checksRun.push("captcha");
        try {
            captchaResult = await verifyCaptcha(request, captchaOpts);

            const cSignals = captchaToSignals(captchaResult);
            allSignals.push(...cSignals);
            captchaScore = cSignals.reduce((max, s) => Math.max(max, s.weight), 0);

            // Score positivo do CAPTCHA reduz o risco global
            if (captchaResult.ok && captchaResult.score !== undefined) {
                captchaScore = Math.round((1 - captchaResult.score) * 100);
            } else if (captchaResult.ok) {
                captchaScore = 0; // CAPTCHA passou sem score (v2) — sem risco
            }
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (opts.onModuleError === "block") {
                allSignals.push({
                    violation: "PIPELINE_ERROR",
                    weight: opts.blockThreshold,
                    confidence: 1.0,
                    source: "pipeline",
                    detail: `CAPTCHA module error: ${msg}`,
                });
                earlyExit = true;
            }
            if (opts.verboseLog) {
                console.error("[BOT_DETECTION] CAPTCHA module error:", msg);
            }
        }
    }

    // ── Score final ──────────────────────────────────────────────────────────────
    const riskScore = earlyExit
        ? 100  // Short-circuit = score máximo
        : calculateWeightedScore(
            honeypotScore,
            behavioralScore,
            captchaScore,
            opts.weights,
            checksRun
        );

    const action = scoreToAction(riskScore, opts);
    const isBot = riskScore >= opts.blockThreshold;

    // ── Combina com CAPTCHA score para decisão mais refinada ──────────────────────
    // Se temos tanto behavioral quanto captcha, usa combineScores() para precisão
    let finalRiskScore = riskScore;
    if (behavioralResult && captchaResult?.score !== undefined) {
        const combined = combineScores({
            behavioralScore: 100 - behavioralResult.humanScore,
            captchaScore: 1 - captchaResult.score, // inverte: captcha score é pró-humano
            behavioralWeight: opts.weights.behavioral / (opts.weights.behavioral + opts.weights.captcha),
            captchaWeight: opts.weights.captcha / (opts.weights.behavioral + opts.weights.captcha),
        });
        // Usa a média entre o score ponderado e o combinado
        finalRiskScore = Math.round((riskScore + combined) / 2);
    }

    const result: BotDetectionResult = {
        isBot: finalRiskScore >= opts.blockThreshold,
        action: scoreToAction(finalRiskScore, opts),
        riskScore: finalRiskScore,
        signals: allSignals,
        details: {
            honeypot: honeypotResult,
            behavioral: behavioralResult,
            captcha: captchaResult,
        },
        audit: {
            requestId,
            timestamp: new Date().toISOString(),
            ip,
            path: url.pathname,
            method: request.method,
            processingMs: Date.now() - startTime,
            checksRun,
        },
    };

    // ── Callback de auditoria ──────────────────────────────────────────────────
    if (result.isBot || result.action !== "allow") {
        void options.onBotDetected?.(result, request);
        logDetection(result, opts.verboseLog);
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS INTERNOS
// ─────────────────────────────────────────────────────────────────────────────

function logDetection(
    result: BotDetectionResult,
    verbose: boolean
): void {
    const level = result.isBot ? "warn" : "info";
    const payload = {
        requestId: result.audit.requestId,
        ip: result.audit.ip,
        path: result.audit.path,
        action: result.action,
        riskScore: result.riskScore,
        checksRun: result.audit.checksRun,
        violations: result.signals.map((s) => ({
            type: s.violation,
            weight: s.weight,
            confidence: s.confidence,
        })),
        processingMs: result.audit.processingMs,
    };

    if (verbose) {
        console[level]("[BOT_DETECTION]", JSON.stringify(payload, null, 2));
    } else {
        console[level]("[BOT_DETECTION]", payload);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPOSTA HTTP
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Constrói a NextResponse adequada para cada ação de detecção.
 *
 * IMPORTANTE: para "block", retorna 200 falso por padrão — nunca revele
 * ao bot que ele foi detectado. Use `exposeBlocking: true` apenas
 * para environments de debug.
 *
 * @example
 * ```ts
 * const result = await detectBot(request, opts);
 * if (result.action !== "allow") {
 *   return buildBotResponse(result);
 * }
 * ```
 */
export function buildBotResponse(
    result: BotDetectionResult,
    options: {
        /**
         * Se true, retorna 403 real em vez de 200 falso (padrão: false).
         * Use apenas em desenvolvimento — em produção sempre false.
         */
        exposeBlocking?: boolean;
        /** Mensagem de sucesso falsa para bots (padrão: "Enviado com sucesso!"). */
        fakeSuccessMessage?: string;
        /** URL para redirecionar em caso de "challenge". */
        challengeRedirectUrl?: string;
    } = {}
): NextResponse {
    const isDev = process.env.NODE_ENV === "development";
    const expose = options.exposeBlocking ?? false;

    switch (result.action) {
        case "allow":
            // Não deveria chegar aqui, mas retorna OK por segurança
            return NextResponse.json({ success: true });

        case "challenge": {
            if (options.challengeRedirectUrl) {
                return NextResponse.redirect(
                    new URL(options.challengeRedirectUrl, "https://placeholder"),
                    { status: 302 }
                );
            }
            return new NextResponse(
                JSON.stringify({
                    error: "Verification required",
                    challenge: true,
                    requestId: result.audit.requestId,
                }),
                {
                    status: 401,
                    headers: {
                        "Content-Type": "application/json",
                        "X-Content-Type-Options": "nosniff",
                        "Cache-Control": "no-store",
                    },
                }
            );
        }

        case "monitor":
            // Permite mas pode adicionar header interno para logging
            return NextResponse.json({ success: true });

        case "block":
        default: {
            if (expose || isDev) {
                return new NextResponse(
                    JSON.stringify({
                        error: "Bot detected",
                        requestId: result.audit.requestId,
                        ...(isDev && {
                            debug: {
                                riskScore: result.riskScore,
                                action: result.action,
                                violations: result.signals.map((s) => s.violation),
                            },
                        }),
                    }),
                    {
                        status: 403,
                        headers: {
                            "Content-Type": "application/json",
                            "X-Content-Type-Options": "nosniff",
                            "Cache-Control": "no-store",
                        },
                    }
                );
            }

            // Produção: resposta falsa de sucesso — o bot não sabe que foi bloqueado
            return NextResponse.json({
                success: true,
                message: options.fakeSuccessMessage ?? "Enviado com sucesso!",
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE WRAPPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrapper completo para Route Handlers — detecta e responde automaticamente.
 *
 * @example
 * ```ts
 * // app/api/contato/route.ts
 * export async function POST(request: NextRequest) {
 *   return withBotDetection(
 *     request,
 *     async (botResult) => {
 *       // Só chega aqui se action === "allow"
 *       // botResult disponível para lógica adicional (ex: rate limiting por score)
 *       const body = await request.json();
 *       await processarContato(body);
 *       return NextResponse.json({ success: true });
 *     },
 *     {
 *       honeypot:  { secret: process.env.HONEYPOT_SECRET },
 *       behavioral: { minHumanScore: 40 },
 *       captcha: {
 *         provider:  "recaptcha_v3",
 *         secretKey: process.env.RECAPTCHA_SECRET_KEY!,
 *         minScore:  0.5,
 *         expectedAction: "contact",
 *       },
 *     }
 *   );
 * }
 * ```
 */
export async function withBotDetection(
    request: NextRequest,
    handler: (result: BotDetectionResult) => NextResponse | Promise<NextResponse>,
    options: BotDetectionOptions = {}
): Promise<NextResponse> {
    const result = await detectBot(request, options);

    if (result.action === "block" || result.isBot) {
        return buildBotResponse(result);
    }

    if (result.action === "challenge") {
        return buildBotResponse(result);
    }

    // "allow" e "monitor" passam para o handler
    return handler(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS PÚBLICOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Retorna uma label legível para o riskScore.
 *
 * @example
 * ```ts
 * console.log(getRiskLabel(85)); // "Alto risco — provável bot"
 * ```
 */
export function getRiskLabel(score: number): string {
    if (score >= 90) return "Crítico — bot confirmado";
    if (score >= 70) return "Alto risco — provável bot";
    if (score >= 50) return "Médio risco — suspeito";
    if (score >= 30) return "Baixo risco — monitorar";
    return "Risco mínimo — provável humano";
}

/**
 * Verifica rapidamente se um resultado indica bot sem instanciar todo o pipeline.
 * Útil para guards simples em middleware.
 */
export function isDefinitelyBot(result: BotDetectionResult): boolean {
    return (
        result.riskScore >= 90 ||
        result.signals.some(
            (s) =>
                s.violation === "BEHAVIORAL_WEBDRIVER" ||
                (s.violation === "HONEYPOT_FIELD_FILLED" && s.confidence > 0.95)
        )
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

export { DEFAULTS as BOT_DETECTION_DEFAULTS, HONEYPOT_TRIGGER_MAP };