/**
 * anti-bot/behavioral-analysis.ts
 *
 * Análise comportamental client-side para distinguir humanos de bots
 * de forma transparente — sem fricção para o usuário.
 *
 * ── Arquitetura ───────────────────────────────────────────────────────────
 *
 * Este módulo tem DUAS partes que trabalham juntas:
 *
 *   CLIENT (navegador)                SERVER (Next.js API Route)
 *   ─────────────────                 ──────────────────────────
 *   BehavioralCollector               analyzeBehavior()
 *        │                                   │
 *        │  coleta eventos DOM               │  analisa telemetria
 *        │  (mouse, teclado, scroll)         │  calcula score (0–100)
 *        │                                   │  detecta padrões de bot
 *        └──── UserTelemetry (JSON) ─────────┘
 *                 via HTTP POST
 *
 * ── O que analisa ─────────────────────────────────────────────────────────
 *
 *  Sinais de HUMANO:
 *   - Movimentos de mouse com variação de velocidade (Bézier natural)
 *   - Pausa antes de clicar (tempo de reação humano: 150–400ms)
 *   - Scroll com aceleração/desaceleração
 *   - Keystroke dynamics: variação no intervalo entre teclas (dwell/flight time)
 *   - Tempo total na página condizente com o conteúdo
 *   - Foco/desfoque de janela (troca de abas — comportamento humano normal)
 *   - Eventos de toque em dispositivos móveis (pressão, área de contato)
 *   - Movimentos de scroll irregular (humanos não scrollam em velocidade constante)
 *
 *  Sinais de BOT:
 *   - Zero movimentos de mouse
 *   - Submissão em < 500ms (impossível para humano)
 *   - Movimentos perfeitamente lineares (interpolação matemática)
 *   - Intervalos entre teclas perfeitamente iguais (script digitando)
 *   - Ausência total de scroll mesmo em página longa
 *   - Zero foco/desfoque (bot não troca de aba)
 *   - Coordenadas de mouse fora dos limites da viewport
 *   - Clique em posição exata sem movimento prévio (click() via JS)
 *   - window.navigator.webdriver === true (Selenium/Playwright)
 *   - Inconsistência entre userAgent e capacidades reais do navegador
 *
 * ── Integração ────────────────────────────────────────────────────────────
 *
 *  Client: BehavioralCollector → coleta → serialize() → envia junto com o form
 *  Server: analyzeBehavior(telemetry) → BehavioralResult → decide ação
 *
 * Integra-se com: honeypot.ts, recaptcha.ts, trafficInspection.ts
 *
 * @module security/anti-bot/behavioral-analysis
 */

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS — TELEMETRIA (dados coletados no cliente)
// ─────────────────────────────────────────────────────────────────────────────

/** Ponto de posição do mouse com timestamp. */
export interface MousePoint {
    x: number;
    y: number;
    /** Timestamp em ms desde o início da coleta (não Unix time — privacidade). */
    t: number;
}

/** Evento de clique com contexto. */
export interface ClickEvent {
    x: number;
    y: number;
    t: number;
    /** Distância percorrida pelo mouse nos 100ms antes do clique. */
    priorMovementPx: number;
    /** Elemento alvo do clique (tag normalizada: "button", "a", "input", etc). */
    targetTag: string;
}

/** Intervalo entre teclas (keystroke dynamics). */
export interface KeystrokeInterval {
    /** Dwell time: quanto tempo a tecla ficou pressionada (ms). */
    dwellMs: number;
    /** Flight time: tempo entre o release de uma tecla e o press da próxima (ms). */
    flightMs: number;
}

/** Evento de scroll com velocidade. */
export interface ScrollEvent {
    /** Pixels scrollados desde o evento anterior. */
    deltaY: number;
    t: number;
    /** Posição absoluta do scroll no momento do evento. */
    scrollY: number;
}

/**
 * Payload completo de telemetria comportamental.
 * Coletado no cliente e enviado ao servidor para análise.
 *
 * Campos opcionais são sinais extras — a análise funciona mesmo sem eles,
 * mas com mais sinais a precisão aumenta.
 */
export interface UserTelemetry {
    // ── Métricas básicas ──────────────────────────────────────────────────────

    /** Total de eventos mousemove registrados. */
    mouseMoveCount: number;
    /** Total de cliques. */
    clickCount: number;
    /** Total de eventos de scroll. */
    scrollCount: number;
    /** Total de keydowns. */
    keyStrokeCount: number;
    /** Tempo desde a primeira interação até o submit (ms). */
    timeToSubmitMs: number;
    /** Tempo desde o carregamento da página até o submit (ms). */
    timeOnPageMs: number;
    /** Total de eventos de toque (dispositivos touch). */
    touchEventCount: number;

    // ── Sinais avançados (opcionais) ──────────────────────────────────────────

    /**
     * Amostra de posições do mouse (máximo 50 pontos).
     * O cliente deve amostrar, não enviar todos os eventos.
     */
    mouseSample?: MousePoint[];

    /** Dados de cliques (máximo 10). */
    clicks?: ClickEvent[];

    /** Intervalos de keystroke (máximo 20). */
    keystrokeIntervals?: KeystrokeInterval[];

    /** Eventos de scroll (máximo 20). */
    scrollEvents?: ScrollEvent[];

    /** Quantas vezes o usuário saiu e voltou para a aba (focus/blur). */
    focusBlurCount?: number;

    /** Dimensões da viewport no momento do submit. */
    viewport?: { width: number; height: number };

    /**
     * Sinais do ambiente coletados pelo cliente.
     * Detecta inconsistências que indicam automação.
     */
    environment?: EnvironmentSignals;

    /**
     * Timestamp Unix (ms) do início da coleta.
     * Usado para validar que a telemetria não é muito antiga.
     */
    collectionStartTs?: number;

    /**
     * Identificador da sessão de coleta — previne replay de telemetria.
     * Gerado pelo BehavioralCollector no cliente.
     */
    sessionId?: string;
}

/** Sinais do ambiente do navegador — detecta automação. */
export interface EnvironmentSignals {
    /** window.navigator.webdriver === true → Selenium/Playwright/WebDriver */
    webdriverDetected: boolean;
    /** Número de plugins do navegador (headless geralmente tem 0). */
    pluginCount: number;
    /** Profundidade de cor da tela (headless pode ser 0 ou 1). */
    colorDepth: number;
    /** Se o navegador tem suporte a WebGL (headless frequentemente não tem). */
    hasWebGL: boolean;
    /** Se existe propriedade __selenium_evaluate ou similar. */
    hasAutomationProperty: boolean;
    /** Se o navigator.languages está preenchido (headless geralmente está vazio). */
    hasLanguages: boolean;
    /** Tamanho da tela (headless tende a ter dimensões padrão como 1024x768). */
    screenResolution?: { width: number; height: number };
    /** devicePixelRatio (headless frequentemente é 1.0 exato). */
    devicePixelRatio?: number;
    /** Se o hardware concurrency é suspeitosamente alto (mais de 32 cores). */
    hardwareConcurrency?: number;
    /**
     * Resultado do Canvas fingerprint (hash).
     * Headless browsers geram canvas diferente de browsers reais.
     */
    canvasFingerprint?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS — RESULTADO DA ANÁLISE (server-side)
// ─────────────────────────────────────────────────────────────────────────────

export type BehavioralSignalName =
    // Sinais negativos (indicam bot)
    | "NO_MOUSE_MOVEMENT"
    | "NO_SCROLL"
    | "NO_KEYSTROKES"
    | "SUBMIT_TOO_FAST"
    | "SUBMIT_EXTREMELY_FAST"
    | "LINEAR_MOUSE_MOVEMENT"
    | "PERFECT_KEYSTROKE_INTERVALS"
    | "CLICK_WITHOUT_PRIOR_MOVEMENT"
    | "MOUSE_OUTSIDE_VIEWPORT"
    | "WEBDRIVER_DETECTED"
    | "ZERO_PLUGINS"
    | "LOW_COLOR_DEPTH"
    | "NO_WEBGL"
    | "AUTOMATION_PROPERTY"
    | "HEADLESS_SCREEN_RESOLUTION"
    | "UNIFORM_SCROLL_SPEED"
    | "ZERO_FOCUS_BLUR"
    | "TELEMETRY_TOO_OLD"
    | "MISSING_ENVIRONMENT_SIGNALS"
    | "CANVAS_FINGERPRINT_ANOMALY"
    // Sinais positivos (indicam humano)
    | "NATURAL_MOUSE_CURVE"
    | "VARIED_KEYSTROKE_TIMING"
    | "ORGANIC_SCROLL_PATTERN"
    | "REALISTIC_TIME_ON_PAGE"
    | "FOCUS_BLUR_DETECTED"
    | "TOUCH_EVENTS_PRESENT"
    | "NORMAL_PLUGIN_COUNT"
    | "REALISTIC_VIEWPORT";

export interface BehavioralSignal {
    name: BehavioralSignalName;
    /** Positivo aumenta o score humano; negativo diminui. */
    impact: number;
    /** Confiança no sinal (0.0–1.0). */
    confidence: number;
    detail?: string;
}

export type BehavioralVerdict =
    | "human"          // Score alto, padrões naturais
    | "likely_human"   // Score bom, poucos sinais suspeitos
    | "suspicious"     // Sinais mistos — requerer verificação adicional
    | "likely_bot"     // Muitos sinais de automação
    | "bot";           // Certeza alta de automação

export interface BehavioralResult {
    /**
     * Score final de 0 a 100.
     * 0 = bot certo, 100 = humano certo.
     * (Invertido em relação ao score de risco dos outros módulos
     * porque aqui medimos "humanidade", não "risco".)
     */
    humanScore: number;

    /** Veredicto categórico baseado no score e nos sinais. */
    verdict: BehavioralVerdict;

    /** true se deve bloquear/desafiar a requisição. */
    shouldBlock: boolean;

    /** Sinais detectados com impacto e confiança. */
    signals: BehavioralSignal[];

    /** Sinais negativos resumidos para logging. */
    botSignals: BehavioralSignalName[];

    /** Sinais positivos resumidos para logging. */
    humanSignals: BehavioralSignalName[];

    /** Confiança geral da análise (0.0–1.0). Baixa = poucos dados. */
    confidence: number;

    /** Metadados para auditoria. */
    meta: {
        analyzedAt: string;
        telemetryAge?: number;
        signalCount: number;
        hasAdvancedSignals: boolean;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURAÇÃO DO ANALISADOR
// ─────────────────────────────────────────────────────────────────────────────

export interface BehavioralAnalysisConfig {
    /**
     * Score mínimo (0–100) para considerar humano (padrão: 40).
     * Abaixo disso, `shouldBlock` = true.
     */
    minHumanScore?: number;

    /**
     * Tempo mínimo de submit em ms (padrão: 800).
     * Abaixo disso é impossível para um humano.
     */
    minSubmitTimeMs?: number;

    /**
     * Tempo considerado "muito rápido" em ms (padrão: 3000).
     * Abaixo disso adiciona sinal negativo mas não bloqueia sozinho.
     */
    naturalMinTimeMs?: number;

    /**
     * Desvio padrão mínimo aceitável para keystroke intervals (padrão: 20ms).
     * Abaixo disso os intervalos são perfeitamente uniformes — indica script.
     */
    minKeystrokeStdDev?: number;

    /**
     * Variância mínima nos ângulos de movimento do mouse (padrão: 15°).
     * Movimentos perfeitamente lineares indicam interpolação matemática.
     */
    minMouseAngleVariance?: number;

    /**
     * Se deve bloquear automaticamente quando webdriver for detectado.
     * Padrão: true.
     */
    blockOnWebdriverDetected?: boolean;

    /**
     * Idade máxima da telemetria em ms (padrão: 600000 = 10min).
     * Telemetria muito antiga pode ser replay.
     */
    maxTelemetryAgeMs?: number;

    /**
     * Peso extra para sinais de ambiente (padrão: 1.5).
     * Aumentar se quiser priorizar detecção de headless browsers.
     */
    environmentSignalWeight?: number;

    /**
     * IDs de sessão já usados — previne replay de telemetria.
     * Em produção, usar Redis/KV store.
     */
    usedSessionIds?: Set<string>;
}

const ANALYSIS_DEFAULTS: Required<BehavioralAnalysisConfig> = {
    minHumanScore: 40,
    minSubmitTimeMs: 800,
    naturalMinTimeMs: 3_000,
    minKeystrokeStdDev: 20,
    minMouseAngleVariance: 15,
    blockOnWebdriverDetected: true,
    maxTelemetryAgeMs: 600_000,
    environmentSignalWeight: 1.5,
    usedSessionIds: new Set(),
};

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS MATEMÁTICOS (server-side)
// ─────────────────────────────────────────────────────────────────────────────

/** Calcula o desvio padrão de um array de números. */
function stdDev(values: number[]): number {
    if (values.length < 2) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
}

/** Calcula o ângulo em graus entre dois pontos. */
function angleBetween(a: MousePoint, b: MousePoint): number {
    return Math.atan2(b.y - a.y, b.x - a.x) * (180 / Math.PI);
}

/** Distância euclidiana entre dois pontos. */
function distance(a: MousePoint, b: MousePoint): number {
    return Math.sqrt(Math.pow(b.x - a.x, 2) + Math.pow(b.y - a.y, 2));
}

/** Calcula a curvatura de uma sequência de pontos (0 = linha reta). */
function calculateCurvature(points: MousePoint[]): number {
    if (points.length < 3) return 0;

    let totalCurvature = 0;
    for (let i = 1; i < points.length - 1; i++) {
        const prev = points[i - 1]!;
        const curr = points[i]!;
        const next = points[i + 1]!;

        const angle1 = angleBetween(prev, curr);
        const angle2 = angleBetween(curr, next);
        let delta = Math.abs(angle2 - angle1);
        if (delta > 180) delta = 360 - delta;
        totalCurvature += delta;
    }

    return totalCurvature / (points.length - 2);
}

/** Calcula a velocidade média de scroll. */
function scrollVelocities(events: ScrollEvent[]): number[] {
    if (events.length < 2) return [];
    const velocities: number[] = [];
    for (let i = 1; i < events.length; i++) {
        const dt = events[i]!.t - events[i - 1]!.t;
        if (dt > 0) {
            velocities.push(Math.abs(events[i]!.deltaY) / dt);
        }
    }
    return velocities;
}

// ─────────────────────────────────────────────────────────────────────────────
// ANALISADORES POR DOMÍNIO
// ─────────────────────────────────────────────────────────────────────────────

function analyzeTiming(
    telemetry: UserTelemetry,
    cfg: Required<BehavioralAnalysisConfig>
): BehavioralSignal[] {
    const signals: BehavioralSignal[] = [];
    const t = telemetry.timeToSubmitMs;

    if (t < cfg.minSubmitTimeMs) {
        signals.push({
            name: "SUBMIT_EXTREMELY_FAST",
            impact: -50,
            confidence: 0.97,
            detail: `Submit in ${t}ms — impossible for a human (min: ${cfg.minSubmitTimeMs}ms)`,
        });
    } else if (t < cfg.naturalMinTimeMs) {
        signals.push({
            name: "SUBMIT_TOO_FAST",
            impact: -25,
            confidence: 0.75,
            detail: `Submit in ${t}ms — unusually fast (natural min: ${cfg.naturalMinTimeMs}ms)`,
        });
    } else {
        signals.push({
            name: "REALISTIC_TIME_ON_PAGE",
            impact: +20,
            confidence: 0.80,
            detail: `Submit after ${t}ms — consistent with human behavior`,
        });
    }

    return signals;
}

function analyzeMouseMovement(
    telemetry: UserTelemetry,
    cfg: Required<BehavioralAnalysisConfig>
): BehavioralSignal[] {
    const signals: BehavioralSignal[] = [];

    if (telemetry.mouseMoveCount === 0) {
        // Dispositivos touch podem ter zero movimentos de mouse
        if (telemetry.touchEventCount === 0) {
            signals.push({
                name: "NO_MOUSE_MOVEMENT",
                impact: -20,
                confidence: 0.70,
                detail: "No mouse movement and no touch events",
            });
        }
        return signals;
    }

    // Análise avançada se temos a amostra de pontos
    const sample = telemetry.mouseSample;
    if (!sample || sample.length < 5) return signals;

    // Verifica coordenadas fora da viewport
    const vp = telemetry.viewport;
    if (vp) {
        const outOfBounds = sample.filter(
            (p) => p.x < 0 || p.y < 0 || p.x > vp.width || p.y > vp.height
        );
        if (outOfBounds.length > sample.length * 0.1) {
            signals.push({
                name: "MOUSE_OUTSIDE_VIEWPORT",
                impact: -30,
                confidence: 0.85,
                detail: `${outOfBounds.length} of ${sample.length} mouse points are outside viewport`,
            });
        }
    }

    // Análise de linearidade (movimentos perfeitamente retos = automação)
    const curvature = calculateCurvature(sample);
    if (curvature < cfg.minMouseAngleVariance && sample.length > 10) {
        signals.push({
            name: "LINEAR_MOUSE_MOVEMENT",
            impact: -35,
            confidence: 0.85,
            detail: `Average curvature ${curvature.toFixed(1)}° — suspiciously linear`,
        });
    } else if (curvature > cfg.minMouseAngleVariance * 2) {
        signals.push({
            name: "NATURAL_MOUSE_CURVE",
            impact: +25,
            confidence: 0.80,
            detail: `Natural mouse curvature detected (${curvature.toFixed(1)}°)`,
        });
    }

    return signals;
}

function analyzeClicks(telemetry: UserTelemetry): BehavioralSignal[] {
    const signals: BehavioralSignal[] = [];
    const clicks = telemetry.clicks;
    if (!clicks || clicks.length === 0) return signals;

    // Cliques sem movimento prévio = click() programático via JavaScript
    const clicksWithoutMovement = clicks.filter((c) => c.priorMovementPx < 2);
    if (
        clicksWithoutMovement.length > 0 &&
        clicksWithoutMovement.length === clicks.length
    ) {
        signals.push({
            name: "CLICK_WITHOUT_PRIOR_MOVEMENT",
            impact: -30,
            confidence: 0.80,
            detail: `All ${clicks.length} clicks have no prior mouse movement — possible programmatic click()`,
        });
    }

    return signals;
}

function analyzeKeystrokes(
    telemetry: UserTelemetry,
    cfg: Required<BehavioralAnalysisConfig>
): BehavioralSignal[] {
    const signals: BehavioralSignal[] = [];

    if (telemetry.keyStrokeCount === 0) {
        signals.push({
            name: "NO_KEYSTROKES",
            impact: -15,
            confidence: 0.60,
            detail: "No keystroke activity detected",
        });
        return signals;
    }

    const intervals = telemetry.keystrokeIntervals;
    if (!intervals || intervals.length < 4) return signals;

    const flightTimes = intervals.map((k) => k.flightMs).filter((v) => v >= 0);
    const dwellTimes = intervals.map((k) => k.dwellMs).filter((v) => v > 0);

    if (flightTimes.length >= 4) {
        const flightStdDev = stdDev(flightTimes);

        if (flightStdDev < cfg.minKeystrokeStdDev) {
            signals.push({
                name: "PERFECT_KEYSTROKE_INTERVALS",
                impact: -40,
                confidence: 0.90,
                detail: `Keystroke flight time std dev: ${flightStdDev.toFixed(1)}ms — suspiciously uniform (min expected: ${cfg.minKeystrokeStdDev}ms)`,
            });
        } else {
            signals.push({
                name: "VARIED_KEYSTROKE_TIMING",
                impact: +20,
                confidence: 0.85,
                detail: `Natural keystroke variation (std dev: ${flightStdDev.toFixed(1)}ms)`,
            });
        }
    }

    // Dwell time: humanos geralmente têm dwell entre 50–200ms
    if (dwellTimes.length >= 4) {
        const meanDwell = dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length;
        const dwellStd = stdDev(dwellTimes);

        if (meanDwell < 20 && dwellStd < 5) {
            // Teclas pressionadas por tempo mínimo e uniforme = script
            signals.push({
                name: "PERFECT_KEYSTROKE_INTERVALS",
                impact: -20,
                confidence: 0.75,
                detail: `Very short and uniform dwell times (mean: ${meanDwell.toFixed(0)}ms, std: ${dwellStd.toFixed(0)}ms)`,
            });
        }
    }

    return signals;
}

function analyzeScroll(telemetry: UserTelemetry): BehavioralSignal[] {
    const signals: BehavioralSignal[] = [];

    if (telemetry.scrollCount === 0) {
        signals.push({
            name: "NO_SCROLL",
            impact: -10,
            confidence: 0.50,
            detail: "No scroll activity (may be normal for short pages)",
        });
        return signals;
    }

    const events = telemetry.scrollEvents;
    if (!events || events.length < 3) {
        signals.push({
            name: "ORGANIC_SCROLL_PATTERN",
            impact: +10,
            confidence: 0.50,
        });
        return signals;
    }

    const velocities = scrollVelocities(events);
    if (velocities.length >= 3) {
        const velStdDev = stdDev(velocities);

        if (velStdDev < 0.5) {
            signals.push({
                name: "UNIFORM_SCROLL_SPEED",
                impact: -25,
                confidence: 0.80,
                detail: `Scroll velocities are perfectly uniform (std dev: ${velStdDev.toFixed(3)}) — indicates scripted scrollTo()`,
            });
        } else {
            signals.push({
                name: "ORGANIC_SCROLL_PATTERN",
                impact: +15,
                confidence: 0.75,
                detail: `Natural scroll acceleration pattern detected`,
            });
        }
    }

    return signals;
}

function analyzeEnvironment(
    env: EnvironmentSignals,
    cfg: Required<BehavioralAnalysisConfig>,
    viewport?: { width: number; height: number }
): BehavioralSignal[] {
    const signals: BehavioralSignal[] = [];
    const w = cfg.environmentSignalWeight;

    // WebDriver — o sinal mais confiável de automação
    if (env.webdriverDetected) {
        signals.push({
            name: "WEBDRIVER_DETECTED",
            impact: Math.round(-60 * w),
            confidence: 0.99,
            detail: "navigator.webdriver === true — Selenium/Playwright/WebDriver detected",
        });
    }

    // Propriedade de automação customizada
    if (env.hasAutomationProperty) {
        signals.push({
            name: "AUTOMATION_PROPERTY",
            impact: Math.round(-40 * w),
            confidence: 0.90,
            detail: "Browser automation property detected (__selenium_evaluate, _phantom, etc.)",
        });
    }

    // Plugins — browsers reais têm plugins, headless geralmente tem 0
    if (env.pluginCount === 0 && !env.webdriverDetected) {
        signals.push({
            name: "ZERO_PLUGINS",
            impact: Math.round(-15 * w),
            confidence: 0.65,
            detail: "Zero browser plugins — common in headless environments",
        });
    } else if (env.pluginCount >= 2) {
        signals.push({
            name: "NORMAL_PLUGIN_COUNT",
            impact: +10,
            confidence: 0.60,
        });
    }

    // Color depth — headless pode retornar 0, 1 ou 8
    if (env.colorDepth < 16) {
        signals.push({
            name: "LOW_COLOR_DEPTH",
            impact: Math.round(-20 * w),
            confidence: 0.70,
            detail: `Color depth ${env.colorDepth}bpp — unusually low for a real browser`,
        });
    }

    // WebGL — headless frequentemente não suporta
    if (!env.hasWebGL) {
        signals.push({
            name: "NO_WEBGL",
            impact: Math.round(-15 * w),
            confidence: 0.60,
            detail: "WebGL not supported — common in headless environments",
        });
    }

    // Languages — headless geralmente tem navigator.languages vazio
    if (!env.hasLanguages) {
        signals.push({
            name: "MISSING_ENVIRONMENT_SIGNALS",
            impact: Math.round(-15 * w),
            confidence: 0.65,
            detail: "navigator.languages is empty — unusual for a real browser",
        });
    }

    // Resolução suspeita de headless
    const screen = env.screenResolution;
    if (screen) {
        const commonHeadlessResolutions = [
            "800x600", "1024x768", "1280x720", "1366x768",
        ];
        const key = `${screen.width}x${screen.height}`;
        const isHeadlessRes = commonHeadlessResolutions.includes(key);
        const isSameAsViewport = viewport
            ? screen.width === viewport.width && screen.height === viewport.height
            : false;

        if (isHeadlessRes && isSameAsViewport && env.pluginCount === 0) {
            signals.push({
                name: "HEADLESS_SCREEN_RESOLUTION",
                impact: Math.round(-20 * w),
                confidence: 0.70,
                detail: `Screen resolution ${key} matches common headless browser defaults`,
            });
        }
    }

    // devicePixelRatio exatamente 1.0 com outros sinais suspeitos
    if (env.devicePixelRatio === 1.0 && env.pluginCount === 0 && !env.hasWebGL) {
        signals.push({
            name: "HEADLESS_SCREEN_RESOLUTION",
            impact: -10,
            confidence: 0.55,
            detail: "devicePixelRatio === 1.0 combined with other headless indicators",
        });
    }

    return signals;
}

// ─────────────────────────────────────────────────────────────────────────────
// ANALISADOR PRINCIPAL (SERVER-SIDE)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Analisa a telemetria comportamental e retorna um veredicto.
 *
 * @example
 * ```ts
 * // app/api/submit/route.ts
 * import { analyzeBehavior } from "@/lib/security/anti-bot/behavioral-analysis";
 *
 * export async function POST(request: NextRequest) {
 *   const body = await request.json();
 *   const telemetry = body.telemetry as UserTelemetry;
 *
 *   const result = analyzeBehavior(telemetry, { minHumanScore: 40 });
 *
 *   if (result.shouldBlock) {
 *     // Responde 200 falso para não revelar detecção
 *     return NextResponse.json({ success: true });
 *   }
 *
 *   // Processa normalmente...
 * }
 * ```
 */
export function analyzeBehavior(
    telemetry: UserTelemetry,
    config: BehavioralAnalysisConfig = {}
): BehavioralResult {
    const cfg = { ...ANALYSIS_DEFAULTS, ...config };
    const now = Date.now();
    const allSignals: BehavioralSignal[] = [];

    // ── Validade da telemetria ──────────────────────────────────────────────────
    if (telemetry.collectionStartTs) {
        const age = now - telemetry.collectionStartTs;
        if (age > cfg.maxTelemetryAgeMs) {
            allSignals.push({
                name: "TELEMETRY_TOO_OLD",
                impact: -30,
                confidence: 0.85,
                detail: `Telemetry is ${Math.round(age / 1000)}s old — possible replay`,
            });
        }
    }

    // ── Replay de sessão ───────────────────────────────────────────────────────
    if (
        telemetry.sessionId &&
        cfg.usedSessionIds.has(telemetry.sessionId)
    ) {
        allSignals.push({
            name: "TELEMETRY_TOO_OLD",
            impact: -50,
            confidence: 0.99,
            detail: `Session ID "${telemetry.sessionId}" has already been used — replay attack`,
        });
    } else if (telemetry.sessionId) {
        cfg.usedSessionIds.add(telemetry.sessionId);
    }

    // ── Análises por domínio ────────────────────────────────────────────────────
    allSignals.push(...analyzeTiming(telemetry, cfg));
    allSignals.push(...analyzeMouseMovement(telemetry, cfg));
    allSignals.push(...analyzeClicks(telemetry));
    allSignals.push(...analyzeKeystrokes(telemetry, cfg));
    allSignals.push(...analyzeScroll(telemetry));

    if (telemetry.environment) {
        allSignals.push(
            ...analyzeEnvironment(telemetry.environment, cfg, telemetry.viewport)
        );
    } else {
        // Ausência de dados de ambiente é leve sinal negativo
        allSignals.push({
            name: "MISSING_ENVIRONMENT_SIGNALS",
            impact: -10,
            confidence: 0.50,
            detail: "No environment signals provided",
        });
    }

    // Foco/blur da janela
    if (telemetry.focusBlurCount !== undefined) {
        if (telemetry.focusBlurCount > 0) {
            allSignals.push({
                name: "FOCUS_BLUR_DETECTED",
                impact: +10,
                confidence: 0.60,
                detail: `${telemetry.focusBlurCount} focus/blur events — consistent with human browsing`,
            });
        } else if (telemetry.timeOnPageMs > 10_000) {
            // Mais de 10s na página sem trocar de aba nunca é incomum para humanos
            allSignals.push({
                name: "ZERO_FOCUS_BLUR",
                impact: -10,
                confidence: 0.50,
                detail: "No focus/blur events despite extended time on page",
            });
        }
    }

    // Eventos de toque
    if (telemetry.touchEventCount > 0) {
        allSignals.push({
            name: "TOUCH_EVENTS_PRESENT",
            impact: +15,
            confidence: 0.70,
            detail: `${telemetry.touchEventCount} touch events — indicates mobile/tablet user`,
        });
    }

    // ── Bloqueio imediato por webdriver ────────────────────────────────────────
    const webdriverSignal = allSignals.find((s) => s.name === "WEBDRIVER_DETECTED");
    if (webdriverSignal && cfg.blockOnWebdriverDetected) {
        return buildResult(allSignals, 0, cfg, telemetry, now);
    }

    // ── Cálculo do score ───────────────────────────────────────────────────────
    // Começa em 50 (neutro) e ajusta conforme os sinais
    const BASE_SCORE = 50;
    const rawScore = allSignals.reduce((acc, s) => acc + s.impact, BASE_SCORE);
    const humanScore = Math.max(0, Math.min(100, rawScore));

    return buildResult(allSignals, humanScore, cfg, telemetry, now);
}

function buildResult(
    signals: BehavioralSignal[],
    humanScore: number,
    cfg: Required<BehavioralAnalysisConfig>,
    telemetry: UserTelemetry,
    now: number
): BehavioralResult {
    const botSignals = signals.filter((s) => s.impact < 0).map((s) => s.name);
    const humanSignals = signals.filter((s) => s.impact > 0).map((s) => s.name);
    const hasAdvanced = !!(
        telemetry.mouseSample?.length ||
        telemetry.keystrokeIntervals?.length ||
        telemetry.environment
    );

    // Confiança é proporcional à quantidade de sinais disponíveis
    const signalCount = signals.length;
    const confidence = Math.min(0.99, 0.3 + signalCount * 0.07);

    const verdict = scoreToVerdict(humanScore);
    const shouldBlock = humanScore < cfg.minHumanScore ||
        signals.some((s) => s.name === "WEBDRIVER_DETECTED" && s.confidence > 0.95);

    return {
        humanScore,
        verdict,
        shouldBlock,
        signals,
        botSignals,
        humanSignals,
        confidence,
        meta: {
            analyzedAt: new Date(now).toISOString(),
            telemetryAge: telemetry.collectionStartTs
                ? now - telemetry.collectionStartTs
                : undefined,
            signalCount,
            hasAdvancedSignals: hasAdvanced,
        },
    };
}

function scoreToVerdict(score: number): BehavioralVerdict {
    if (score >= 75) return "human";
    if (score >= 55) return "likely_human";
    if (score >= 40) return "suspicious";
    if (score >= 20) return "likely_bot";
    return "bot";
}

// ─────────────────────────────────────────────────────────────────────────────
// COLETOR CLIENT-SIDE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Coleta telemetria comportamental no navegador.
 *
 * IMPORTANTE: Este código roda no CLIENTE (browser), não no servidor.
 * Use em um Client Component (`"use client"`) ou script vanilla.
 *
 * @example
 * ```tsx
 * "use client";
 * import { BehavioralCollector } from "@/lib/security/anti-bot/behavioral-analysis";
 *
 * export function ContatoForm() {
 *   const collectorRef = useRef<BehavioralCollector | null>(null);
 *
 *   useEffect(() => {
 *     collectorRef.current = new BehavioralCollector();
 *     collectorRef.current.start();
 *     return () => collectorRef.current?.stop();
 *   }, []);
 *
 *   async function handleSubmit(e: React.FormEvent) {
 *     e.preventDefault();
 *     const telemetry = collectorRef.current?.collect();
 *
 *     await fetch("/api/contato", {
 *       method: "POST",
 *       body: JSON.stringify({ ...formData, telemetry }),
 *     });
 *   }
 * }
 * ```
 */
export class BehavioralCollector {
    private startTime = 0;
    private firstInteraction = 0;
    private running = false;
    private sessionId = "";

    // Contadores
    private mouseMoveCount = 0;
    private clickCount = 0;
    private scrollCount = 0;
    private keyStrokeCount = 0;
    private touchEventCount = 0;
    private focusBlurCount = 0;

    // Amostras
    private readonly mouseSample: MousePoint[] = [];
    private readonly clicks: ClickEvent[] = [];
    private readonly keystrokeIntervals: KeystrokeInterval[] = [];
    private readonly scrollEvents: ScrollEvent[] = [];

    // Estado interno para cálculos
    private lastMousePos: MousePoint | null = null;
    private lastKeyDownTime: number = 0;
    private lastKeyUpTime: number = 0;
    private lastScrollY: number = 0;
    private readonly MAX_SAMPLE = 50;
    private readonly MAX_CLICKS = 10;
    private readonly MAX_KEYS = 20;
    private readonly MAX_SCROLL = 20;

    // Handlers com bind para poder remover os listeners
    private readonly _onMouseMove = this.onMouseMove.bind(this);
    private readonly _onMouseDown = this.onMouseDown.bind(this);
    private readonly _onScroll = this.onScroll.bind(this);
    private readonly _onKeyDown = this.onKeyDown.bind(this);
    private readonly _onKeyUp = this.onKeyUp.bind(this);
    private readonly _onTouch = this.onTouch.bind(this);
    private readonly _onFocusBlur = this.onFocusBlur.bind(this);

    /** Inicia a coleta de eventos. Chame no mount do componente. */
    start(): void {
        if (this.running || typeof window === "undefined") return;
        this.running = true;
        this.startTime = Date.now();
        this.sessionId = this.generateSessionId();
        this.lastScrollY = window.scrollY;

        document.addEventListener("mousemove", this._onMouseMove, { passive: true });
        document.addEventListener("mousedown", this._onMouseDown, { passive: true });
        window.addEventListener("scroll", this._onScroll, { passive: true });
        document.addEventListener("keydown", this._onKeyDown, { passive: true });
        document.addEventListener("keyup", this._onKeyUp, { passive: true });
        document.addEventListener("touchstart", this._onTouch, { passive: true });
        window.addEventListener("focus", this._onFocusBlur, { passive: true });
        window.addEventListener("blur", this._onFocusBlur, { passive: true });
    }

    /** Para a coleta e remove todos os listeners. Chame no unmount. */
    stop(): void {
        if (!this.running) return;
        this.running = false;

        document.removeEventListener("mousemove", this._onMouseMove);
        document.removeEventListener("mousedown", this._onMouseDown);
        window.removeEventListener("scroll", this._onScroll);
        document.removeEventListener("keydown", this._onKeyDown);
        document.removeEventListener("keyup", this._onKeyUp);
        document.removeEventListener("touchstart", this._onTouch);
        window.removeEventListener("focus", this._onFocusBlur);
        window.removeEventListener("blur", this._onFocusBlur);
    }

    /**
     * Coleta e serializa a telemetria para envio ao servidor.
     * Chame no momento do submit.
     */
    collect(): UserTelemetry {
        const now = Date.now();
        const timeOnPage = now - this.startTime;
        const timeToSubmit = this.firstInteraction > 0
            ? now - this.firstInteraction
            : timeOnPage;

        return {
            // Contadores
            mouseMoveCount: this.mouseMoveCount,
            clickCount: this.clickCount,
            scrollCount: this.scrollCount,
            keyStrokeCount: this.keyStrokeCount,
            timeToSubmitMs: timeToSubmit,
            timeOnPageMs: timeOnPage,
            touchEventCount: this.touchEventCount,
            focusBlurCount: this.focusBlurCount,

            // Amostras
            mouseSample: [...this.mouseSample],
            clicks: [...this.clicks],
            keystrokeIntervals: [...this.keystrokeIntervals],
            scrollEvents: [...this.scrollEvents],

            // Contexto
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight,
            },

            // Sinais de ambiente
            environment: this.collectEnvironmentSignals(),

            // Metadados de sessão
            collectionStartTs: this.startTime,
            sessionId: this.sessionId,
        };
    }

    // ── Event handlers privados ─────────────────────────────────────────────────

    private onMouseMove(e: MouseEvent): void {
        const t = Date.now() - this.startTime;
        this.mouseMoveCount++;
        this.markFirstInteraction();

        // Amostragem: guarda apenas a cada 5 eventos para não sobrecarregar o payload
        if (this.mouseMoveCount % 5 === 0 && this.mouseSample.length < this.MAX_SAMPLE) {
            this.mouseSample.push({ x: Math.round(e.clientX), y: Math.round(e.clientY), t });
        }

        this.lastMousePos = { x: e.clientX, y: e.clientY, t };
    }

    private onMouseDown(e: MouseEvent): void {
        if (this.clicks.length >= this.MAX_CLICKS) return;
        const t = Date.now() - this.startTime;
        this.clickCount++;
        this.markFirstInteraction();

        const priorMove = this.lastMousePos
            ? Math.sqrt(
                Math.pow(e.clientX - this.lastMousePos.x, 2) +
                Math.pow(e.clientY - this.lastMousePos.y, 2)
            )
            : 0;

        const target = e.target as Element | null;
        this.clicks.push({
            x: Math.round(e.clientX),
            y: Math.round(e.clientY),
            t,
            priorMovementPx: Math.round(priorMove),
            targetTag: target?.tagName?.toLowerCase() ?? "unknown",
        });
    }

    private onScroll(): void {
        if (this.scrollEvents.length >= this.MAX_SCROLL) return;
        const t = Date.now() - this.startTime;
        const scrollY = window.scrollY;
        const deltaY = scrollY - this.lastScrollY;

        this.scrollCount++;
        this.markFirstInteraction();
        this.scrollEvents.push({ deltaY: Math.round(deltaY), t, scrollY: Math.round(scrollY) });
        this.lastScrollY = scrollY;
    }

    private onKeyDown(e: KeyboardEvent): void {
        // Ignora teclas de controle (Tab, Shift, Ctrl, etc.)
        if (e.key.length > 1 && !["Backspace", "Delete", "Space"].includes(e.key)) return;

        const now = Date.now();
        this.keyStrokeCount++;
        this.markFirstInteraction();
        this.lastKeyDownTime = now;
    }

    private onKeyUp(e: KeyboardEvent): void {
        if (e.key.length > 1 && !["Backspace", "Delete", "Space"].includes(e.key)) return;
        if (this.keystrokeIntervals.length >= this.MAX_KEYS) return;

        const now = Date.now();
        const dwellMs = now - this.lastKeyDownTime;
        const flightMs = this.lastKeyUpTime > 0
            ? this.lastKeyDownTime - this.lastKeyUpTime
            : -1;

        if (dwellMs > 0 && dwellMs < 2000) {
            this.keystrokeIntervals.push({ dwellMs, flightMs });
        }

        this.lastKeyUpTime = now;
    }

    private onTouch(): void {
        this.touchEventCount++;
        this.markFirstInteraction();
    }

    private onFocusBlur(): void {
        this.focusBlurCount++;
    }

    private markFirstInteraction(): void {
        if (this.firstInteraction === 0) {
            this.firstInteraction = Date.now();
        }
    }

    private generateSessionId(): string {
        const arr = new Uint8Array(12);
        crypto.getRandomValues(arr);
        return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
    }

    /** Coleta sinais do ambiente do navegador. */
    private collectEnvironmentSignals(): EnvironmentSignals {
        const nav = navigator as Navigator & Record<string, unknown>;

        // Detecta propriedades de automação
        const automationProps = [
            "__webdriver_evaluate",
            "__selenium_evaluate",
            "__webdriver_script_function",
            "__webdriver_script_func",
            "__webdriver_script_element",
            "__selenium_unwrapped",
            "__fxdriver_evaluate",
            "__driver_unwrapped",
            "_phantom",
            "_nightmare",
            "callPhantom",
        ];

        const hasAutomationProperty = automationProps.some(
            (prop) => prop in window || prop in nav
        );

        // Canvas fingerprint simples
        let canvasFingerprint: string | undefined;
        try {
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");
            if (ctx) {
                ctx.textBaseline = "top";
                ctx.font = "14px Arial";
                ctx.fillStyle = "#f60";
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = "#069";
                ctx.fillText("behavioral", 2, 15);
                ctx.fillStyle = "rgba(102,204,0,0.7)";
                ctx.fillText("analysis", 4, 17);
                // Pega apenas os primeiros 12 chars do hash para não vazar dados
                canvasFingerprint = canvas.toDataURL().slice(-12);
            }
        } catch {
            canvasFingerprint = undefined;
        }

        let hasWebGL = false;
        try {
            const gl = document.createElement("canvas").getContext("webgl");
            hasWebGL = gl !== null;
        } catch {
            hasWebGL = false;
        }

        return {
            webdriverDetected: nav.webdriver === true,
            pluginCount: nav.plugins?.length ?? 0,
            colorDepth: screen.colorDepth,
            hasWebGL,
            hasAutomationProperty,
            hasLanguages: Array.isArray(nav.languages) && nav.languages.length > 0,
            screenResolution: { width: screen.width, height: screen.height },
            devicePixelRatio: window.devicePixelRatio,
            hardwareConcurrency: nav.hardwareConcurrency as number | undefined,
            canvasFingerprint,
        };
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS PÚBLICOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Retorna uma label de risco legível para o veredicto.
 *
 * @example
 * ```ts
 * const result = analyzeBehavior(telemetry);
 * console.log(getVerdictLabel(result.verdict)); // "Provável humano"
 * ```
 */
export function getVerdictLabel(verdict: BehavioralVerdict): string {
    const labels: Record<BehavioralVerdict, string> = {
        human: "Humano confirmado",
        likely_human: "Provável humano",
        suspicious: "Suspeito — verificação recomendada",
        likely_bot: "Provável bot",
        bot: "Bot detectado",
    };
    return labels[verdict];
}

/**
 * Combina o score comportamental com o score do reCAPTCHA v3
 * para uma decisão mais precisa.
 *
 * @example
 * ```ts
 * const combined = combineScores({
 *   behavioralScore: result.humanScore,  // 0–100
 *   captchaScore:    captcha.score,      // 0.0–1.0
 * });
 * if (combined < 50) { // bloquear }
 * ```
 */
export function combineScores(opts: {
    behavioralScore: number;
    captchaScore?: number;
    behavioralWeight?: number;
    captchaWeight?: number;
}): number {
    const bw = opts.behavioralWeight ?? 0.6;
    const cw = opts.captchaWeight ?? 0.4;

    if (opts.captchaScore === undefined) {
        return opts.behavioralScore;
    }

    const captchaScoreNormalized = opts.captchaScore * 100;
    return Math.round(
        opts.behavioralScore * bw + captchaScoreNormalized * cw
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

export { ANALYSIS_DEFAULTS as BEHAVIORAL_ANALYSIS_DEFAULTS };