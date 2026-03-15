/**
 * anti-bot/honeypot.ts
 *
 * Armadilhas invisíveis para detectar bots e automação.
 *
 * Estratégias implementadas:
 *  1. Campo de formulário oculto — bots preenchem campos hidden que humanos não veem
 *  2. Rota honeypot (URL trap) — qualquer acesso a rotas-isca é bot ou scanner
 *  3. Timing check — humanos levam segundos; bots enviam em < 500ms
 *  4. Token de sessão encadeado — bots que não fazem GET inicial não têm token
 *  5. Link honeypot (crawler trap) — crawlers seguem links invisíveis
 *  6. Campo lure — campos com nomes atrativos para autofill de bots
 *
 * Vetores cobertos:
 *  - Form spam via bots simples (HTTP direto)
 *  - Credential stuffing com scripts básicos
 *  - Web scraping / crawling não autorizado
 *  - Reconhecimento via scanner de vulnerabilidades
 *  - Account enumeration via registro em massa
 *  - Comment spam, fake account creation, voting bots
 *
 * Integra-se com: recaptcha.ts, firewallRules.ts, trafficInspection.ts
 *
 * @module security/anti-bot/honeypot
 */

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES PÚBLICOS
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da verificação de honeypot. */
export interface HoneypotResult {
    /** true = passou na verificação (provavelmente humano). */
    clean: boolean;
    /** Qual armadilha foi acionada (undefined se clean = true). */
    triggered?: HoneypotTrigger;
    /** Detalhes para logging interno. Nunca retorne ao cliente. */
    detail?: string;
    /** Score de risco acumulado desta verificação (0–100). */
    score: number;
    /** Sinais individuais detectados (pode ter múltiplos). */
    signals: string[];
}

export type HoneypotTrigger =
    | "FIELD_FILLED"       // Campo hidden foi preenchido
    | "TIMING_TOO_FAST"    // Formulário enviado rápido demais
    | "TOKEN_MISSING"      // Token de sessão ausente
    | "TOKEN_INVALID"      // Token de sessão inválido ou expirado
    | "TOKEN_REPLAYED"     // Token já foi usado (replay attempt)
    | "TRAP_ROUTE_HIT"     // Bot acessou rota armadilha
    | "CRAWLER_TRAP_HIT"   // Crawler seguiu link honeypot
    | "LURE_FIELD_FILLED"  // Campo atraente (email hidden) foi preenchido
    | "MULTIPLE_SIGNALS";  // Vários sinais menores combinados

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURAÇÃO
// ─────────────────────────────────────────────────────────────────────────────

export interface HoneypotConfig {
    /**
     * Nomes dos campos honeypot no formulário.
     * Use nomes que pareçam reais para enganar bots, mas que nunca
     * devem ser preenchidos por humanos.
     * Padrão: ["website", "url", "company", "fax", "_hp_name", "_hp_email"]
     */
    fieldNames?: string[];

    /**
     * Nome do campo de timestamp — quando o formulário foi renderizado.
     * Padrão: "_t"
     */
    timestampField?: string;

    /**
     * Nome do campo que carrega o token de sessão.
     * Padrão: "_tk"
     */
    tokenField?: string;

    /**
     * Tempo mínimo em ms para preencher o formulário (padrão: 3000).
     * Calibragem recomendada:
     *   - 1 campo (email):            2000ms
     *   - Login (email + senha):      3000ms
     *   - Registro (5+ campos):       5000ms
     *   - Contato (texto livre):      8000ms
     */
    minSubmitTimeMs?: number;

    /**
     * Tempo máximo em ms — tokens mais antigos são rejeitados (padrão: 3600000 = 1h).
     */
    maxSubmitTimeMs?: number;

    /**
     * Segredo para assinar os tokens de formulário.
     * Use process.env.HONEYPOT_SECRET — mínimo 32 caracteres.
     */
    secret?: string;

    /**
     * Rotas que são armadilhas — qualquer acesso indica bot ou scanner.
     * Aparecem no HTML de forma invisível (CSS hidden).
     */
    trapRoutes?: string[];

    /**
     * Score acumulado mínimo para considerar bot (0–100).
     * Padrão: 70
     */
    scoreThreshold?: number;

    /** Pesos dos sinais individuais (0–100 cada). */
    signalWeights?: Partial<HoneypotSignalWeights>;

    /**
     * Store para persistência de tokens (previne replay).
     * Use MemoryHoneypotStore para dev, Redis em produção.
     */
    store?: HoneypotStore;

    /**
     * Hook chamado quando um bot é detectado.
     * Use para integração com logs, alertas e rate limiting.
     */
    onBotDetected?: (result: HoneypotResult, req: HoneypotRequest) => void | Promise<void>;

    /** Habilita logging detalhado. Padrão: false */
    debug?: boolean;
}

export interface HoneypotSignalWeights {
    fieldFilled: number;    // Campo hidden preenchido.  Padrão: 90
    timingTooFast: number;  // Envio muito rápido.       Padrão: 70
    tokenMissing: number;   // Sem token.                Padrão: 60
    tokenInvalid: number;   // Token inválido.           Padrão: 80
    tokenReplayed: number;  // Token reusado.            Padrão: 90
    trapRouteHit: number;   // Rota armadilha acessada.  Padrão: 100
    crawlerTrapHit: number; // Link honeypot seguido.    Padrão: 100
    lureFilled: number;     // Campo lure preenchido.    Padrão: 85
}

export interface HoneypotStore {
    /** Marca token como usado. Retorna true se já foi usado (replay). */
    markTokenUsed(token: string, ttlMs: number): Promise<boolean>;
    /** Verifica se token já foi usado sem marcar. */
    isTokenUsed(token: string): Promise<boolean>;
    /** Marca IP como bot detectado. */
    markBot(ip: string, ttlMs: number): Promise<void>;
    /** Verifica se IP já foi marcado como bot. */
    isMarkedBot(ip: string): Promise<boolean>;
}

/** Requisição normalizada para verificação de honeypot. */
export interface HoneypotRequest {
    ip?: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    body?: Record<string, unknown>;
    query?: Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────────────
// STORE EM MEMÓRIA
// ─────────────────────────────────────────────────────────────────────────────

export class MemoryHoneypotStore implements HoneypotStore {
    private readonly usedTokens = new Map<string, number>(); // token → expiresAt
    private readonly bots = new Map<string, number>(); // ip    → expiresAt
    private readonly interval: ReturnType<typeof setInterval>;

    constructor(cleanupMs = 60_000) {
        this.interval = setInterval(() => {
            const now = Date.now();
            Array.from(this.usedTokens.entries()).forEach(([k, v]) => {
                if (v < now) this.usedTokens.delete(k);
            });
            Array.from(this.bots.entries()).forEach(([k, v]) => {
                if (v < now) this.bots.delete(k);
            });
        }, cleanupMs);

        if (typeof this.interval.unref === "function") this.interval.unref();
    }

    async markTokenUsed(token: string, ttlMs: number): Promise<boolean> {
        const now = Date.now();
        const exp = this.usedTokens.get(token);
        if (exp !== undefined && exp > now) return true; // replay
        this.usedTokens.set(token, now + ttlMs);
        return false;
    }

    async isTokenUsed(token: string): Promise<boolean> {
        const exp = this.usedTokens.get(token);
        return exp !== undefined && exp > Date.now();
    }

    async markBot(ip: string, ttlMs: number): Promise<void> {
        this.bots.set(ip, Date.now() + ttlMs);
    }

    async isMarkedBot(ip: string): Promise<boolean> {
        const exp = this.bots.get(ip);
        if (exp === undefined) return false;
        if (exp < Date.now()) { this.bots.delete(ip); return false; }
        return true;
    }

    destroy(): void {
        clearInterval(this.interval);
        this.usedTokens.clear();
        this.bots.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS CRIPTOGRÁFICOS
// ─────────────────────────────────────────────────────────────────────────────

/** Gera token seguro base64url sem dependências externas. */
function generateToken(byteLength = 24): string {
    const bytes = new Uint8Array(byteLength);
    globalThis.crypto.getRandomValues(bytes);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

/** HMAC-SHA256 → base64url. Usa Web Crypto API (Node 15+, todos os browsers). */
async function hmacSign(data: string, secret: string): Promise<string> {
    const enc = new TextEncoder();
    const keyBuf = enc.encode(secret).buffer.slice(0) as ArrayBuffer;
    const datBuf = enc.encode(data).buffer.slice(0) as ArrayBuffer;

    const key = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBuf,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );

    const sig = await globalThis.crypto.subtle.sign("HMAC", key, datBuf);
    let binary = "";
    const bytes = new Uint8Array(sig);
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

/** Comparação em tempo constante — previne timing attack. */
function timingSafeEqual(a: string, b: string): boolean {
    const enc = new TextEncoder();
    const ba = enc.encode(a);
    const bb = enc.encode(b);
    let diff = ba.length ^ bb.length;
    const max = Math.max(ba.length, bb.length);
    for (let i = 0; i < max; i++) {
        diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
    }
    return diff === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES
// ─────────────────────────────────────────────────────────────────────────────

/** CSS de ocultação reutilizado em todos os campos honeypot. */
const HIDE_STYLE =
    "position:absolute;left:-9999px;top:-9999px;" +
    "width:1px;height:1px;overflow:hidden;" +
    "opacity:0;pointer-events:none;";

/** Padrões de path que indicam scanner de vulnerabilidades. */
const SCANNER_PATH_PATTERNS: RegExp[] = [
    /\/\.env(\b|$)/i,
    /\/wp-(?:admin|login|config)/i,
    /\/phpmy?admin/i,
    /\/\.git\//i,
    /\/config\.(?:json|yml|yaml|xml)/i,
    /\/(?:server-status|server-info)/i,
    /\/actuator(?:\/|$)/i,
    /\/(?:phpmyadmin|adminer)(?:\/|$)/i,
    /\/_(?:profiler|debug|console)/i,
    /\/(?:xmlrpc|wp-cron)\.php/i,
];

/** Campos lure — nomes que autofills de bots adoram. */
const LURE_FIELDS: Array<{ name: string; type: string; label: string }> = [
    { name: "_lure_email", type: "email", label: "Your email address" },
    { name: "_lure_phone", type: "tel", label: "Your phone number" },
];

export const HONEYPOT_DEFAULTS = {
    fieldNames: ["website", "url", "company", "fax", "_hp_name", "_hp_email"] as string[],
    timestampField: "_t",
    tokenField: "_tk",
    minSubmitTimeMs: 3_000,
    maxSubmitTimeMs: 3_600_000,
    trapRoutes: [] as string[],
    scoreThreshold: 70,
    debug: false,
} as const;

export const HoneypotFieldName = {
    DEFAULT: "_hp_name",
    EMAIL: "_hp_email",
    WEBSITE: "website",
    URL: "url",
    COMPANY: "company",
    FAX: "fax",
    TIMESTAMP: "_t",
    TOKEN: "_tk",
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// CLASSE PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

export class HoneypotMiddleware {
    private readonly cfg: Required<
        Omit<HoneypotConfig, "onBotDetected" | "store" | "secret" | "signalWeights">
    > & Pick<HoneypotConfig, "onBotDetected" | "store" | "secret">;

    private readonly weights: HoneypotSignalWeights;
    private readonly trapRouteSet: Set<string>;

    constructor(config: HoneypotConfig = {}) {
        this.cfg = {
            fieldNames: config.fieldNames ?? [...HONEYPOT_DEFAULTS.fieldNames],
            timestampField: config.timestampField ?? HONEYPOT_DEFAULTS.timestampField,
            tokenField: config.tokenField ?? HONEYPOT_DEFAULTS.tokenField,
            minSubmitTimeMs: config.minSubmitTimeMs ?? HONEYPOT_DEFAULTS.minSubmitTimeMs,
            maxSubmitTimeMs: config.maxSubmitTimeMs ?? HONEYPOT_DEFAULTS.maxSubmitTimeMs,
            trapRoutes: config.trapRoutes ?? [],
            scoreThreshold: config.scoreThreshold ?? HONEYPOT_DEFAULTS.scoreThreshold,
            debug: config.debug ?? HONEYPOT_DEFAULTS.debug,
            onBotDetected: config.onBotDetected,
            store: config.store,
            secret: config.secret,
        };

        this.weights = {
            fieldFilled: 90,
            timingTooFast: 70,
            tokenMissing: 60,
            tokenInvalid: 80,
            tokenReplayed: 90,
            trapRouteHit: 100,
            crawlerTrapHit: 100,
            lureFilled: 85,
            ...(config.signalWeights ?? {}),
        };

        this.trapRouteSet = new Set(
            this.cfg.trapRoutes.map((r) => r.toLowerCase()),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // VERIFICAÇÃO DE FORMULÁRIO
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica se um envio de formulário foi feito por bot.
     * Deve ser chamado no handler POST que processa o formulário.
     *
     * @example
     * ```ts
     * const check = await honeypot.checkForm(req);
     * if (!check.clean) {
     *   // Responde 200 para não revelar a detecção ao bot
     *   return res.status(200).json({ success: true });
     * }
     * ```
     */
    async checkForm(req: HoneypotRequest): Promise<HoneypotResult> {
        const signals: string[] = [];
        let totalScore = 0;
        const body = req.body ?? {};
        const ip = req.ip ?? "0.0.0.0";
        const now = Date.now();

        const addSignal = (name: string, weight: number): void => {
            signals.push(`${name}:${weight}`);
            totalScore = Math.min(100, totalScore + weight);
        };

        // ── IP já marcado como bot ───────────────────────────────────────────
        if (this.cfg.store && (await this.cfg.store.isMarkedBot(ip))) {
            signals.push("previously-detected-bot");
            return this.buildResult(
                false, "MULTIPLE_SIGNALS", "Known bot IP", 100, signals, req,
            );
        }

        // ── 1. Campos honeypot preenchidos ────────────────────────────────────
        for (const field of this.cfg.fieldNames) {
            const val = body[field];
            if (val !== undefined && val !== "" && val !== null) {
                addSignal(`field-filled:${field}`, this.weights.fieldFilled);
                this.debugLog("FIELD-FILLED", field, String(val).slice(0, 40));

                if (totalScore >= this.cfg.scoreThreshold) {
                    await this.markBot(ip);
                    return this.buildResult(
                        false,
                        "FIELD_FILLED",
                        `Honeypot field "${field}" was filled with: "${String(val).slice(0, 40)}"`,
                        totalScore,
                        signals,
                        req,
                    );
                }
            }
        }

        // ── 2. Campos lure preenchidos ─────────────────────────────────────────
        for (const { name } of LURE_FIELDS) {
            const val = body[name];
            if (val !== undefined && val !== "" && val !== null) {
                addSignal(`lure-field:${name}`, this.weights.lureFilled);
            }
        }

        // ── 3. Verificação de timing ───────────────────────────────────────────
        const tsRaw = body[this.cfg.timestampField];
        if (tsRaw !== undefined) {
            const formRenderedAt = parseInt(String(tsRaw), 10);

            if (!isNaN(formRenderedAt)) {
                const elapsed = now - formRenderedAt;

                if (elapsed < this.cfg.minSubmitTimeMs) {
                    addSignal(`timing-too-fast:${elapsed}ms`, this.weights.timingTooFast);
                    this.debugLog("TIMING-TOO-FAST", `${elapsed}ms < ${this.cfg.minSubmitTimeMs}ms`);
                }

                if (elapsed > this.cfg.maxSubmitTimeMs) {
                    addSignal(`timing-expired:${elapsed}ms`, this.weights.tokenInvalid);
                }
            } else {
                addSignal("timestamp-invalid", this.weights.tokenInvalid);
            }
        } else {
            addSignal("timestamp-missing", this.weights.tokenMissing);
        }

        // ── 4. Verificação de token de sessão ──────────────────────────────────
        if (this.cfg.secret) {
            const tokenResult = await this.verifyFormToken(body, now);

            switch (tokenResult.status) {
                case "missing":
                    addSignal("token-missing", this.weights.tokenMissing);
                    break;
                case "invalid":
                    addSignal("token-invalid", this.weights.tokenInvalid);
                    break;
                case "replayed":
                    addSignal("token-replayed", this.weights.tokenReplayed);
                    break;
                case "valid":
                    // Sinal positivo — reduz score levemente
                    if (totalScore > 0) totalScore = Math.max(0, totalScore - 10);
                    break;
            }
        }

        // ── Decisão final ──────────────────────────────────────────────────────
        if (totalScore >= this.cfg.scoreThreshold) {
            await this.markBot(ip);
            const trigger = this.scoreToTrigger(signals);
            return this.buildResult(
                false,
                trigger,
                `Score ${totalScore} ≥ threshold ${this.cfg.scoreThreshold}. Signals: ${signals.join(", ")}`,
                totalScore,
                signals,
                req,
            );
        }

        this.debugLog("CLEAN", ip, `score=${totalScore}`, signals);
        return { clean: true, score: totalScore, signals };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // VERIFICAÇÃO DE ROTA
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica se a rota atual é uma armadilha.
     * Responda com 404 (não 403) para não revelar a detecção.
     *
     * @example
     * ```ts
     * const check = honeypot.checkRoute(req.path, req.ip);
     * if (!check.clean) {
     *   return res.status(404).end();
     * }
     * ```
     */
    checkRoute(path: string, ip = "0.0.0.0"): HoneypotResult {
        const normalizedPath = path.toLowerCase().split("?")[0] ?? path;

        if (this.trapRouteSet.has(normalizedPath)) {
            this.debugLog("TRAP-ROUTE-HIT", ip, normalizedPath);
            return this.buildResult(
                false,
                "TRAP_ROUTE_HIT",
                `Bot accessed trap route: ${normalizedPath}`,
                this.weights.trapRouteHit,
                [`trap-route:${normalizedPath}`],
                { ip, method: "GET", path, headers: {} },
            );
        }

        for (const pattern of SCANNER_PATH_PATTERNS) {
            if (pattern.test(normalizedPath)) {
                this.debugLog("SCANNER-ROUTE", ip, normalizedPath);
                return this.buildResult(
                    false,
                    "TRAP_ROUTE_HIT",
                    `Scanner accessed suspicious path: ${normalizedPath}`,
                    this.weights.trapRouteHit,
                    [`scanner-pattern:${normalizedPath}`],
                    { ip, method: "GET", path, headers: {} },
                );
            }
        }

        return { clean: true, score: 0, signals: [] };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GERAÇÃO DE HTML
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Gera os campos HTML do honeypot para incluir nos formulários.
     * Os campos são invisíveis para humanos via CSS, mas visíveis para bots.
     *
     * @example
     * ```html
     * <form method="POST" action="/contato">
     *   <input name="nome" type="text" required>
     *   <input name="email" type="email" required>
     *   <!-- Campos honeypot — invisíveis para humanos -->
     *   ${await honeypot.generateFormFields()}
     *   <button type="submit">Enviar</button>
     * </form>
     * ```
     */
    async generateFormFields(formId?: string): Promise<string> {
        const now = Date.now();
        const id = formId ?? generateToken(8);
        const ts = String(now);
        const nonce = generateToken(16);

        let token = "";
        if (this.cfg.secret) {
            const payload = `${ts}:${id}:${nonce}`;
            const sig = await hmacSign(payload, this.cfg.secret);
            token = `${payload}.${sig}`;
        } else {
            token = `${ts}:${id}:${nonce}`;
        }

        const fields: string[] = [];

        // ── Campos honeypot ─────────────────────────────────────────────────────
        for (const field of this.cfg.fieldNames) {
            fields.push(
                `<div style="${HIDE_STYLE}" aria-hidden="true" tabindex="-1">` +
                `<label for="_hp_${field}" style="display:none">` +
                `Do not fill this out if you are a human</label>` +
                `<input type="text" id="_hp_${field}" name="${field}" ` +
                `value="" autocomplete="off" tabindex="-1" ` +
                `aria-hidden="true" style="${HIDE_STYLE}">` +
                `</div>`,
            );
        }

        // ── Campos lure ─────────────────────────────────────────────────────────
        for (const { name, type, label } of LURE_FIELDS) {
            fields.push(
                `<div style="${HIDE_STYLE}" aria-hidden="true">` +
                `<input type="${type}" name="${name}" ` +
                `placeholder="${label}" autocomplete="${type}" ` +
                `tabindex="-1" aria-hidden="true" style="${HIDE_STYLE}">` +
                `</div>`,
            );
        }

        // ── Timestamp ───────────────────────────────────────────────────────────
        fields.push(
            `<input type="hidden" name="${this.cfg.timestampField}" value="${ts}">`,
        );

        // ── Token ────────────────────────────────────────────────────────────────
        if (token) {
            fields.push(
                `<input type="hidden" name="${this.cfg.tokenField}" value="${token}">`,
            );
        }

        return fields.join("\n");
    }

    /**
     * Gera um link honeypot invisível para detectar crawlers.
     * Inclua no rodapé de páginas que crawlers visitam.
     *
     * @example
     * ```html
     * ${honeypot.generateCrawlerTrap("/api/internal/trap")}
     * ```
     */
    generateCrawlerTrap(trapURL: string): string {
        return (
            `<a href="${trapURL}" ` +
            `style="display:none;visibility:hidden;pointer-events:none;" ` +
            `aria-hidden="true" tabindex="-1" rel="nofollow noopener">` +
            `</a>`
        );
    }

    /**
     * Gera o CSS de ocultação para incluir no `<head>` da página.
     *
     * @example
     * ```html
     * <head>
     *   <style>${honeypot.generateCSS()}</style>
     * </head>
     * ```
     */
    generateCSS(): string {
        const selectors = [
            ...this.cfg.fieldNames.map((f) => `#_hp_${f}`),
            ...LURE_FIELDS.map(({ name }) => `#${name}`),
            '[aria-hidden="true"] input',
        ].join(",\n");

        return (
            `${selectors} {\n` +
            `  position: absolute !important;\n` +
            `  left: -9999px !important;\n` +
            `  top: -9999px !important;\n` +
            `  width: 1px !important;\n` +
            `  height: 1px !important;\n` +
            `  overflow: hidden !important;\n` +
            `  opacity: 0 !important;\n` +
            `  pointer-events: none !important;\n` +
            `}`
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UTILITÁRIOS PÚBLICOS
    // ─────────────────────────────────────────────────────────────────────────

    /** Verifica se um IP foi marcado como bot nas últimas horas. */
    async isKnownBot(ip: string): Promise<boolean> {
        return this.cfg.store?.isMarkedBot(ip) ?? false;
    }

    /**
     * Lista os nomes dos campos honeypot para filtrar ao processar o formulário.
     *
     * @example
     * ```ts
     * const honeyFields = new Set(honeypot.getHoneypotFieldNames());
     * const dadosReais  = Object.fromEntries(
     *   Object.entries(req.body).filter(([key]) => !honeyFields.has(key)),
     * );
     * ```
     */
    getHoneypotFieldNames(): string[] {
        return [
            ...this.cfg.fieldNames,
            ...LURE_FIELDS.map(({ name }) => name),
            this.cfg.timestampField,
            this.cfg.tokenField,
        ];
    }

    /**
     * Remove campos honeypot do body antes de validar ou salvar dados.
     *
     * @example
     * ```ts
     * const dadosLimpos = honeypot.stripHoneypotFields(req.body);
     * ```
     */
    stripHoneypotFields(body: Record<string, unknown>): Record<string, unknown> {
        const honeypotFields = new Set(this.getHoneypotFieldNames());
        return Object.fromEntries(
            Object.entries(body).filter(([key]) => !honeypotFields.has(key)),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PRIVADOS
    // ─────────────────────────────────────────────────────────────────────────

    private async verifyFormToken(
        body: Record<string, unknown>,
        now: number,
    ): Promise<{ status: "valid" | "missing" | "invalid" | "replayed" }> {
        const rawToken = body[this.cfg.tokenField];
        if (!rawToken || typeof rawToken !== "string") return { status: "missing" };

        const token = rawToken.trim();
        const dotIdx = token.lastIndexOf(".");
        const payload = dotIdx !== -1 ? token.slice(0, dotIdx) : token;
        const sig = dotIdx !== -1 ? token.slice(dotIdx + 1) : null;
        const parts = payload.split(":");

        if (parts.length !== 3) return { status: "invalid" };

        const ts = parseInt(parts[0] ?? "", 10);
        if (isNaN(ts)) return { status: "invalid" };

        const age = now - ts;
        if (age < 0 || age > this.cfg.maxSubmitTimeMs) return { status: "invalid" };

        if (this.cfg.secret && sig) {
            const expectedSig = await hmacSign(payload, this.cfg.secret);
            if (!timingSafeEqual(expectedSig, sig)) return { status: "invalid" };
        }

        if (this.cfg.store) {
            const isReplay = await this.cfg.store.markTokenUsed(token, this.cfg.maxSubmitTimeMs);
            if (isReplay) return { status: "replayed" };
        }

        return { status: "valid" };
    }

    private async markBot(ip: string): Promise<void> {
        if (this.cfg.store) {
            await this.cfg.store.markBot(ip, 3_600_000); // 1 hora
        }
    }

    private buildResult(
        clean: boolean,
        trigger: HoneypotTrigger,
        detail: string,
        score: number,
        signals: string[],
        req: HoneypotRequest,
    ): HoneypotResult {
        const result: HoneypotResult = {
            clean,
            triggered: clean ? undefined : trigger,
            detail: clean ? undefined : detail,
            score,
            signals,
        };

        if (!clean) {
            void this.cfg.onBotDetected?.(result, req);
            this.debugLog("BOT-DETECTED", trigger, detail, `score=${score}`);
        }

        return result;
    }

    private scoreToTrigger(signals: string[]): HoneypotTrigger {
        if (signals.some((s) => s.startsWith("field-filled"))) return "FIELD_FILLED";
        if (signals.some((s) => s.startsWith("lure-field"))) return "LURE_FIELD_FILLED";
        if (signals.some((s) => s.startsWith("token-replay"))) return "TOKEN_REPLAYED";
        if (signals.some((s) => s.startsWith("token-invalid"))) return "TOKEN_INVALID";
        if (signals.some((s) => s.startsWith("token-missing"))) return "TOKEN_MISSING";
        if (signals.some((s) => s.startsWith("timing-too-fast"))) return "TIMING_TOO_FAST";
        return "MULTIPLE_SIGNALS";
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.cfg.debug) return;
        console.debug("[honeypot]", event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ADAPTADORES DE FRAMEWORK
// ─────────────────────────────────────────────────────────────────────────────

type ExpressReq = {
    ip?: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    body?: Record<string, unknown>;
    query?: Record<string, unknown>;
};

type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    json(d: unknown): void;
    end(): void;
};

type NextFn = (err?: unknown) => void;

/**
 * Middleware Express para verificar rotas armadilha.
 * Aplique ANTES das rotas da aplicação.
 *
 * @example
 * ```ts
 * app.use(createExpressRouteTrap(honeypot));
 * ```
 */
export function createExpressRouteTrap(honeypot: HoneypotMiddleware) {
    return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
        const result = honeypot.checkRoute(req.path, req.ip ?? "0.0.0.0");
        if (!result.clean) {
            res.status(404).set({
                "Content-Type": "text/plain",
                "Cache-Control": "no-store",
            }).end();
            return;
        }
        next();
    };
}

/**
 * Middleware Express que verifica o envio de formulário.
 * Responde 200 ao bot para não revelar a detecção.
 *
 * @example
 * ```ts
 * app.post("/contato", createExpressFormCheck(hp), handler);
 * ```
 */
export function createExpressFormCheck(honeypot: HoneypotMiddleware) {
    return async (
        req: ExpressReq & { honeypotResult?: HoneypotResult },
        res: ExpressRes,
        next: NextFn,
    ): Promise<void> => {
        const result = await honeypot.checkForm({
            ip: req.ip,
            method: req.method,
            path: req.path,
            headers: req.headers,
            body: req.body,
            query: req.query,
        });

        req.honeypotResult = result;

        if (!result.clean) {
            // Responde 200 para não revelar a detecção ao bot
            res.status(200).json({
                success: true,
                message: "Obrigado! Sua mensagem foi recebida.",
            });
            return;
        }

        next();
    };
}

/**
 * Handler de rota honeypot para Next.js Edge Runtime / App Router.
 * Retorna null se a rota for legítima, Response 404 se for armadilha.
 *
 * @example
 * ```ts
 * // middleware.ts
 * export function middleware(request: NextRequest) {
 *   const trap = createNextRouteTrap(honeypot)(request);
 *   if (trap) return trap;
 *   return NextResponse.next();
 * }
 * ```
 */
export function createNextRouteTrap(honeypot: HoneypotMiddleware) {
    return (request: Request): Response | null => {
        const url = new URL(request.url);
        const ip =
            request.headers.get("cf-connecting-ip") ??
            request.headers.get("x-real-ip") ??
            "0.0.0.0";

        const result = honeypot.checkRoute(url.pathname, ip);

        if (!result.clean) {
            return new Response("Not found", {
                status: 404,
                headers: {
                    "Content-Type": "text/plain",
                    "Cache-Control": "no-store",
                },
            });
        }

        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// FACTORIES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria honeypot com configuração padrão balanceada.
 *
 * @example
 * ```ts
 * const hp = createDefaultHoneypot(process.env.HONEYPOT_SECRET!);
 * app.use(createExpressRouteTrap(hp));
 * app.post("/contato", createExpressFormCheck(hp), handler);
 * ```
 */
export function createDefaultHoneypot(
    secret?: string,
    onBotDetected?: HoneypotConfig["onBotDetected"],
): HoneypotMiddleware {
    return new HoneypotMiddleware({
        secret,
        store: new MemoryHoneypotStore(),
        trapRoutes: [
            "/admin",
            "/wp-admin",
            "/wp-login.php",
            "/.env",
            "/config.json",
            "/api/internal",
            "/actuator",
            "/phpinfo.php",
        ],
        fieldNames: ["website", "url", "company", "fax", "_hp_email"],
        minSubmitTimeMs: 3_000,
        scoreThreshold: 70,
        onBotDetected,
    });
}

/**
 * Cria honeypot reforçado para formulários de alto risco
 * (login, cadastro, pagamento).
 *
 * @example
 * ```ts
 * const hp = createStrictHoneypot(process.env.HONEYPOT_SECRET!);
 * app.post("/api/auth/register", createExpressFormCheck(hp), handler);
 * ```
 */
export function createStrictHoneypot(
    secret: string,
    onBotDetected?: HoneypotConfig["onBotDetected"],
): HoneypotMiddleware {
    return new HoneypotMiddleware({
        secret,
        store: new MemoryHoneypotStore(),
        minSubmitTimeMs: 5_000,
        scoreThreshold: 50, // Mais restritivo
        fieldNames: [
            "website", "url", "company", "fax",
            "_hp_email", "_hp_phone", "_hp_address",
            "referral", "promo_code_hidden",
        ],
        signalWeights: {
            timingTooFast: 80,
            tokenMissing: 70,
        },
        onBotDetected,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS PARA O index.ts
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aliases funcionais que o index.ts expõe como API pública.
 * Mantém consistência com a nomenclatura do módulo recaptcha.ts.
 */

export const validateHoneypot = (
    req: HoneypotRequest,
    config?: HoneypotConfig,
): Promise<HoneypotResult> => new HoneypotMiddleware(config).checkForm(req);

export const generateHoneypotField = (
    config?: HoneypotConfig,
    formId?: string,
): Promise<string> => new HoneypotMiddleware(config).generateFormFields(formId);

export const generateHoneypotToken = generateToken;

export const withHoneypot = createExpressFormCheck;

export const buildHoneypotResponse = (result: HoneypotResult): Response =>
    new Response(
        JSON.stringify({
            success: true,
            message: "Obrigado! Sua mensagem foi recebida.",
        }),
        {
            status: 200,
            headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
        },
    );