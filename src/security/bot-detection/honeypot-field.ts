/**
 * anti-bot/honeypot-field.ts
 *
 * Adapter de conveniência sobre honeypot.ts.
 *
 * ── Por que este arquivo existe ──────────────────────────────────────────
 *
 * O honeypot.ts é a implementação completa e autoritativa.
 * Ele expõe o HoneypotMiddleware com todas as estratégias de detecção,
 * mas requer instanciação e configuração.
 *
 * Este adapter oferece:
 *  1. Verificações pontuais sem instanciar HoneypotMiddleware
 *     (útil em contextos onde só um campo ou timing precisa ser checado)
 *
 *  2. Presets por tipo de formulário — sem precisar calibrar manualmente
 *     fieldNames, minSubmitTimeMs e scoreThreshold
 *
 *  3. Helpers para construção do HTML do campo no cliente
 *     (React Server Components, template engines, email builders)
 *
 * ── O que NÃO está aqui ───────────────────────────────────────────────────
 *
 * Toda a lógica real está em honeypot.ts:
 *   - HMAC signing de tokens
 *   - Replay detection via MemoryHoneypotStore
 *   - CSS e HTML generation completos
 *   - checkRoute() para rotas armadilha
 *
 * Para uso completo, use HoneypotMiddleware diretamente.
 * Este adapter é para verificações rápidas e pontuais.
 *
 * Integra-se com: honeypot.ts, bot-detection.ts
 *
 * @module security/anti-bot/honeypot-field
 */

import {
    HoneypotMiddleware,
    MemoryHoneypotStore,
    HONEYPOT_DEFAULTS,
    HoneypotFieldName,
    createDefaultHoneypot,
    createStrictHoneypot,
    type HoneypotResult,
    type HoneypotRequest,
    type HoneypotConfig,
    type HoneypotTrigger,
} from "../anti-bot/honeypot";

// ─────────────────────────────────────────────────────────────────────────────
// RE-EXPORTS — contrato público deste adapter
// ─────────────────────────────────────────────────────────────────────────────

export {
    HONEYPOT_DEFAULTS,
    HoneypotFieldName,
    createDefaultHoneypot,
    createStrictHoneypot,
};

export type {
    HoneypotResult,
    HoneypotRequest,
    HoneypotConfig,
    HoneypotTrigger,
};

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS LOCAIS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Tipo de formulário — determina o preset de configuração.
 * Cada tipo tem thresholds calibrados para o risco do contexto.
 */
export type FormType =
    | "contact"   // Formulário de contato — threshold padrão (3s)
    | "login"     // Login — threshold maior, mais campos isca
    | "register"  // Cadastro — mais restritivo
    | "checkout"  // Pagamento — máximo rigor
    | "comment"   // Comentário / review — padrão
    | "search"    // Busca — mais permissivo
    | "newsletter"// Inscrição — padrão
    | "custom";   // Configuração manual via HoneypotFieldOptions

/** Opções para verificação pontual de campo. */
export interface HoneypotFieldOptions {
    /**
     * Nome(s) do(s) campo(s) honeypot a verificar.
     * Padrão: lista completa de HONEYPOT_DEFAULTS.fieldNames
     */
    fieldNames?: string[];

    /**
     * Tempo mínimo aceitável entre renderização e submit (ms).
     * Padrão determinado pelo formType, ou HONEYPOT_DEFAULTS.minSubmitTimeMs.
     */
    minSubmitTimeMs?: number;

    /**
     * Segredo para validar o token (mesmo que foi usado ao gerar o form).
     * Se não fornecido, a verificação de token é pulada.
     */
    secret?: string;

    /**
     * Tipo de formulário — define o preset de threshold.
     * Padrão: "contact"
     */
    formType?: FormType;
}

/** Resultado de uma verificação pontual de campo. */
export interface HoneypotFieldResult {
    /** true = provavelmente humano. */
    clean: boolean;
    /** Trigger principal da detecção (undefined se clean). */
    triggered?: HoneypotTrigger;
    /** Score de risco (0–100). */
    score: number;
    /** Sinais individuais detectados. */
    signals: string[];
    /** Tempo decorrido desde o timestamp do form (ms). Se null, campo ausente. */
    elapsedMs: number | null;
    /** true se o tempo foi suspeito (abaixo do mínimo). */
    timingFast: boolean;
    /** true se algum campo honeypot foi preenchido. */
    fieldFilled: boolean;
    /** Qual campo foi preenchido (para logging interno). */
    filledFieldName?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// PRESET DE THRESHOLDS POR TIPO DE FORMULÁRIO
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Configurações pré-calibradas por tipo de formulário.
 * Baseadas em tempo médio de preenchimento humano observado.
 */
export const FORM_TYPE_PRESETS: Record<FormType, {
    minSubmitTimeMs: number;
    scoreThreshold: number;
    fieldNames: string[];
}> = {
    contact: {
        minSubmitTimeMs: 3_000,   // 3s — campo de texto livre demora mais
        scoreThreshold: 70,
        fieldNames: ["website", "url", "company", "_hp_email"],
    },
    login: {
        minSubmitTimeMs: 2_000,   // 2s — login é rápido mas não instantâneo
        scoreThreshold: 60,      // Mais restritivo — alvo de credential stuffing
        fieldNames: ["website", "_hp_email", "_hp_phone"],
    },
    register: {
        minSubmitTimeMs: 5_000,   // 5s — cadastro tem mais campos
        scoreThreshold: 55,
        fieldNames: ["website", "url", "company", "fax", "_hp_email", "_hp_phone", "_hp_address"],
    },
    checkout: {
        minSubmitTimeMs: 8_000,   // 8s — checkout tem card info, endereço, etc.
        scoreThreshold: 50,      // Máximo rigor — fraude financeira
        fieldNames: ["website", "url", "referral", "_hp_email", "promo_code_hidden"],
    },
    comment: {
        minSubmitTimeMs: 3_000,
        scoreThreshold: 70,
        fieldNames: ["website", "url", "_hp_email"],
    },
    newsletter: {
        minSubmitTimeMs: 1_500,   // 1.5s — só email, mais rápido
        scoreThreshold: 75,
        fieldNames: ["website", "_hp_name"],
    },
    search: {
        minSubmitTimeMs: 500,     // 0.5s — busca é instantânea para humanos
        scoreThreshold: 80,      // Muito permissivo — buscas rápidas são legítimas
        fieldNames: ["_hp_email"],
    },
    custom: {
        minSubmitTimeMs: HONEYPOT_DEFAULTS.minSubmitTimeMs,
        scoreThreshold: HONEYPOT_DEFAULTS.scoreThreshold,
        fieldNames: [...HONEYPOT_DEFAULTS.fieldNames],
    },
};

// ─────────────────────────────────────────────────────────────────────────────
// VERIFICAÇÕES PONTUAIS (sem instanciar HoneypotMiddleware)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se um campo honeypot foi preenchido no body da requisição.
 * Operação síncrona e sem I/O — ideal para verificação rápida no início
 * do handler antes de qualquer processamento.
 *
 * @example
 * ```ts
 * const filled = isHoneypotFilled(body);
 * if (filled.detected) {
 *   console.warn("Bot preencheu campo:", filled.fieldName);
 *   return NextResponse.json({ success: true }); // resposta falsa
 * }
 * ```
 */
export function isHoneypotFilled(
    body: Record<string, unknown>,
    fieldNames: string[] = [...HONEYPOT_DEFAULTS.fieldNames]
): { detected: boolean; fieldName?: string; value?: string } {
    for (const field of fieldNames) {
        const val = body[field];
        if (val !== undefined && val !== null && val !== "") {
            return {
                detected: true,
                fieldName: field,
                value: typeof val === "string" ? val.slice(0, 50) : String(val),
            };
        }
    }
    return { detected: false };
}

/**
 * Verifica se o formulário foi enviado rápido demais.
 * Lê o campo de timestamp do body e compara com o tempo atual.
 *
 * @example
 * ```ts
 * const timing = checkSubmitTiming(body, { formType: "login" });
 * if (timing.tooFast) {
 *   console.warn("Submit em", timing.elapsedMs, "ms");
 * }
 * ```
 */
export function checkSubmitTiming(
    body: Record<string, unknown>,
    options: {
        formType?: FormType;
        minSubmitTimeMs?: number;
        timestampField?: string;
    } = {}
): { tooFast: boolean; elapsedMs: number | null; minExpectedMs: number } {
    const formType = options.formType ?? "contact";
    const preset = FORM_TYPE_PRESETS[formType];
    const minMs: number = options.minSubmitTimeMs ?? preset.minSubmitTimeMs ?? HONEYPOT_DEFAULTS.minSubmitTimeMs;
    const tsField = options.timestampField ?? HONEYPOT_DEFAULTS.timestampField;
    const rawTs = body[tsField];

    if (rawTs === undefined || rawTs === null) {
        return { tooFast: false, elapsedMs: null, minExpectedMs: minMs };
    }

    const ts = parseInt(String(rawTs), 10);
    if (isNaN(ts)) {
        return { tooFast: true, elapsedMs: null, minExpectedMs: minMs };
    }

    const elapsed = Date.now() - ts;
    return {
        tooFast: elapsed < minMs,
        elapsedMs: elapsed,
        minExpectedMs: minMs,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFICAÇÃO COMPLETA (via HoneypotMiddleware)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executa a verificação completa de honeypot em um body de formulário.
 * Combina verificação de campo + timing + token em uma só chamada.
 * Usa HoneypotMiddleware internamente com preset do formType.
 *
 * Para uso em Route Handlers que não precisam da instância persistente.
 * Se você usa o mesmo formulário em múltiplas requisições, prefira
 * manter uma instância de HoneypotMiddleware (evita recriar o store).
 *
 * @example
 * ```ts
 * export async function POST(request: NextRequest) {
 *   const body = await request.json();
 *
 *   const check = await checkHoneypotField(body, request, {
 *     formType: "contact",
 *     secret: process.env.HONEYPOT_SECRET,
 *   });
 *
 *   if (!check.clean) {
 *     return NextResponse.json({ success: true }); // resposta falsa ao bot
 *   }
 *   // processa normalmente...
 * }
 * ```
 */
export async function checkHoneypotField(
    body: Record<string, unknown>,
    request: { headers: { get(name: string): string | null }; method: string; url: string },
    options: HoneypotFieldOptions = {}
): Promise<HoneypotFieldResult> {
    const formType = options.formType ?? "contact";
    const preset = FORM_TYPE_PRESETS[formType];

    // Verificação pontual de campo (síncrona, fast-path)
    const fieldCheck = isHoneypotFilled(
        body,
        options.fieldNames ?? preset.fieldNames ?? [...HONEYPOT_DEFAULTS.fieldNames]
    );

    const timingCheck = checkSubmitTiming(body, {
        formType,
        minSubmitTimeMs: options.minSubmitTimeMs,
    });

    // Se campo foi preenchido — certeza alta, não precisa de HoneypotMiddleware
    if (fieldCheck.detected) {
        return {
            clean: false,
            triggered: "FIELD_FILLED",
            score: 90,
            signals: [`field-filled:${fieldCheck.fieldName}:90`],
            elapsedMs: timingCheck.elapsedMs,
            timingFast: timingCheck.tooFast,
            fieldFilled: true,
            filledFieldName: fieldCheck.fieldName,
        };
    }

    // Verificação completa via HoneypotMiddleware (inclui token validation)
    const hp = new HoneypotMiddleware({
        fieldNames: options.fieldNames ?? preset.fieldNames,
        minSubmitTimeMs: options.minSubmitTimeMs ?? preset.minSubmitTimeMs,
        scoreThreshold: preset.scoreThreshold,
        secret: options.secret,
        store: new MemoryHoneypotStore(),
    });

    const url = new URL(request.url);
    const ipRaw = request.headers.get("cf-connecting-ip")
        ?? request.headers.get("x-real-ip")
        ?? request.headers.get("x-forwarded-for")
        ?? undefined;

    const hpRequest: HoneypotRequest = {
        ip: ipRaw?.split(",")[0]?.trim(),
        method: request.method,
        path: url.pathname,
        headers: { host: request.headers.get("host") ?? "" },
        body,
    };

    const result = await hp.checkForm(hpRequest);

    return {
        clean: result.clean,
        triggered: result.triggered,
        score: result.score,
        signals: result.signals,
        elapsedMs: timingCheck.elapsedMs,
        timingFast: timingCheck.tooFast,
        fieldFilled: fieldCheck.detected,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS DE GERAÇÃO DE HTML (client-side helpers)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Gera os atributos HTML de um campo honeypot individual.
 * Útil para frameworks que constroem inputs via props (React, Vue).
 *
 * @example
 * ```tsx
 * // React — campo invisível para humanos
 * <input {...getHoneypotInputProps("website")} />
 * ```
 */
export function getHoneypotInputProps(fieldName: string): {
    name: string;
    type: "text";
    value: "";
    tabIndex: -1;
    autoComplete: "off";
    "aria-hidden": true;
    style: React.CSSProperties;
} {
    return {
        name: fieldName,
        type: "text",
        value: "",
        tabIndex: -1,
        autoComplete: "off",
        "aria-hidden": true,
        style: {
            position: "absolute",
            left: "-9999px",
            top: "-9999px",
            width: "1px",
            height: "1px",
            overflow: "hidden",
            opacity: 0,
            pointerEvents: "none",
        } as React.CSSProperties,
    };
}

/**
 * Gera todos os campos honeypot como props de React.
 * Inclui timestamp atual (o valor do timestamp é fixado no render).
 *
 * @example
 * ```tsx
 * // Uso em formulário React (Server Component ou Client Component)
 * const honeypotFields = getHoneypotFormProps("contact");
 *
 * return (
 *   <form>
 *     {honeypotFields.hiddenInputs.map((props) => (
 *       <input key={props.name} {...props} />
 *     ))}
 *     <input name={honeypotFields.timestampField.name} type="hidden" value={honeypotFields.timestampField.value} />
 *     {/* campos reais */

export function getHoneypotFormProps(formType: FormType = "contact"): {
    hiddenInputs: ReturnType<typeof getHoneypotInputProps>[];
    timestampField: { name: string; type: "hidden"; value: string };
} {
    const preset = FORM_TYPE_PRESETS[formType];
    const fieldNames = preset.fieldNames ?? [...HONEYPOT_DEFAULTS.fieldNames];

    return {
        hiddenInputs: fieldNames.map((name) => getHoneypotInputProps(name)),
        timestampField: {
            name: HONEYPOT_DEFAULTS.timestampField,
            type: "hidden",
            value: String(Date.now()),
        },
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS DE SCORE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Converte HoneypotResult ou HoneypotFieldResult para score de risco (0–100).
 * Compatível com o sistema de score do bot-detection.ts.
 *
 * @example
 * ```ts
 * const check = await checkHoneypotField(body, request, { formType: "login" });
 * const risk  = honeypotRiskScore(check); // 0 (limpo) a 100 (bot certo)
 * ```
 */
export function honeypotRiskScore(
    result: HoneypotResult | HoneypotFieldResult
): number {
    if (result.clean) return 0;
    return Math.min(100, result.score);
}

/**
 * Descreve o resultado em linguagem natural para logging.
 *
 * @example
 * ```ts
 * console.warn("[HONEYPOT]", describeHoneypotResult(check));
 * // "[HONEYPOT] Bot detectado — FIELD_FILLED (score: 90) — campo: website"
 * ```
 */
export function describeHoneypotResult(
    result: HoneypotResult | HoneypotFieldResult
): string {
    if (result.clean) {
        return `Verificação limpa (score: ${result.score})`;
    }

    const trigger = result.triggered ?? "MULTIPLE_SIGNALS";
    const fieldInfo = "filledFieldName" in result && result.filledFieldName
        ? ` — campo: ${result.filledFieldName}`
        : "";
    const timingInfo = "timingFast" in result && result.timingFast
        ? ` — timing: ${result.elapsedMs ?? "?"}ms`
        : "";

    return `Bot detectado — ${trigger} (score: ${result.score})${fieldInfo}${timingInfo}`;
}

/**
 * Determina se o resultado indica bot com alta certeza
 * (sem precisar verificar o scoreThreshold completo).
 *
 * @example
 * ```ts
 * if (isDefinitelyHoneypotBot(check)) {
 *   // Pula checks subsequentes — bot confirmado
 * }
 * ```
 */
export function isDefinitelyHoneypotBot(
    result: HoneypotResult | HoneypotFieldResult
): boolean {
    if (result.clean) return false;
    // Campo preenchido ou token reusado = bot com altíssima certeza
    return (
        result.triggered === "FIELD_FILLED" ||
        result.triggered === "LURE_FIELD_FILLED" ||
        result.triggered === "TOKEN_REPLAYED" ||
        result.triggered === "TRAP_ROUTE_HIT" ||
        result.score >= 90
    );
}