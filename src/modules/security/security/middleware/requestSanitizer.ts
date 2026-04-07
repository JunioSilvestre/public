/**
 * @arquivo     src/security/middleware/requestSanitizer.ts
 * @módulo      Security / Middleware / Sanitizador de Requisições
 * @descrição   Camada de sanitização e validação de requisições HTTP para Next.js.
 *              Protege contra: XSS, SQL Injection, Path Traversal, NoSQL Injection,
 *              SSTI, Command Injection, LDAP Injection e CRLF em headers.
 *              Totalmente stateless e sem efeitos colaterais externos.
 *
 * @como-usar
 *              // Uso direto:
 *              const result = await sanitizeRequest(req, options);
 *              if (!result.ok) return NextResponse.json(result.error, { status: 400 });
 *              // Wrapper conveniente:
 *              return withSanitizedRequest(req, async (sanitized) => { ... });
 *
 * @dependências next/server (NextRequest, NextResponse)
 * @notas       Em produção nunca exponha `result.error.details` ao cliente.
 *              strictMode: true por padrão (recomendado).
 *
 * @módulo security/requestSanitizer
 */

import { NextRequest, NextResponse } from "next/server";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

export interface SanitizedRequest {
    body: Record<string, unknown> | null;
    query: Record<string, string>;
    headers: Record<string, string>;
    method: string;
    pathname: string;
}

export interface SanitizerOptions {
    /** Tamanho máximo do body em bytes (padrão: 100KB) */
    maxBodySize?: number;
    /** Profundidade máxima de objetos JSON aninhados (padrão: 5) */
    maxDepth?: number;
    /** Número máximo de chaves em um objeto (padrão: 50) */
    maxKeys?: number;
    /** Comprimento máximo de qualquer string individual (padrão: 10.000) */
    maxStringLength?: number;
    /** Lista de headers permitidos (allowlist) */
    allowedHeaders?: string[];
    /** Se deve rejeitar requisições com padrões suspeitos detectados */
    strictMode?: boolean;
}

export interface SanitizationResult {
    ok: boolean;
    data?: SanitizedRequest;
    error?: {
        code: SanitizationErrorCode;
        message: string;
        field?: string;
    };
}

export type SanitizationErrorCode =
    | "PAYLOAD_TOO_LARGE"
    | "INVALID_JSON"
    | "MAX_DEPTH_EXCEEDED"
    | "MAX_KEYS_EXCEEDED"
    | "STRING_TOO_LONG"
    | "MALICIOUS_PATTERN_DETECTED"
    | "INVALID_CONTENT_TYPE"
    | "INVALID_HEADER"
    | "INVALID_METHOD"
    | "INVALID_PATH";

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES DE SEGURANÇA
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULTS: Required<SanitizerOptions> = {
    maxBodySize: 100 * 1024, // 100 KB
    maxDepth: 5,
    maxKeys: 50,
    maxStringLength: 10_000,
    allowedHeaders: [
        "content-type",
        "authorization",
        "accept",
        "accept-language",
        "cache-control",
        "x-requested-with",
        "x-csrf-token",
        "x-api-key",
        "user-agent",
    ],
    strictMode: true,
};

/** Métodos HTTP explicitamente permitidos. */
const ALLOWED_METHODS = new Set([
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
]);

/** Content-Types aceitos para bodies com payload. */
const ALLOWED_CONTENT_TYPES = new Set([
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
]);

// ─────────────────────────────────────────────────────────────────────────────
// PADRÕES DE DETECÇÃO DE AMEAÇAS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Padrões que indicam tentativas de injeção.
 * Cada entrada possui um nome descritivo para logging e auditoria.
 */
const THREAT_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    // XSS — Cross-Site Scripting
    {
        name: "XSS_SCRIPT_TAG",
        pattern: /<\s*script[\s\S]*?>[\s\S]*?<\s*\/\s*script\s*>/gi,
    },
    {
        name: "XSS_EVENT_HANDLER",
        pattern: /\bon\w+\s*=\s*["']?[^"'>]*/gi,
    },
    {
        name: "XSS_JAVASCRIPT_PROTO",
        pattern: /javascript\s*:/gi,
    },
    {
        name: "XSS_DATA_URI",
        pattern: /data\s*:\s*text\s*\/\s*html/gi,
    },
    {
        name: "XSS_VBSCRIPT",
        pattern: /vbscript\s*:/gi,
    },

    // SQL Injection
    {
        name: "SQLI_UNION",
        pattern: /(\bUNION\b[\s\S]*?\bSELECT\b|\bSELECT\b[\s\S]*?\bFROM\b)/gi,
    },
    {
        name: "SQLI_DROP",
        pattern: /\bDROP\s+TABLE\b/gi,
    },
    {
        name: "SQLI_COMMENT",
        pattern: /(--|#|\/\*)[\s\S]*?(;|$)/,
    },
    {
        name: "SQLI_OR_TRUE",
        pattern: /\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/gi,
    },
    {
        name: "SQLI_EXEC",
        pattern: /\bEXEC\s*\(/gi,
    },

    // Path Traversal
    {
        name: "PATH_TRAVERSAL",
        pattern: /(\.\.[/\\]){2,}/,
    },
    {
        name: "PATH_NULL_BYTE",
        pattern: /\x00/,
    },

    // NoSQL Injection (MongoDB operators)
    {
        name: "NOSQL_OPERATOR",
        pattern: /\$\s*(where|gt|lt|ne|in|nin|exists|regex|expr|function)\b/gi,
    },

    // Server-Side Template Injection
    {
        name: "SSTI_DELIMITERS",
        pattern: /(\{\{[\s\S]*?\}\}|<%[\s\S]*?%>|\$\{[\s\S]*?\})/,
    },

    // Command Injection
    {
        name: "CMD_INJECTION",
        pattern: /[`|;&$]|(\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby)\b)/gi,
    },

    // LDAP Injection
    {
        name: "LDAP_INJECTION",
        pattern: /[)(\\*\x00]/,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// FUNÇÕES DE SANITIZAÇÃO PRIMITIVAS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapa entidades HTML para prevenção de XSS em contextos de output.
 * Nota: use em conjunto com a sanitização de input — nunca como substituto.
 */
export function escapeHtml(raw: string): string {
    return raw
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;")
        .replace(/\//g, "&#x2F;");
}

/**
 * Remove caracteres de controle Unicode e bytes nulos que podem
 * ser usados para contornar filtros ou confundir parsers.
 */
export function stripControlCharacters(input: string): string {
    // Mantém: tab (0x09), newline (0x0A), carriage return (0x0D)
    // Remove: todos os outros caracteres de controle (0x00–0x08, 0x0B–0x0C, 0x0E–0x1F, 0x7F)
    // eslint-disable-next-line no-control-regex
    return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

/**
 * Normaliza espaços em branco excessivos e remove caracteres invisíveis
 * frequentemente usados em ataques de homoglyph/invisíveis.
 */
export function normalizeWhitespace(input: string): string {
    return input
        .replace(/\u00A0/g, " ") // Non-breaking space
        .replace(/\u200B/g, "") // Zero-width space
        .replace(/\u200C/g, "") // Zero-width non-joiner
        .replace(/\u200D/g, "") // Zero-width joiner
        .replace(/\uFEFF/g, "") // BOM
        .replace(/\s{2,}/g, " ")
        .trim();
}

/**
 * Sanitiza uma string individual aplicando todas as camadas de proteção.
 * Retorna null se a string contiver padrão de ameaça em modo estrito.
 */
export function sanitizeString(
    input: unknown,
    opts: { maxLength?: number; strictMode?: boolean } = {}
): string | null {
    if (typeof input !== "string") return null;

    const maxLength = opts.maxLength ?? DEFAULTS.maxStringLength;
    const strict = opts.strictMode ?? DEFAULTS.strictMode;

    // 1. Trunca antes de processar para evitar ReDoS com strings enormes
    let value = input.slice(0, maxLength * 2);

    // 2. Remove controles e normaliza
    value = stripControlCharacters(value);
    value = normalizeWhitespace(value);

    // 3. Verifica tamanho após normalização
    if (value.length > maxLength) {
        return null;
    }

    // 4. Detecção de ameaças (apenas em modo estrito)
    if (strict) {
        for (const { pattern } of THREAT_PATTERNS) {
            // Reset do lastIndex para padrões com flag 'g'
            pattern.lastIndex = 0;
            if (pattern.test(value)) {
                return null; // Retorna null — o chamador decide como tratar
            }
        }
    }

    return value;
}

/**
 * Identifica qual padrão de ameaça foi detectado em uma string.
 * Útil para logging e auditoria detalhada.
 */
export function detectThreatPattern(
    input: string
): { name: string; pattern: RegExp } | null {
    for (const threat of THREAT_PATTERNS) {
        threat.pattern.lastIndex = 0;
        if (threat.pattern.test(input)) {
            return threat;
        }
    }
    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDAÇÃO RECURSIVA DE OBJETOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Percorre recursivamente um objeto/array e sanitiza todas as strings.
 * Lança erro se profundidade ou quantidade de chaves for excedida.
 */
function sanitizeObject(
    value: unknown,
    opts: Required<SanitizerOptions>,
    depth = 0,
    path = "root"
): { sanitized: unknown; violations: string[] } {
    const violations: string[] = [];

    if (depth > opts.maxDepth) {
        return {
            sanitized: null,
            violations: [`MAX_DEPTH_EXCEEDED at ${path}`],
        };
    }

    // Primitivos
    if (value === null || value === undefined) {
        return { sanitized: value, violations: [] };
    }

    if (typeof value === "boolean" || typeof value === "number") {
        // Garante que numbers são finitos e não NaN
        if (typeof value === "number" && !Number.isFinite(value)) {
            return { sanitized: null, violations: [`INVALID_NUMBER at ${path}`] };
        }
        return { sanitized: value, violations: [] };
    }

    if (typeof value === "string") {
        const sanitized = sanitizeString(value, {
            maxLength: opts.maxStringLength,
            strictMode: opts.strictMode,
        });
        if (sanitized === null) {
            const threat = detectThreatPattern(value);
            return {
                sanitized: null,
                violations: [
                    `MALICIOUS_PATTERN_DETECTED at ${path}${threat ? ` [${threat.name}]` : ""}`,
                ],
            };
        }
        return { sanitized, violations: [] };
    }

    if (Array.isArray(value)) {
        const sanitizedArray: unknown[] = [];
        for (let i = 0; i < value.length; i++) {
            const result = sanitizeObject(value[i], opts, depth + 1, `${path}[${i}]`);
            violations.push(...result.violations);
            sanitizedArray.push(result.sanitized);
        }
        return { sanitized: sanitizedArray, violations };
    }

    if (typeof value === "object") {
        const keys = Object.keys(value as object);
        if (keys.length > opts.maxKeys) {
            return {
                sanitized: null,
                violations: [
                    `MAX_KEYS_EXCEEDED at ${path} (${keys.length}/${opts.maxKeys})`,
                ],
            };
        }

        const sanitizedObj: Record<string, unknown> = {};
        for (const key of keys) {
            // Sanitiza a chave também — chaves maliciosas podem ser exploradas
            const sanitizedKey = sanitizeString(key, {
                maxLength: 256,
                strictMode: opts.strictMode,
            });
            if (sanitizedKey === null) {
                violations.push(`MALICIOUS_KEY at ${path}.${key}`);
                continue;
            }

            const result = sanitizeObject(
                (value as Record<string, unknown>)[key],
                opts,
                depth + 1,
                `${path}.${key}`
            );
            violations.push(...result.violations);
            sanitizedObj[sanitizedKey] = result.sanitized;
        }
        return { sanitized: sanitizedObj, violations };
    }

    // Tipo desconhecido — descarta com segurança
    return {
        sanitized: null,
        violations: [`UNKNOWN_TYPE at ${path}: ${typeof value}`],
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// SANITIZAÇÃO DE QUERY PARAMS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitiza todos os parâmetros de query string.
 * Retorna objeto limpo ou erro se houver violação.
 */
function sanitizeQueryParams(
    searchParams: URLSearchParams,
    opts: Required<SanitizerOptions>
): { query: Record<string, string>; violations: string[] } {
    const query: Record<string, string> = {};
    const violations: string[] = [];

    // Array.from() evita dependência de --downlevelIteration ou target ES2015+
    Array.from(searchParams.entries()).forEach(([key, value]) => {
        const sanitizedKey = sanitizeString(key, {
            maxLength: 256,
            strictMode: opts.strictMode,
        });
        const sanitizedValue = sanitizeString(value, {
            maxLength: opts.maxStringLength,
            strictMode: opts.strictMode,
        });

        if (sanitizedKey === null) {
            violations.push(`MALICIOUS_QUERY_KEY: ${key}`);
            return; // continue equivalente dentro do forEach
        }
        if (sanitizedValue === null) {
            violations.push(`MALICIOUS_QUERY_VALUE for key: ${key}`);
            return;
        }

        query[sanitizedKey] = sanitizedValue;
    });

    return { query, violations };
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDAÇÃO DE HEADERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Filtra e valida headers da requisição.
 * Mantém apenas headers da allowlist e verifica valores.
 */
function sanitizeHeaders(
    headers: Headers,
    allowedHeaders: string[]
): { sanitized: Record<string, string>; violations: string[] } {
    const sanitized: Record<string, string> = {};
    const violations: string[] = [];
    const allowedSet = new Set(allowedHeaders.map((h) => h.toLowerCase()));

    headers.forEach((value, key) => {
        const lowerKey = key.toLowerCase();

        if (!allowedSet.has(lowerKey)) {
            // Header não permitido — silenciosamente descartado (não é violação de segurança)
            return;
        }

        // Verifica Header Injection (CRLF Injection)
        if (/[\r\n]/.test(value)) {
            violations.push(`HEADER_INJECTION_ATTEMPT: ${lowerKey}`);
            return;
        }

        // Limita comprimento de valores de header
        if (value.length > 8192) {
            violations.push(`HEADER_VALUE_TOO_LONG: ${lowerKey}`);
            return;
        }

        sanitized[lowerKey] = value;
    });

    return { sanitized, violations };
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDAÇÃO DE PATH
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Valida e normaliza o pathname da URL.
 * Bloqueia path traversal e segmentos maliciosos.
 */
function validatePathname(pathname: string): {
    normalized: string | null;
    violation?: string;
} {
    // Path traversal
    if (/(\.\.[/\\]){1,}/.test(pathname)) {
        return { normalized: null, violation: "PATH_TRAVERSAL_DETECTED" };
    }

    // Bytes nulos
    if (/\x00/.test(pathname)) {
        return { normalized: null, violation: "NULL_BYTE_IN_PATH" };
    }

    // Comprimento máximo de URL
    if (pathname.length > 2048) {
        return { normalized: null, violation: "PATH_TOO_LONG" };
    }

    // Normaliza barras duplas
    const normalized = pathname.replace(/\/+/g, "/");

    return { normalized };
}

// ─────────────────────────────────────────────────────────────────────────────
// SANITIZADOR PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitiza e valida uma NextRequest completa.
 *
 * @example
 * ```ts
 * // Em um Route Handler (app/api/example/route.ts):
 * import { sanitizeRequest } from "@/lib/security/requestSanitizer";
 *
 * export async function POST(req: NextRequest) {
 *   const result = await sanitizeRequest(req);
 *   if (!result.ok) {
 *     return NextResponse.json({ error: result.error }, { status: 400 });
 *   }
 *   const { body, query } = result.data!;
 *   // ...
 * }
 * ```
 */
export async function sanitizeRequest(
    request: NextRequest,
    options: SanitizerOptions = {}
): Promise<SanitizationResult> {
    const opts: Required<SanitizerOptions> = { ...DEFAULTS, ...options };
    const allViolations: string[] = [];

    // ── 1. Valida método HTTP ──────────────────────────────────────────────────
    const method = request.method.toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
        return {
            ok: false,
            error: {
                code: "INVALID_METHOD",
                message: `HTTP method not allowed: ${method}`,
            },
        };
    }

    // ── 2. Valida pathname ─────────────────────────────────────────────────────
    const url = new URL(request.url);
    const pathResult = validatePathname(url.pathname);
    if (!pathResult.normalized) {
        return {
            ok: false,
            error: {
                code: "INVALID_PATH",
                message: pathResult.violation ?? "Invalid path",
            },
        };
    }

    // ── 3. Sanitiza headers ────────────────────────────────────────────────────
    const { sanitized: sanitizedHeaders, violations: headerViolations } =
        sanitizeHeaders(request.headers, opts.allowedHeaders);

    if (headerViolations.length > 0 && opts.strictMode) {
        return {
            ok: false,
            error: {
                code: "INVALID_HEADER",
                message: headerViolations[0],
            },
        };
    }
    allViolations.push(...headerViolations);

    // ── 4. Sanitiza query params ───────────────────────────────────────────────
    const { query, violations: queryViolations } = sanitizeQueryParams(
        url.searchParams,
        opts
    );

    if (queryViolations.length > 0 && opts.strictMode) {
        return {
            ok: false,
            error: {
                code: "MALICIOUS_PATTERN_DETECTED",
                message: queryViolations[0],
                field: "query",
            },
        };
    }
    allViolations.push(...queryViolations);

    // ── 5. Processa e sanitiza o body ──────────────────────────────────────────
    let sanitizedBody: Record<string, unknown> | null = null;

    const hasBody = ["POST", "PUT", "PATCH"].includes(method);
    if (hasBody) {
        const contentType = sanitizedHeaders["content-type"] ?? "";
        const baseContentType = contentType.split(";")[0].trim().toLowerCase();

        if (contentType && !ALLOWED_CONTENT_TYPES.has(baseContentType)) {
            return {
                ok: false,
                error: {
                    code: "INVALID_CONTENT_TYPE",
                    message: `Content-Type not allowed: ${baseContentType}`,
                },
            };
        }

        // Verifica Content-Length antes de ler (fast-fail)
        const contentLength = parseInt(
            request.headers.get("content-length") ?? "0",
            10
        );
        if (contentLength > opts.maxBodySize) {
            return {
                ok: false,
                error: {
                    code: "PAYLOAD_TOO_LARGE",
                    message: `Body size ${contentLength} exceeds maximum of ${opts.maxBodySize} bytes`,
                },
            };
        }

        // Lê o body com limite de tamanho real
        let rawBody: string;
        try {
            const buffer = await request.arrayBuffer();
            if (buffer.byteLength > opts.maxBodySize) {
                return {
                    ok: false,
                    error: {
                        code: "PAYLOAD_TOO_LARGE",
                        message: `Body size ${buffer.byteLength} exceeds maximum of ${opts.maxBodySize} bytes`,
                    },
                };
            }
            rawBody = new TextDecoder("utf-8").decode(buffer);
        } catch {
            return {
                ok: false,
                error: { code: "INVALID_JSON", message: "Failed to read request body" },
            };
        }

        if (rawBody.trim()) {
            if (baseContentType === "application/json") {
                let parsed: unknown;
                try {
                    parsed = JSON.parse(rawBody);
                } catch {
                    return {
                        ok: false,
                        error: { code: "INVALID_JSON", message: "Request body is not valid JSON" },
                    };
                }

                const { sanitized, violations: bodyViolations } = sanitizeObject(
                    parsed,
                    opts
                );

                if (bodyViolations.length > 0 && opts.strictMode) {
                    return {
                        ok: false,
                        error: {
                            code: "MALICIOUS_PATTERN_DETECTED",
                            message: bodyViolations[0],
                            field: "body",
                        },
                    };
                }

                if (
                    bodyViolations.some((v) => v.startsWith("MAX_DEPTH_EXCEEDED"))
                ) {
                    return {
                        ok: false,
                        error: {
                            code: "MAX_DEPTH_EXCEEDED",
                            message: `JSON nesting exceeds maximum depth of ${opts.maxDepth}`,
                        },
                    };
                }

                if (bodyViolations.some((v) => v.startsWith("MAX_KEYS_EXCEEDED"))) {
                    return {
                        ok: false,
                        error: {
                            code: "MAX_KEYS_EXCEEDED",
                            message: `JSON object exceeds maximum key count of ${opts.maxKeys}`,
                        },
                    };
                }

                allViolations.push(...bodyViolations);
                sanitizedBody = sanitized as Record<string, unknown>;
            } else if (
                baseContentType === "application/x-www-form-urlencoded"
            ) {
                const formParams = new URLSearchParams(rawBody);
                const { query: formData, violations: formViolations } =
                    sanitizeQueryParams(formParams, opts);

                if (formViolations.length > 0 && opts.strictMode) {
                    return {
                        ok: false,
                        error: {
                            code: "MALICIOUS_PATTERN_DETECTED",
                            message: formViolations[0],
                            field: "body",
                        },
                    };
                }

                allViolations.push(...formViolations);
                sanitizedBody = formData;
            }
            // multipart/form-data e text/plain são tratados em módulo separado
        }
    }

    // ── 6. Resultado final ─────────────────────────────────────────────────────
    return {
        ok: true,
        data: {
            body: sanitizedBody,
            query,
            headers: sanitizedHeaders,
            method,
            pathname: pathResult.normalized,
        },
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE HELPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrapper para uso direto em Route Handlers do Next.js App Router.
 * Retorna NextResponse de erro automaticamente se a sanitização falhar.
 *
 * @example
 * ```ts
 * export async function POST(req: NextRequest) {
 *   return withSanitizedRequest(req, async (sanitized) => {
 *     const { body } = sanitized;
 *     // lógica do handler...
 *     return NextResponse.json({ ok: true });
 *   });
 * }
 * ```
 */
export async function withSanitizedRequest(
    request: NextRequest,
    handler: (sanitized: SanitizedRequest) => Promise<NextResponse>,
    options?: SanitizerOptions
): Promise<NextResponse> {
    const result = await sanitizeRequest(request, options);

    if (!result.ok) {
        // Não expõe detalhes internos em produção
        const isDev = process.env.NODE_ENV === "development";
        return NextResponse.json(
            {
                error: "Bad Request",
                ...(isDev && { details: result.error }),
            },
            {
                status: 400,
                headers: {
                    "Content-Type": "application/json",
                    // Previne sniffing e clickjacking mesmo em respostas de erro
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            }
        );
    }

    return handler(result.data!);
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS EXPORTADOS
// ─────────────────────────────────────────────────────────────────────────────

export {
    THREAT_PATTERNS,
    ALLOWED_METHODS,
    ALLOWED_CONTENT_TYPES,
    DEFAULTS as SANITIZER_DEFAULTS,
};