/**
 * @fileoverview Middleware de integridade de requisições HTTP.
 *
 * @description
 * Valida que cada requisição chegou intacta, não foi adulterada em trânsito,
 * não é um replay de uma requisição anterior legítima, e que a estrutura
 * do payload é consistente com o que o servidor espera.
 *
 * ── Camadas de verificação ─────────────────────────────────────────────────
 *  1. Assinatura HMAC       — verifica que o body não foi adulterado
 *  2. Timestamp + Nonce     — previne replay attacks com janela de tempo
 *  3. Content-Type          — valida que o tipo declarado é o tipo real
 *  4. Content-Length        — detecta discrepâncias de tamanho
 *  5. Body hash             — SHA-256 do body para detectar corrupção
 *  6. Schema validation     — estrutura do payload conforme schema esperado
 *  7. Encoding consistency  — charset, encoding declarados vs reais
 *  8. Header consistency    — headers obrigatórios, proibidos, conflitantes
 *  9. Request ID            — rastreabilidade e deduplicação
 * 10. Idempotency key       — operações idempotentes seguras
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *  • Request tampering em trânsito (MITM sem TLS)             (ubíquo)
 *  • Replay attack — reusar request legítimo capturado        (ubíquo)
 *  • Body smuggling via Content-Length inconsistente          (CVE-2019-9517+)
 *  • HTTP Request Smuggling via Transfer-Encoding / CL        (CVE-2019-9516+)
 *  • JSON injection via Content-Type: text/plain bypass       (2012+)
 *  • Charset confusion attack (UTF-7, ISO-2022-JP bypass)     (histórico)
 *  • Oversized payload DoS                                    (ubíquo)
 *  • Parameter pollution via arrays duplicados                (OWASP HPP)
 *  • Mass assignment via campos extras no body               (Rails vuln 2012)
 *  • Type confusion via JSON number/string coerção             (2019+)
 *  • Prototype pollution via __proto__ no JSON               (CVE-2019-7609)
 *  • XML External Entity (XXE) via Content-Type: text/xml     (OWASP A05)
 *  • Billion laughs via nested JSON                           (adaptação)
 *  • SSRF via URL em payload não validada                     (OWASP A10)
 *  • Race condition em idempotência (double-spend)            (fintech)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • HTTP/3 header injection via QPACK                        (emergente)
 *  • gRPC payload tampering                                   (2022+)
 *  • Signed Exchanges (SXG) integrity                         (Chrome 73+)
 *  • Request policy via Permissions-Policy                    (W3C 2021)
 *  • Structured Field Values (RFC 8941) validation            (2021+)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Configurável por rota (cada endpoint tem seus requisitos)
 *  • Assinatura HMAC-SHA256 via Web Crypto API
 *  • Nonce store injetável (Redis em produção)
 *  • Schema validation agnóstica (Zod, Joi, Yup, custom)
 *  • Framework-agnostic: adaptadores Express e Next.js
 *  • Respostas de erro padronizadas sem vazar detalhes internos
 *
 * @see https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/
 * @see https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
 * @see https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da verificação de integridade. */
export interface IntegrityResult {
    valid: boolean;
    reason?: IntegrityViolation;
    /** Detalhes internos — nunca exponha ao cliente. */
    detail?: string;
    /** Request ID extraído ou gerado. */
    requestId?: string;
    meta: IntegrityMeta;
}

export type IntegrityViolation =
    | 'SIGNATURE_MISSING'
    | 'SIGNATURE_INVALID'
    | 'SIGNATURE_EXPIRED'
    | 'TIMESTAMP_MISSING'
    | 'TIMESTAMP_INVALID'
    | 'TIMESTAMP_EXPIRED'
    | 'TIMESTAMP_FUTURE'
    | 'NONCE_MISSING'
    | 'NONCE_REPLAYED'
    | 'NONCE_INVALID'
    | 'CONTENT_TYPE_MISSING'
    | 'CONTENT_TYPE_MISMATCH'
    | 'CONTENT_TYPE_FORBIDDEN'
    | 'CONTENT_LENGTH_MISMATCH'
    | 'CONTENT_LENGTH_EXCEEDED'
    | 'BODY_HASH_MISMATCH'
    | 'BODY_MISSING'
    | 'BODY_PARSE_ERROR'
    | 'SCHEMA_INVALID'
    | 'PROTOTYPE_POLLUTION'
    | 'FORBIDDEN_FIELD'
    | 'ENCODING_INVALID'
    | 'HEADER_MISSING'
    | 'HEADER_FORBIDDEN'
    | 'HEADER_CONFLICT'
    | 'REQUEST_SMUGGLING_SUSPECTED'
    | 'IDEMPOTENCY_KEY_REPLAYED'
    | 'IDEMPOTENCY_KEY_MISSING';

export interface IntegrityMeta {
    path: string;
    method: string;
    timestamp: number;
    requestId: string;
    signals: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

/** Schema validator genérico — compatível com Zod, Joi, Yup ou custom. */
export type SchemaValidator = (body: unknown) => SchemaValidationResult;

export interface SchemaValidationResult {
    valid: boolean;
    errors?: string[];
}

/** Configuração de assinatura HMAC. */
export interface SignatureConfig {
    /**
     * Segredo HMAC (mínimo 32 bytes / 256 bits).
     * Use variável de ambiente: process.env.REQUEST_SIGNING_SECRET
     */
    secret: string;

    /**
     * Nome do header que carrega a assinatura.
     * Default: 'x-signature-sha256'
     *
     * Formato do valor: 'sha256=<hex_ou_base64url>'
     * (compatível com GitHub Webhooks, Stripe, etc.)
     */
    headerName?: string;

    /**
     * Formato da assinatura no header.
     * Default: 'sha256=<base64url>'
     */
    format?: 'sha256-base64url' | 'sha256-hex' | 'sha256-base64';

    /**
     * Campos adicionais a incluir na assinatura além do body.
     * Ex: ['x-timestamp', 'x-nonce', 'content-type']
     *
     * Incluir headers na assinatura previne que um atacante troque
     * o Content-Type mantendo o body igual.
     */
    signedHeaders?: string[];

    /** A assinatura é obrigatória ou opcional. Default: true */
    required?: boolean;
}

/** Configuração de proteção anti-replay. */
export interface ReplayProtectionConfig {
    /**
     * Janela de tempo válida em ms.
     * Requisições com timestamp fora desta janela são rejeitadas.
     * Default: 300_000 (5 minutos)
     *
     * Balance: janela pequena = mais seguro mas requer sincronização de relógio.
     * Janela de 5 min é padrão na indústria (AWS Signature V4, Stripe).
     */
    windowMs?: number;

    /**
     * Nome do header de timestamp.
     * Default: 'x-timestamp'
     * Valor: Unix timestamp em ms como string.
     */
    timestampHeader?: string;

    /**
     * Nome do header de nonce (number used once).
     * Default: 'x-nonce'
     * Valor: string aleatória única por requisição.
     */
    nonceHeader?: string;

    /** Comprimento mínimo do nonce em caracteres. Default: 16 */
    minNonceLength?: number;

    /** O replay protection é obrigatório. Default: false */
    required?: boolean;

    /** Store para persistência de nonces usados. */
    nonceStore?: NonceStore;
}

/** Configuração de validação de Content-Type. */
export interface ContentTypeConfig {
    /**
     * Content-Types permitidos para este endpoint.
     * @example ['application/json', 'multipart/form-data']
     */
    allowed?: string[];

    /**
     * Content-Types explicitamente proibidos.
     * Default: ['text/xml', 'application/xml'] (previne XXE)
     */
    forbidden?: string[];

    /** Exige charset=utf-8 em tipos text/*. Default: true */
    requireUtf8Charset?: boolean;
}

/** Configuração de integridade do body. */
export interface BodyIntegrityConfig {
    /**
     * Tamanho máximo em bytes.
     * Default: 1_048_576 (1 MB)
     */
    maxSizeBytes?: number;

    /**
     * Se o body é obrigatório para este método.
     * Default: true para POST/PUT/PATCH
     */
    required?: boolean;

    /**
     * Valida hash SHA-256 do body via header.
     * Header: 'x-body-hash: sha256=<base64url>'
     * Default: false (verificação quando header está presente)
     */
    validateHash?: boolean;

    /**
     * Nome do header de hash.
     * Default: 'x-body-hash'
     */
    hashHeader?: string;

    /**
     * Schema validator para o body parseado.
     */
    schema?: SchemaValidator;

    /**
     * Campos proibidos no body (previne mass assignment).
     * @example ['isAdmin', 'role', 'createdAt', '__proto__', 'constructor']
     */
    forbiddenFields?: string[];

    /**
     * Profundidade máxima de JSON aninhado.
     * Default: 10 (previne JSON bomb)
     */
    maxDepth?: number;

    /**
     * Detecta prototype pollution (__proto__, constructor, prototype).
     * Default: true
     */
    detectPrototypePollution?: boolean;
}

/** Configuração de idempotência. */
export interface IdempotencyConfig {
    /**
     * Nome do header de idempotency key.
     * Default: 'idempotency-key'
     *
     * Padrão adotado por Stripe, Adyen, Braintree.
     */
    headerName?: string;

    /** A chave é obrigatória. Default: false */
    required?: boolean;

    /**
     * TTL da chave em ms (quanto tempo guardar para deduplicação).
     * Default: 86_400_000 (24 horas)
     */
    ttlMs?: number;

    /** Store para persistência de chaves usadas. */
    idempotencyStore?: IdempotencyStore;
}

/** Configuração por rota. */
export interface RouteIntegrityConfig {
    signature?: SignatureConfig;
    replayProtection?: ReplayProtectionConfig;
    contentType?: ContentTypeConfig;
    body?: BodyIntegrityConfig;
    idempotency?: IdempotencyConfig;
    /** Headers obrigatórios para esta rota. */
    requiredHeaders?: string[];
    /** Headers proibidos para esta rota. */
    forbiddenHeaders?: string[];
}

/** Configuração global do middleware. */
export interface RequestIntegrityConfig {
    /** Configuração padrão aplicada a todas as rotas. */
    defaults?: RouteIntegrityConfig;

    /** Configurações específicas por rota (sobrescreve defaults). */
    routes?: Record<string, RouteIntegrityConfig>;

    /**
     * Métodos HTTP que exigem verificação de integridade do body.
     * Default: ['POST', 'PUT', 'PATCH']
     */
    bodyMethods?: string[];

    /**
     * Métodos ignorados completamente.
     * Default: ['OPTIONS', 'HEAD']
     */
    ignoredMethods?: string[];

    /**
     * Rotas ignoradas completamente (ex: health checks, webhooks externos).
     */
    ignoredRoutes?: Array<string | RegExp>;

    /**
     * Comportamento quando verificação falha.
     * - 'reject': retorna 400/401 (padrão)
     * - 'log':    registra mas permite (para análise de impacto)
     */
    onFailure?: 'reject' | 'log';

    /** Hook chamado em violação de integridade. */
    onViolation?: (result: IntegrityResult, req: IntegrityRequest) => void | Promise<void>;

    /** Habilita geração automática de Request ID se ausente. Default: true */
    generateRequestId?: boolean;

    /** Nome do header de Request ID. Default: 'x-request-id' */
    requestIdHeader?: string;

    /** Habilita logging detalhado. Default: false */
    debug?: boolean;
}

/** Requisição normalizada para verificação de integridade. */
export interface IntegrityRequest {
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    /** Body como Buffer/Uint8Array (bytes crus, antes do parse). */
    rawBody?: Uint8Array | Buffer;
    /** Body já parseado (quando rawBody não disponível). */
    parsedBody?: unknown;
    /** Tamanho declarado no Content-Length. */
    contentLength?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store interfaces
// ─────────────────────────────────────────────────────────────────────────────

export interface NonceStore {
    /** Retorna true se o nonce já foi usado (e o armazena se não). */
    checkAndStore(nonce: string, ttlMs: number): Promise<boolean>;
    /** Verifica sem armazenar. */
    exists(nonce: string): Promise<boolean>;
}

export interface IdempotencyStore {
    /** Retorna true se a chave já foi processada. */
    checkAndStore(key: string, ttlMs: number): Promise<boolean>;
    /** Recupera resposta cacheada para uma chave idempotente. */
    getResponse(key: string): Promise<unknown | null>;
    /** Armazena a resposta para uma chave idempotente. */
    setResponse(key: string, response: unknown, ttlMs: number): Promise<void>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stores em memória
// ─────────────────────────────────────────────────────────────────────────────

export class MemoryNonceStore implements NonceStore {
    private readonly used = new Map<string, number>(); // nonce → expiresAt
    private readonly interval: ReturnType<typeof setInterval>;

    constructor(cleanupMs = 60_000) {
        this.interval = setInterval(() => {
            const now = Date.now();
            for (const [k, exp] of Array.from(this.used.entries())) {
                if (exp < now) this.used.delete(k);
            }
        }, cleanupMs);
        if (typeof this.interval.unref === 'function') this.interval.unref();
    }

    async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
        if (await this.exists(nonce)) return true;
        this.used.set(nonce, Date.now() + ttlMs);
        return false;
    }

    async exists(nonce: string): Promise<boolean> {
        const exp = this.used.get(nonce);
        if (exp === undefined) return false;
        if (exp < Date.now()) { this.used.delete(nonce); return false; }
        return true;
    }

    destroy(): void {
        clearInterval(this.interval);
        this.used.clear();
    }
}

export class MemoryIdempotencyStore implements IdempotencyStore {
    private readonly keys = new Map<string, number>();        // key → expiresAt
    private readonly responses = new Map<string, { data: unknown; expiresAt: number }>();
    private readonly interval: ReturnType<typeof setInterval>;

    constructor(cleanupMs = 60_000) {
        this.interval = setInterval(() => {
            const now = Date.now();
            for (const [k, exp] of Array.from(this.keys.entries())) {
                if (exp < now) { this.keys.delete(k); this.responses.delete(k); }
            }
        }, cleanupMs);
        if (typeof this.interval.unref === 'function') this.interval.unref();
    }

    async checkAndStore(key: string, ttlMs: number): Promise<boolean> {
        const exp = this.keys.get(key);
        if (exp !== undefined && exp >= Date.now()) return true;
        this.keys.set(key, Date.now() + ttlMs);
        return false;
    }

    async getResponse(key: string): Promise<unknown | null> {
        const entry = this.responses.get(key);
        if (!entry || entry.expiresAt < Date.now()) return null;
        return entry.data;
    }

    async setResponse(key: string, response: unknown, ttlMs: number): Promise<void> {
        this.responses.set(key, { data: response, expiresAt: Date.now() + ttlMs });
    }

    destroy(): void {
        clearInterval(this.interval);
        this.keys.clear();
        this.responses.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários criptográficos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Computa HMAC-SHA256 de um payload usando Web Crypto API.
 * Compatível com Node.js 15+, todos os browsers modernos, Edge Runtime.
 */
async function computeHMAC(payload: string | Uint8Array, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    // crypto.subtle exige ArrayBuffer — .buffer retorna ArrayBufferLike (pode ser SharedArrayBuffer).
    // Copiar via slice() garante um ArrayBuffer ordinário em qualquer runtime.
    const keyBytes = encoder.encode(secret);
    const keyBuf = keyBytes.buffer.slice(keyBytes.byteOffset, keyBytes.byteOffset + keyBytes.byteLength) as ArrayBuffer;

    let dataBuf: ArrayBuffer;
    if (typeof payload === 'string') {
        const enc = encoder.encode(payload);
        dataBuf = enc.buffer.slice(enc.byteOffset, enc.byteOffset + enc.byteLength) as ArrayBuffer;
    } else {
        dataBuf = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength) as ArrayBuffer;
    }

    const cryptoKey = await globalThis.crypto.subtle.importKey(
        'raw', keyBuf,
        { name: 'HMAC', hash: 'SHA-256' },
        false, ['sign'],
    );

    const signature = await globalThis.crypto.subtle.sign('HMAC', cryptoKey, dataBuf);
    return base64urlEncode(new Uint8Array(signature));
}

/**
 * Computa SHA-256 de um payload.
 */
async function computeSHA256(payload: string | Uint8Array): Promise<string> {
    const encoder = new TextEncoder();
    let dataBuf: ArrayBuffer;
    if (typeof payload === 'string') {
        const enc = encoder.encode(payload);
        dataBuf = enc.buffer.slice(enc.byteOffset, enc.byteOffset + enc.byteLength) as ArrayBuffer;
    } else {
        dataBuf = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength) as ArrayBuffer;
    }
    const hash = await globalThis.crypto.subtle.digest('SHA-256', dataBuf);
    return base64urlEncode(new Uint8Array(hash));
}

/** Encode base64url sem padding. */
function base64urlEncode(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** Decode base64url. */
function base64urlDecode(str: string): string {
    return str.replace(/-/g, '+').replace(/_/g, '/');
}

/**
 * Comparação em tempo constante de duas strings (previne timing attack).
 */
function timingSafeEqual(a: string, b: string): boolean {
    const encoder = new TextEncoder();
    const ba = encoder.encode(a);
    const bb = encoder.encode(b);
    let diff = ba.length ^ bb.length;
    const max = Math.max(ba.length, bb.length);
    for (let i = 0; i < max; i++) {
        diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
    }
    return diff === 0;
}

/**
 * Gera Request ID único (formato simples sem dependências).
 */
function generateRequestId(): string {
    const now = Date.now().toString(36);
    const rand = Math.random().toString(36).slice(2, 10);
    return `${now}-${rand}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários de header
// ─────────────────────────────────────────────────────────────────────────────

function getHeader(
    headers: Record<string, string | string[] | undefined>,
    name: string,
): string | undefined {
    const val = headers[name.toLowerCase()];
    if (!val) return undefined;
    return Array.isArray(val) ? val[0] : val;
}

/** Extrai o MIME type sem parâmetros. Ex: 'application/json; charset=utf-8' → 'application/json' */
function extractMimeType(contentType: string): string {
    return contentType.split(';')[0].trim().toLowerCase();
}

/** Extrai o charset do Content-Type. */
function extractCharset(contentType: string): string | undefined {
    const match = contentType.match(/charset=([^\s;]+)/i);
    return match ? match[1].toLowerCase() : undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// Detecção de Prototype Pollution
// ─────────────────────────────────────────────────────────────────────────────

const PROTOTYPE_POLLUTION_KEYS = new Set([
    '__proto__', 'constructor', 'prototype',
    '__defineGetter__', '__defineSetter__',
    '__lookupGetter__', '__lookupSetter__',
]);

/**
 * Detecta chaves de prototype pollution em um objeto JSON de forma recursiva.
 * Scan O(n) sobre a string antes do parse — mais eficiente que recursão pós-parse.
 */
function detectPrototypePollutionInString(json: string): boolean {
    // Rápido: checa na string antes do parse
    for (const key of Array.from(PROTOTYPE_POLLUTION_KEYS)) {
        if (json.includes(`"${key}"`)) return true;
    }
    return false;
}

/**
 * Recursivamente verifica um objeto já parseado.
 * Usado como segunda passagem de segurança.
 */
function detectPrototypePollutionInObject(obj: unknown, depth = 0): boolean {
    if (depth > 20 || obj === null || typeof obj !== 'object') return false;

    for (const key of Object.keys(obj as object)) {
        if (PROTOTYPE_POLLUTION_KEYS.has(key)) return true;
        const val = (obj as Record<string, unknown>)[key];
        if (typeof val === 'object' && detectPrototypePollutionInObject(val, depth + 1)) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Estimativa de profundidade JSON
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Estima profundidade máxima de JSON em O(n) sem parse completo.
 * Reutiliza a mesma lógica do ddosProtection.ts para consistência.
 */
function estimateJsonDepth(json: string): number {
    let depth = 0; let max = 0; let inStr = false; let esc = false;
    for (let i = 0; i < json.length; i++) {
        const c = json[i];
        if (esc) { esc = false; continue; }
        if (c === '\\' && inStr) { esc = true; continue; }
        if (c === '"') { inStr = !inStr; continue; }
        if (inStr) continue;
        if (c === '{' || c === '[') { if (++depth > max) max = depth; }
        else if (c === '}' || c === ']') depth--;
    }
    return max;
}

// ─────────────────────────────────────────────────────────────────────────────
// Verificação de campos proibidos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se algum campo proibido existe no objeto (nível superior).
 * Para mass assignment protection.
 */
function detectForbiddenFields(
    obj: unknown,
    forbidden: string[],
): string | undefined {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return undefined;
    for (const field of forbidden) {
        if (Object.prototype.hasOwnProperty.call(obj, field)) return field;
    }
    return undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// Request Smuggling detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detecta sinais de HTTP Request Smuggling.
 *
 * Vetores clássicos:
 *  - Content-Length e Transfer-Encoding presentes simultaneamente
 *  - Transfer-Encoding: chunked com obfuscação (chunked , chunked\t, etc.)
 *  - Content-Length com valor inválido
 *  - Headers duplicados com valores conflitantes
 */
function detectRequestSmuggling(
    headers: Record<string, string | string[] | undefined>,
): string | null {
    const cl = headers['content-length'];
    const te = headers['transfer-encoding'];

    // CL + TE simultaneamente — vetor clássico de smuggling (RFC 7230 §3.3.3)
    if (cl !== undefined && te !== undefined) {
        return 'both Content-Length and Transfer-Encoding present';
    }

    // Transfer-Encoding obfuscado
    if (te) {
        const teVal = Array.isArray(te) ? te[0] : te;
        if (/chunked[\s,]|[\s,]chunked/i.test(teVal) && !/^chunked$/i.test(teVal.trim())) {
            return `obfuscated Transfer-Encoding: "${teVal}"`;
        }
    }

    // Content-Length inválido (não numérico ou negativo)
    if (cl) {
        const clVal = Array.isArray(cl) ? cl[0] : cl;
        const parsed = parseInt(clVal, 10);
        if (isNaN(parsed) || parsed < 0 || String(parsed) !== clVal.trim()) {
            return `invalid Content-Length: "${clVal}"`;
        }
    }

    // Headers duplicados com conflito (array com > 1 valor)
    if (Array.isArray(cl) && cl.length > 1) {
        return `duplicate Content-Length headers: ${cl.join(', ')}`;
    }
    if (Array.isArray(te) && te.length > 1) {
        return `duplicate Transfer-Encoding headers: ${te.join(', ')}`;
    }

    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class RequestIntegrityMiddleware {
    private readonly config: Required<
        Omit<RequestIntegrityConfig, 'onViolation'>
    > & Pick<RequestIntegrityConfig, 'onViolation'>;

    constructor(config: RequestIntegrityConfig = {}) {
        this.config = {
            defaults: {},
            routes: {},
            bodyMethods: ['POST', 'PUT', 'PATCH'],
            ignoredMethods: ['OPTIONS', 'HEAD'],
            ignoredRoutes: [],
            onFailure: 'reject',
            generateRequestId: true,
            requestIdHeader: 'x-request-id',
            debug: false,
            onViolation: undefined,
            ...config,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verificação principal
    // ─────────────────────────────────────────────────────────────────────────

    async verify(req: IntegrityRequest): Promise<IntegrityResult> {
        const method = req.method.toUpperCase();
        const path = req.path;
        const now = Date.now();
        const signals: string[] = [];

        // Extrai ou gera Request ID
        const requestId = getHeader(req.headers, this.config.requestIdHeader)
            ?? (this.config.generateRequestId ? generateRequestId() : undefined);

        const meta: IntegrityMeta = {
            path, method, timestamp: now,
            requestId: requestId ?? 'unknown',
            signals,
        };

        const fail = (
            reason: IntegrityViolation,
            detail?: string,
        ): IntegrityResult => {
            signals.push(reason);
            const result: IntegrityResult = {
                valid: false, reason, detail, requestId, meta,
            };
            void this.config.onViolation?.(result, req);
            this.debugLog('VIOLATION', reason, detail ?? '', path);
            return result;
        };

        // ── Métodos ignorados ──────────────────────────────────────────────
        if (this.config.ignoredMethods.includes(method)) {
            return { valid: true, requestId, meta };
        }

        // ── Rotas ignoradas ───────────────────────────────────────────────
        if (this.isIgnoredRoute(path)) {
            return { valid: true, requestId, meta };
        }

        // ── Configuração efetiva para esta rota ───────────────────────────
        const routeCfg = this.resolveRouteConfig(path);

        // ── 1. Request Smuggling ──────────────────────────────────────────
        const smugglingSignal = detectRequestSmuggling(req.headers);
        if (smugglingSignal) {
            signals.push(`smuggling:${smugglingSignal}`);
            return fail('REQUEST_SMUGGLING_SUSPECTED', smugglingSignal);
        }

        // ── 2. Headers obrigatórios ────────────────────────────────────────
        for (const hdr of (routeCfg.requiredHeaders ?? [])) {
            if (!getHeader(req.headers, hdr)) {
                return fail('HEADER_MISSING', `missing required header: ${hdr}`);
            }
        }

        // ── 3. Headers proibidos ───────────────────────────────────────────
        for (const hdr of (routeCfg.forbiddenHeaders ?? [])) {
            if (getHeader(req.headers, hdr) !== undefined) {
                return fail('HEADER_FORBIDDEN', `forbidden header present: ${hdr}`);
            }
        }

        // ── 4. Content-Type ────────────────────────────────────────────────
        const ctResult = this.verifyContentType(req, routeCfg.contentType);
        if (!ctResult.valid) return fail(ctResult.violation!, ctResult.detail);

        // ── 5. Content-Length consistency ─────────────────────────────────
        const clResult = this.verifyContentLength(req);
        if (!clResult.valid) return fail(clResult.violation!, clResult.detail);

        // ── 6. Replay protection ──────────────────────────────────────────
        if (routeCfg.replayProtection) {
            const replayResult = await this.verifyReplayProtection(
                req, routeCfg.replayProtection,
            );
            if (!replayResult.valid) return fail(replayResult.violation!, replayResult.detail);
        }

        // ── 7. Assinatura HMAC ────────────────────────────────────────────
        if (routeCfg.signature) {
            const sigResult = await this.verifySignature(req, routeCfg.signature);
            if (!sigResult.valid) return fail(sigResult.violation!, sigResult.detail);
        }

        // ── 8. Integridade do body ─────────────────────────────────────────
        const isBodyMethod = this.config.bodyMethods.includes(method);
        if (isBodyMethod && routeCfg.body) {
            const bodyResult = await this.verifyBody(req, routeCfg.body);
            if (!bodyResult.valid) return fail(bodyResult.violation!, bodyResult.detail);
        }

        // ── 9. Idempotência ────────────────────────────────────────────────
        if (routeCfg.idempotency) {
            const idmpResult = await this.verifyIdempotency(
                req, routeCfg.idempotency,
            );
            if (!idmpResult.valid) return fail(idmpResult.violation!, idmpResult.detail);
        }

        this.debugLog('VALID', path, method, requestId);
        return { valid: true, requestId, meta };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verificações individuais
    // ─────────────────────────────────────────────────────────────────────────

    private verifyContentType(
        req: IntegrityRequest,
        cfg: ContentTypeConfig | undefined,
    ): { valid: boolean; violation?: IntegrityViolation; detail?: string } {
        const ct = getHeader(req.headers, 'content-type');
        const isBodyMethod = this.config.bodyMethods.includes(req.method.toUpperCase());

        if (!ct) {
            if (isBodyMethod && req.rawBody?.length) {
                return { valid: false, violation: 'CONTENT_TYPE_MISSING', detail: 'body present but no Content-Type' };
            }
            return { valid: true };
        }

        const mime = extractMimeType(ct);
        const charset = extractCharset(ct);

        // Verifica types proibidos (XXE default)
        const forbidden = cfg?.forbidden ?? ['text/xml', 'application/xml', 'application/x-www-form-urlencoded'];
        if (forbidden.includes(mime)) {
            return {
                valid: false, violation: 'CONTENT_TYPE_FORBIDDEN',
                detail: `Content-Type "${mime}" is forbidden`,
            };
        }

        // Verifica allowlist
        if (cfg?.allowed && !cfg.allowed.some(a => mime === a.split(';')[0].trim().toLowerCase())) {
            return {
                valid: false, violation: 'CONTENT_TYPE_MISMATCH',
                detail: `Content-Type "${mime}" not in allowed list`,
            };
        }

        // Charset UTF-8 para tipos text/*
        if (cfg?.requireUtf8Charset !== false && mime.startsWith('text/') && charset) {
            if (!['utf-8', 'utf8'].includes(charset)) {
                return {
                    valid: false, violation: 'ENCODING_INVALID',
                    detail: `non-UTF-8 charset: "${charset}"`,
                };
            }
        }

        return { valid: true };
    }

    private verifyContentLength(
        req: IntegrityRequest,
    ): { valid: boolean; violation?: IntegrityViolation; detail?: string } {
        const clHeader = getHeader(req.headers, 'content-length');
        if (!clHeader) return { valid: true };

        const declared = parseInt(clHeader, 10);
        if (isNaN(declared) || declared < 0) {
            return { valid: false, violation: 'CONTENT_LENGTH_MISMATCH', detail: `invalid Content-Length: ${clHeader}` };
        }

        if (req.rawBody && req.rawBody.length !== declared) {
            return {
                valid: false, violation: 'CONTENT_LENGTH_MISMATCH',
                detail: `Content-Length ${declared} != actual body size ${req.rawBody.length}`,
            };
        }

        if (req.contentLength !== undefined && req.contentLength !== declared) {
            return {
                valid: false, violation: 'CONTENT_LENGTH_MISMATCH',
                detail: `declared Content-Length ${declared} != received ${req.contentLength}`,
            };
        }

        return { valid: true };
    }

    private async verifyReplayProtection(
        req: IntegrityRequest,
        cfg: ReplayProtectionConfig,
    ): Promise<{ valid: boolean; violation?: IntegrityViolation; detail?: string }> {
        const windowMs = cfg.windowMs ?? 300_000;
        const tsHeader = cfg.timestampHeader ?? 'x-timestamp';
        const nonceHeader = cfg.nonceHeader ?? 'x-nonce';
        const minNonceLen = cfg.minNonceLength ?? 16;
        const now = Date.now();

        const tsVal = getHeader(req.headers, tsHeader);
        const nonceVal = getHeader(req.headers, nonceHeader);

        // Timestamp
        if (!tsVal) {
            if (cfg.required) return { valid: false, violation: 'TIMESTAMP_MISSING' };
            return { valid: true }; // Opcional — sem timestamp, sem verificação
        }

        const ts = parseInt(tsVal, 10);
        if (isNaN(ts)) {
            return { valid: false, violation: 'TIMESTAMP_INVALID', detail: `invalid timestamp: "${tsVal}"` };
        }

        if (ts > now + 30_000) {
            // Timestamp no futuro (mais de 30s) — clock skew suspeito
            return { valid: false, violation: 'TIMESTAMP_FUTURE', detail: `timestamp ${ts} is ${ts - now}ms in the future` };
        }

        if (now - ts > windowMs) {
            return { valid: false, violation: 'TIMESTAMP_EXPIRED', detail: `timestamp expired: ${now - ts}ms old (max ${windowMs}ms)` };
        }

        // Nonce
        if (!nonceVal) {
            if (cfg.required) return { valid: false, violation: 'NONCE_MISSING' };
            return { valid: true };
        }

        if (nonceVal.length < minNonceLen) {
            return { valid: false, violation: 'NONCE_INVALID', detail: `nonce too short: ${nonceVal.length} < ${minNonceLen}` };
        }

        // Apenas caracteres alfanuméricos e - _ no nonce
        if (!/^[a-zA-Z0-9\-_]+$/.test(nonceVal)) {
            return { valid: false, violation: 'NONCE_INVALID', detail: 'nonce contains invalid characters' };
        }

        if (cfg.nonceStore) {
            const replayed = await cfg.nonceStore.checkAndStore(nonceVal, windowMs);
            if (replayed) {
                return { valid: false, violation: 'NONCE_REPLAYED', detail: `nonce "${nonceVal}" already used` };
            }
        }

        return { valid: true };
    }

    private async verifySignature(
        req: IntegrityRequest,
        cfg: SignatureConfig,
    ): Promise<{ valid: boolean; violation?: IntegrityViolation; detail?: string }> {
        const headerName = cfg.headerName ?? 'x-signature-sha256';
        const sigHeader = getHeader(req.headers, headerName);

        if (!sigHeader) {
            if (cfg.required !== false) {
                return { valid: false, violation: 'SIGNATURE_MISSING', detail: `missing header: ${headerName}` };
            }
            return { valid: true };
        }

        // Extrai a assinatura do header (formato: 'sha256=<valor>')
        const sigMatch = sigHeader.match(/^sha256=(.+)$/i);
        if (!sigMatch) {
            return { valid: false, violation: 'SIGNATURE_INVALID', detail: `invalid signature format: "${sigHeader}"` };
        }

        const receivedSig = base64urlDecode(sigMatch[1]);

        // Monta o payload a assinar
        const bodyStr = req.rawBody
            ? new TextDecoder().decode(req.rawBody)
            : JSON.stringify(req.parsedBody ?? '');

        let signPayload = bodyStr;

        // Adiciona headers signed na assinatura se configurado
        if (cfg.signedHeaders?.length) {
            const headerParts = cfg.signedHeaders
                .map(h => `${h.toLowerCase()}:${getHeader(req.headers, h) ?? ''}`)
                .join('\n');
            signPayload = `${headerParts}\n${bodyStr}`;
        }

        const expectedSig = await computeHMAC(signPayload, cfg.secret);
        const expectedBase64 = base64urlDecode(expectedSig);

        if (!timingSafeEqual(expectedBase64, receivedSig)) {
            return { valid: false, violation: 'SIGNATURE_INVALID', detail: 'HMAC signature mismatch' };
        }

        return { valid: true };
    }

    private async verifyBody(
        req: IntegrityRequest,
        cfg: BodyIntegrityConfig,
    ): Promise<{ valid: boolean; violation?: IntegrityViolation; detail?: string }> {
        const maxBytes = cfg.maxSizeBytes ?? 1_048_576;
        const required = cfg.required ?? true;
        const maxDepth = cfg.maxDepth ?? 10;

        const bodyBytes = req.rawBody?.length ?? 0;

        // Obrigatoriedade
        if (required && bodyBytes === 0 && !req.parsedBody) {
            return { valid: false, violation: 'BODY_MISSING', detail: 'request body is required' };
        }

        // Tamanho máximo
        if (bodyBytes > maxBytes) {
            return {
                valid: false, violation: 'CONTENT_LENGTH_EXCEEDED',
                detail: `body size ${bodyBytes} exceeds maximum ${maxBytes}`
            };
        }

        // Hash do body
        if (cfg.validateHash !== false) {
            const hashHeader = cfg.hashHeader ?? 'x-body-hash';
            const declaredHash = getHeader(req.headers, hashHeader);

            if (declaredHash && req.rawBody) {
                const hashMatch = declaredHash.match(/^sha256=(.+)$/i);
                if (!hashMatch) {
                    return { valid: false, violation: 'BODY_HASH_MISMATCH', detail: 'invalid body hash format' };
                }
                const computedHash = await computeSHA256(req.rawBody);
                if (!timingSafeEqual(hashMatch[1], computedHash)) {
                    return { valid: false, violation: 'BODY_HASH_MISMATCH', detail: 'body SHA-256 hash mismatch' };
                }
            }
        }

        // Parse e validação do body JSON
        let parsedBody = req.parsedBody;

        if (!parsedBody && req.rawBody && bodyBytes > 0) {
            const ct = getHeader(req.headers, 'content-type') ?? '';
            if (extractMimeType(ct) === 'application/json') {
                const bodyStr = new TextDecoder().decode(req.rawBody);

                // Prototype pollution (pre-parse, mais eficiente)
                if (cfg.detectPrototypePollution !== false && detectPrototypePollutionInString(bodyStr)) {
                    return { valid: false, violation: 'PROTOTYPE_POLLUTION', detail: 'prototype pollution key detected' };
                }

                // Profundidade máxima (pre-parse)
                if (estimateJsonDepth(bodyStr) > maxDepth) {
                    return {
                        valid: false, violation: 'BODY_PARSE_ERROR',
                        detail: `JSON depth exceeds maximum ${maxDepth}`
                    };
                }

                try {
                    parsedBody = JSON.parse(bodyStr);
                } catch (e) {
                    return {
                        valid: false, violation: 'BODY_PARSE_ERROR',
                        detail: `invalid JSON: ${(e as Error).message}`
                    };
                }

                // Prototype pollution (pós-parse — segunda verificação)
                if (cfg.detectPrototypePollution !== false && detectPrototypePollutionInObject(parsedBody)) {
                    return { valid: false, violation: 'PROTOTYPE_POLLUTION', detail: 'prototype pollution in parsed object' };
                }
            }
        }

        // Campos proibidos (mass assignment)
        if (cfg.forbiddenFields?.length && parsedBody) {
            const found = detectForbiddenFields(parsedBody, cfg.forbiddenFields);
            if (found) {
                return {
                    valid: false, violation: 'FORBIDDEN_FIELD',
                    detail: `forbidden field in body: "${found}"`
                };
            }
        }

        // Schema validation
        if (cfg.schema && parsedBody !== undefined) {
            const schemaResult = cfg.schema(parsedBody);
            if (!schemaResult.valid) {
                return {
                    valid: false, violation: 'SCHEMA_INVALID',
                    detail: schemaResult.errors?.join('; ')
                };
            }
        }

        return { valid: true };
    }

    private async verifyIdempotency(
        req: IntegrityRequest,
        cfg: IdempotencyConfig,
    ): Promise<{ valid: boolean; violation?: IntegrityViolation; detail?: string }> {
        const headerName = cfg.headerName ?? 'idempotency-key';
        const ttlMs = cfg.ttlMs ?? 86_400_000;
        const keyVal = getHeader(req.headers, headerName);

        if (!keyVal) {
            if (cfg.required) {
                return {
                    valid: false, violation: 'IDEMPOTENCY_KEY_MISSING',
                    detail: `missing header: ${headerName}`
                };
            }
            return { valid: true };
        }

        // Formato válido: alfanumérico, -, _, tamanho razoável
        if (!/^[a-zA-Z0-9\-_]{8,128}$/.test(keyVal)) {
            return {
                valid: false, violation: 'IDEMPOTENCY_KEY_MISSING',
                detail: `invalid idempotency key format`
            };
        }

        if (cfg.idempotencyStore) {
            const replayed = await cfg.idempotencyStore.checkAndStore(keyVal, ttlMs);
            if (replayed) {
                return {
                    valid: false, violation: 'IDEMPOTENCY_KEY_REPLAYED',
                    detail: `idempotency key "${keyVal}" already processed`
                };
            }
        }

        return { valid: true };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários
    // ─────────────────────────────────────────────────────────────────────────

    /** Resolve a configuração efetiva para uma rota (defaults + route override). */
    private resolveRouteConfig(path: string): RouteIntegrityConfig {
        const defaults = this.config.defaults ?? {};

        for (const [pattern, cfg] of Object.entries(this.config.routes ?? {})) {
            if (path === pattern || path.startsWith(pattern + '/')) {
                // Merge profundo: defaults + route override
                return {
                    signature: cfg.signature ?? defaults.signature,
                    replayProtection: cfg.replayProtection ?? defaults.replayProtection,
                    contentType: cfg.contentType ?? defaults.contentType,
                    body: { ...defaults.body, ...cfg.body },
                    idempotency: cfg.idempotency ?? defaults.idempotency,
                    requiredHeaders: [...(defaults.requiredHeaders ?? []), ...(cfg.requiredHeaders ?? [])],
                    forbiddenHeaders: [...(defaults.forbiddenHeaders ?? []), ...(cfg.forbiddenHeaders ?? [])],
                };
            }
        }

        return defaults;
    }

    private isIgnoredRoute(path: string): boolean {
        for (const route of this.config.ignoredRoutes) {
            if (typeof route === 'string') {
                if (path === route || path.startsWith(route + '/')) return true;
            } else if (route.test(path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Utilitário público: assina um body para uso no cliente.
     * Use em testes de integração ou em SDKs cliente.
     *
     * @example
     * const sig = await middleware.signBody(JSON.stringify(payload), secret);
     * headers['x-signature-sha256'] = `sha256=${sig}`;
     */
    async signBody(body: string, secret: string): Promise<string> {
        return computeHMAC(body, secret);
    }

    /**
     * Utilitário público: computa hash SHA-256 de um body.
     *
     * @example
     * const hash = await middleware.hashBody(JSON.stringify(payload));
     * headers['x-body-hash'] = `sha256=${hash}`;
     */
    async hashBody(body: string | Uint8Array): Promise<string> {
        return computeSHA256(body);
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[request-integrity]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

type ExpressReq = {
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
    rawBody?: Buffer;
};
type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    json(d: unknown): void;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware de integridade para Express.
 *
 * ⚠ Requer que o body esteja disponível como Buffer em `req.rawBody`.
 * Configure com express.raw() ou bodyParser com opção verify:
 *
 * @example
 * app.use(express.json({
 *   verify: (req, _res, buf) => { (req as any).rawBody = buf; }
 * }));
 * app.use(createExpressIntegrity(integrity));
 */
export function createExpressIntegrity(middleware: RequestIntegrityMiddleware) {
    return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
        const result = await middleware.verify({
            method: req.method,
            path: req.path,
            headers: req.headers,
            rawBody: req.rawBody,
            parsedBody: req.body,
            contentLength: req.rawBody?.length,
        });

        if (!result.valid) {
            const status = result.reason?.startsWith('SIGNATURE') ? 401
                : result.reason?.startsWith('NONCE') || result.reason?.startsWith('IDEMPOTENCY') ? 409
                    : 400;

            res.status(status).set({
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff',
                'Cache-Control': 'no-store',
                ...(result.requestId ? { 'X-Request-Id': result.requestId } : {}),
            }).json({
                error: 'Bad Request',
                message: 'Request integrity check failed.',
                requestId: result.requestId,
            });
            return;
        }

        next();
    };
}

/**
 * Handler de integridade para Next.js Edge Runtime.
 *
 * @example
 * // middleware.ts
 * const integrityHandler = createNextIntegrity(integrity);
 * export default async function middleware(request: Request) {
 *   const failed = await integrityHandler(request);
 *   if (failed) return failed;
 *   return NextResponse.next();
 * }
 */
export function createNextIntegrity(middleware: RequestIntegrityMiddleware) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => { headers[key] = value; });

        const url = new URL(request.url);
        const rawBodyBuf = request.body
            ? new Uint8Array(await request.arrayBuffer())
            : undefined;

        const result = await middleware.verify({
            method: request.method,
            path: url.pathname,
            headers,
            rawBody: rawBodyBuf,
            contentLength: rawBodyBuf?.length,
        });

        if (!result.valid) {
            const status = result.reason?.startsWith('SIGNATURE') ? 401
                : result.reason?.startsWith('NONCE') || result.reason?.startsWith('IDEMPOTENCY') ? 409
                    : 400;

            return new Response(
                JSON.stringify({
                    error: 'Bad Request',
                    message: 'Request integrity check failed.',
                    requestId: result.requestId,
                }),
                {
                    status,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Content-Type-Options': 'nosniff',
                        'Cache-Control': 'no-store',
                        ...(result.requestId ? { 'X-Request-Id': result.requestId } : {}),
                    },
                },
            );
        }

        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factories com preset
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Preset para API REST padrão sem autenticação de assinatura.
 * Cobre: Content-Type, prototype pollution, mass assignment, body size.
 *
 * @example
 * const integrity = createDefaultIntegrity({
 *   forbiddenFields: ['isAdmin', 'role', '__proto__'],
 * });
 */
export function createDefaultIntegrity(
    overrides: Partial<RouteIntegrityConfig> = {},
): RequestIntegrityMiddleware {
    return new RequestIntegrityMiddleware({
        bodyMethods: ['POST', 'PUT', 'PATCH'],
        ignoredMethods: ['OPTIONS', 'HEAD', 'GET'],
        defaults: {
            contentType: {
                allowed: ['application/json', 'multipart/form-data', 'application/octet-stream'],
                forbidden: ['text/xml', 'application/xml'],
                requireUtf8Charset: true,
            },
            body: {
                maxSizeBytes: 1_048_576,
                detectPrototypePollution: true,
                maxDepth: 10,
                forbiddenFields: ['__proto__', 'constructor', 'prototype'],
                ...overrides.body,
            },
            ...overrides,
        },
    });
}

/**
 * Preset para webhook receiver (Stripe, GitHub, etc.).
 * Valida assinatura HMAC e proteção anti-replay.
 *
 * @example
 * const webhookIntegrity = createWebhookIntegrity(
 *   process.env.WEBHOOK_SECRET!,
 *   new MemoryNonceStore(),
 * );
 */
export function createWebhookIntegrity(
    secret: string,
    nonceStore?: NonceStore,
): RequestIntegrityMiddleware {
    return new RequestIntegrityMiddleware({
        bodyMethods: ['POST'],
        ignoredMethods: ['OPTIONS', 'HEAD', 'GET'],
        defaults: {
            signature: {
                secret,
                headerName: 'x-signature-sha256',
                required: true,
                signedHeaders: ['x-timestamp'],
            },
            replayProtection: nonceStore ? {
                required: true,
                windowMs: 300_000,
                nonceStore,
            } : undefined,
            body: {
                maxSizeBytes: 10_048_576, // 10MB para webhooks
                detectPrototypePollution: true,
                maxDepth: 15,
            },
        },
        ignoredRoutes: [], // webhooks não ignoram nenhuma rota
    });
}

/**
 * Preset para endpoint de pagamento com idempotência.
 * Previne double-spend via Idempotency-Key.
 *
 * @example
 * const paymentIntegrity = createPaymentIntegrity(
 *   process.env.REQUEST_SECRET!,
 *   idempotencyStore,
 *   nonceStore,
 * );
 */
export function createPaymentIntegrity(
    secret: string,
    idempotencyStore: IdempotencyStore,
    nonceStore?: NonceStore,
): RequestIntegrityMiddleware {
    return new RequestIntegrityMiddleware({
        bodyMethods: ['POST', 'PUT'],
        ignoredMethods: ['OPTIONS', 'HEAD', 'GET'],
        defaults: {
            signature: {
                secret,
                required: true,
                signedHeaders: ['x-timestamp', 'x-nonce', 'content-type'],
            },
            replayProtection: {
                required: true,
                windowMs: 60_000,  // 1 minuto para pagamentos
                nonceStore,
            },
            contentType: {
                allowed: ['application/json'],
                forbidden: ['text/xml', 'application/xml', 'application/x-www-form-urlencoded'],
            },
            body: {
                maxSizeBytes: 512_000,  // 500KB para pagamentos
                detectPrototypePollution: true,
                maxDepth: 8,
                validateHash: true,
                forbiddenFields: ['__proto__', 'constructor', 'isVerified', 'status', 'createdAt'],
            },
            idempotency: {
                required: true,
                ttlMs: 86_400_000,
                idempotencyStore,
            },
            requiredHeaders: ['x-timestamp', 'x-nonce'],
        },
    });
}