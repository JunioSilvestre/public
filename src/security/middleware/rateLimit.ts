/**
 * @fileoverview Middleware de Rate Limiting — controle de taxa multicamada.
 *
 * @description
 * Implementa múltiplos algoritmos de rate limiting com estratégias adaptativas,
 * suporte a múltiplas dimensões (IP, usuário, endpoint, tenant) e integração
 * com todos os outros middlewares de segurança do sistema.
 *
 * ── Algoritmos implementados ───────────────────────────────────────────────
 *  1. Fixed Window     — janela fixa (simples, eficiente, sujeita a burst)
 *  2. Sliding Window   — janela deslizante (preciso, sem burst no boundary)
 *  3. Token Bucket     — burst natural com reposição gradual (recomendado)
 *  4. Leaky Bucket     — taxa constante de saída (suaviza picos)
 *  5. Concurrent Limit — limite de requisições simultâneas (sem timeout)
 *
 * ── Dimensões de rate limiting ────────────────────────────────────────────
 *  • Por IP            — padrão para usuários anônimos
 *  • Por usuário       — para usuários autenticados (mais justo)
 *  • Por endpoint      — limites específicos por rota
 *  • Por tenant        — para aplicações multi-tenant (SaaS)
 *  • Por API key       — para integrações B2B
 *  • Combinado         — IP + usuário + endpoint simultaneamente
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *  • HTTP flood genérico                                      (ubíquo)
 *  • Credential stuffing via login endpoint                   (OWASP A07)
 *  • OTP/2FA brute force (6 dígitos = 1M combinações)        (ubíquo)
 *  • Password reset abuse (envio de email em massa)           (ubíquo)
 *  • API key enumeration                                      (2018+)
 *  • Slow-rate distributed attack (baixa taxa por IP)        (2020+)
 *  • Burst at window boundary (fixed window abuse)            (documentado)
 *  • Token hoarding (consome tokens sem usar)                 (2021+)
 *  • Race condition em limite de créditos/recursos            (2019+)
 *  • GraphQL batching para contornar rate limit por request   (2020+)
 *  • Webhook replay flood                                     (2022+)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • gRPC streaming rate limiting                             (emergente)
 *  • WebSocket message rate limiting                         (emergente)
 *  • Server-Sent Events rate limiting                         (emergente)
 *  • Cost-based rate limiting (operações custosas = múltiplos tokens)
 *  • AI/LLM token consumption limiting                        (2023+)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Algoritmo configurável por rota
 *  • Headers RFC 6585 + Draft IETF Rate Limit Headers
 *  • Retry-After correto para cada algoritmo
 *  • Store injetável (Redis em produção)
 *  • Resposta padronizada com headers informativos (sem vazar lógica)
 *  • Adaptadores Express, Next.js e handler funcional puro
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers
 * @see https://www.ietf.org/rfc/rfc6585.txt
 * @see https://cloud.google.com/architecture/rate-limiting-strategies-techniques
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da verificação de rate limit. */
export interface RateLimitResult {
    /** true = dentro do limite | false = limite excedido */
    allowed: boolean;
    /** Algoritmo que tomou a decisão */
    algorithm: RateLimitAlgorithm;
    /** Dimensão que foi limitada */
    dimension: RateLimitDimension;
    /** Limite configurado para esta janela */
    limit: number;
    /** Requisições restantes nesta janela */
    remaining: number;
    /** Timestamp (Unix ms) em que o limite é resetado */
    resetAt: number;
    /** Segundos para aguardar antes de tentar novamente */
    retryAfterSeconds: number;
    /** Headers prontos para adicionar à resposta */
    headers: RateLimitHeaders;
    meta: RateLimitMeta;
}

/** Headers de rate limit padronizados (RFC + Draft IETF). */
export interface RateLimitHeaders {
    /** Index signature — permite spread em Record<string, string> sem double-cast. */
    [key: string]: string | undefined;
    /** Limite total da janela (RateLimit-Limit / X-RateLimit-Limit) */
    'RateLimit-Limit': string;
    /** Requisições restantes (RateLimit-Remaining / X-RateLimit-Remaining) */
    'RateLimit-Remaining': string;
    /** Timestamp de reset em segundos Unix (RateLimit-Reset) */
    'RateLimit-Reset': string;
    /** Política completa (Draft IETF: limite;w=janela) */
    'RateLimit-Policy': string;
    /** Segundos para aguardar (presente apenas quando bloqueado) */
    'Retry-After'?: string;
}

/**
 * Converte RateLimitHeaders em Record<string, string>, removendo
 * campos undefined (Retry-After quando não bloqueado).
 */
export function headersToRecord(h: RateLimitHeaders): Record<string, string> {
    return Object.fromEntries(
        Object.entries(h).filter((entry): entry is [string, string] => entry[1] !== undefined),
    );
}

export type RateLimitAlgorithm =
    | 'fixed-window'
    | 'sliding-window'
    | 'token-bucket'
    | 'leaky-bucket'
    | 'concurrent';

export type RateLimitDimension =
    | 'ip'
    | 'user'
    | 'api-key'
    | 'tenant'
    | 'endpoint'
    | 'combined'
    | 'global';

export interface RateLimitMeta {
    key: string;  // Chave usada no store (anonimizada)
    dimension: RateLimitDimension;
    endpoint: string;
    method: string;
    timestamp: number;
    identifier?: string;  // IP, userId, etc. (hasheado para logs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Configuração de uma regra de rate limit.
 * Cada rota pode ter múltiplas regras — todas são verificadas.
 */
export interface RateLimitRule {
    /**
     * Algoritmo de rate limiting.
     *
     * Guia de escolha:
     *  - fixed-window:   mais simples, menor overhead, permite burst na borda da janela
     *  - sliding-window: mais preciso, sem burst, maior overhead de storage
     *  - token-bucket:   melhor para burst legítimo (usuário abre 5 abas), recomendado
     *  - leaky-bucket:   taxa constante, ideal para proteção de APIs downstream
     *  - concurrent:     limita conexões simultâneas (útil para uploads, websockets)
     *
     * Default: 'sliding-window'
     */
    algorithm?: RateLimitAlgorithm;

    /**
     * Dimensão de identificação.
     *
     * 'ip'       — identifica por IP (para anônimos)
     * 'user'     — identifica por userId (para autenticados, mais justo)
     * 'api-key'  — identifica por API key (B2B)
     * 'tenant'   — identifica por tenant ID (multi-tenant SaaS)
     * 'combined' — IP + userId (detecta abusos mesmo com múltiplos usuários)
     * 'global'   — limite único compartilhado por todos (proteção global)
     *
     * Default: 'ip'
     */
    dimension?: RateLimitDimension;

    /** Máximo de requisições permitidas na janela. */
    limit: number;

    /**
     * Tamanho da janela de tempo em ms.
     * Para token-bucket: tempo para encher o bucket do zero.
     */
    windowMs: number;

    /**
     * Para token-bucket: capacidade máxima de burst.
     * Default: igual ao `limit`
     */
    burstLimit?: number;

    /**
     * Para concurrent: timeout em ms para liberar um slot concorrente.
     * Se a requisição não liberar dentro desse tempo, o slot é liberado automaticamente.
     * Default: 30_000 (30 segundos)
     */
    concurrentTimeoutMs?: number;

    /**
     * Para leaky-bucket: taxa de processamento por segundo.
     * Default: limit / (windowMs / 1000)
     */
    leakRatePerSecond?: number;

    /**
     * Custo desta requisição em tokens.
     * Use para operações custosas (ex: export = 10 tokens, consulta simples = 1).
     * Default: 1
     */
    cost?: number;

    /**
     * Peso da requisição para leaky-bucket/token-bucket baseado em critérios.
     * Permite operações custosas consumirem mais tokens.
     */
    costResolver?: (req: RateLimitRequest) => number;

    /**
     * Ação quando o limite é excedido.
     * - 'reject':  retorna 429 imediatamente (padrão)
     * - 'delay':   aguarda slot disponível (útil para queues)
     * - 'dry-run': registra mas não bloqueia (para análise de impacto)
     *
     * Default: 'reject'
     */
    action?: 'reject' | 'delay' | 'dry-run';

    /**
     * Máximo de ms para aguardar em modo 'delay'.
     * Default: 5000
     */
    maxDelayMs?: number;

    /**
     * Função de identificador customizado.
     * Substitui a extração padrão por dimensão.
     *
     * @example
     * keyResolver: (req) => req.headers['x-tenant-id'] ?? req.ip
     */
    keyResolver?: (req: RateLimitRequest) => string | Promise<string>;

    /**
     * Função que determina se esta regra se aplica à requisição.
     * Permite regras condicionais (ex: apenas para usuários não-premium).
     *
     * @example
     * condition: (req) => !req.user?.isPremium
     */
    condition?: (req: RateLimitRequest) => boolean | Promise<boolean>;

    /**
     * Identificador desta regra para logs e headers.
     * Default: gerado automaticamente
     */
    name?: string;
}

/** Configuração global do middleware. */
export interface RateLimitConfig {
    /** Regras padrão aplicadas a todas as rotas. */
    defaultRules?: RateLimitRule[];

    /**
     * Regras por rota específica.
     * Sobrescreve as regras padrão para as rotas listadas.
     *
     * @example
     * routeRules: {
     *   '/api/auth/login': [
     *     { limit: 5, windowMs: 60_000, algorithm: 'sliding-window' }
     *   ],
     *   '/api/export': [
     *     { limit: 3, windowMs: 300_000, cost: 10 }
     *   ]
     * }
     */
    routeRules?: Record<string, RateLimitRule[]>;

    /**
     * IPs/identificadores sempre excluídos do rate limiting.
     * Use para health checks, load balancers, CIs.
     */
    skip?: Array<string | ((req: RateLimitRequest) => boolean | Promise<boolean>)>;

    /**
     * Prefixo das chaves no store.
     * Útil para isolar ambientes (dev/staging/prod) no mesmo Redis.
     * Default: 'rl'
     */
    keyPrefix?: string;

    /**
     * Comportamento quando o store falha.
     * - 'open':  permite a requisição (fail open — disponibilidade > segurança)
     * - 'closed': bloqueia a requisição (fail closed — segurança > disponibilidade)
     *
     * Default: 'open' (falhar aberto é mais seguro para disponibilidade)
     */
    onStoreError?: 'open' | 'closed';

    /**
     * Hook chamado quando o limite é excedido.
     * Use para alertas, logs de segurança, integração com ipFilter.
     */
    onLimitReached?: (result: RateLimitResult, req: RateLimitRequest) => void | Promise<void>;

    /**
     * Hook chamado em cada requisição (para métricas).
     */
    onRequest?: (result: RateLimitResult, req: RateLimitRequest) => void;

    /** Store injetável. Use Redis em produção. */
    store: RateLimitStore;

    /** Habilita headers de rate limit na resposta. Default: true */
    sendHeaders?: boolean;

    /** Habilita logging detalhado. Default: false */
    debug?: boolean;
}

/** Requisição normalizada para avaliação de rate limit. */
export interface RateLimitRequest {
    ip: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    /** ID do usuário autenticado (para dimensão 'user'). */
    userId?: string;
    /** API key (para dimensão 'api-key'). */
    apiKey?: string;
    /** Tenant ID (para dimensão 'tenant'). */
    tenantId?: string;
    /** Custo pré-calculado da requisição (sobrescreve rule.cost). */
    cost?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Interface do store
// ─────────────────────────────────────────────────────────────────────────────

export interface RateLimitStore {
    /**
     * Incrementa e retorna o contador atual.
     * Se a chave não existir, cria com valor 1 e TTL.
     */
    increment(key: string, ttlMs: number): Promise<number>;

    /** Lê o valor atual sem incrementar. */
    get(key: string): Promise<number | null>;

    /** Define um valor com TTL. */
    set(key: string, value: number, ttlMs: number): Promise<void>;

    /** Retorna o TTL restante em ms. null se não existe. */
    ttl(key: string): Promise<number | null>;

    /** Remove uma chave (usado pelo concurrent limit na liberação). */
    delete(key: string): Promise<void>;

    /**
     * Incremento e leitura do TTL restante atomicamente.
     * Otimização Redis — fallback para increment + ttl se não disponível.
     */
    incrementWithTTL?(key: string, ttlMs: number): Promise<{ count: number; ttlMs: number }>;

    /**
     * Adiciona timestamp ao sliding window log.
     * Para implementação de sliding window com lista de timestamps.
     */
    addToWindow?(key: string, timestamp: number, windowMs: number): Promise<number>;

    /**
     * Retorna todos os timestamps na janela.
     * Para sliding window preciso.
     */
    getWindowEntries?(key: string, windowStart: number): Promise<number[]>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store em memória
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Implementação de store em memória.
 * ⚠ Não use em produção com múltiplas instâncias — use Redis.
 */
export class MemoryRateLimitStore implements RateLimitStore {
    private readonly counters = new Map<string, { value: number; expiresAt: number }>();
    private readonly windows = new Map<string, { timestamps: number[]; expiresAt: number }>();
    private readonly interval: ReturnType<typeof setInterval>;

    constructor(cleanupIntervalMs = 60_000) {
        this.interval = setInterval(() => this.cleanup(), cleanupIntervalMs);
        if (typeof this.interval.unref === 'function') this.interval.unref();
    }

    async increment(key: string, ttlMs: number): Promise<number> {
        const now = Date.now();
        const entry = this.counters.get(key);

        if (!entry || entry.expiresAt <= now) {
            this.counters.set(key, { value: 1, expiresAt: now + ttlMs });
            return 1;
        }

        entry.value++;
        return entry.value;
    }

    async get(key: string): Promise<number | null> {
        const entry = this.counters.get(key);
        if (!entry || entry.expiresAt <= Date.now()) return null;
        return entry.value;
    }

    async set(key: string, value: number, ttlMs: number): Promise<void> {
        this.counters.set(key, { value, expiresAt: Date.now() + ttlMs });
    }

    async ttl(key: string): Promise<number | null> {
        const entry = this.counters.get(key);
        if (!entry) return null;
        const remaining = entry.expiresAt - Date.now();
        return remaining > 0 ? remaining : null;
    }

    async delete(key: string): Promise<void> {
        this.counters.delete(key);
        this.windows.delete(key);
    }

    async incrementWithTTL(key: string, ttlMs: number): Promise<{ count: number; ttlMs: number }> {
        const count = await this.increment(key, ttlMs);
        const remaining = await this.ttl(key);
        return { count, ttlMs: remaining ?? ttlMs };
    }

    async addToWindow(key: string, timestamp: number, windowMs: number): Promise<number> {
        const now = Date.now();
        const existing = this.windows.get(key);
        const cutoff = now - windowMs;

        if (!existing || existing.expiresAt <= now) {
            this.windows.set(key, {
                timestamps: [timestamp],
                expiresAt: now + windowMs,
            });
            return 1;
        }

        // Remove timestamps fora da janela
        existing.timestamps = existing.timestamps.filter(t => t > cutoff);
        existing.timestamps.push(timestamp);
        return existing.timestamps.length;
    }

    async getWindowEntries(key: string, windowStart: number): Promise<number[]> {
        const entry = this.windows.get(key);
        if (!entry || entry.expiresAt <= Date.now()) return [];
        return entry.timestamps.filter(t => t >= windowStart);
    }

    destroy(): void {
        clearInterval(this.interval);
        this.counters.clear();
        this.windows.clear();
    }

    private cleanup(): void {
        const now = Date.now();
        for (const [k, v] of Array.from(this.counters.entries())) {
            if (v.expiresAt <= now) this.counters.delete(k);
        }
        for (const [k, v] of Array.from(this.windows.entries())) {
            if (v.expiresAt <= now) this.windows.delete(k);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários internos
// ─────────────────────────────────────────────────────────────────────────────

function getHeader(
    headers: Record<string, string | string[] | undefined>,
    name: string,
): string | undefined {
    const val = headers[name.toLowerCase()];
    if (!val) return undefined;
    return Array.isArray(val) ? val[0] : val;
}

/** Extrai IP real da requisição. */
function extractIP(headers: Record<string, string | string[] | undefined>): string {
    const cf = headers['cf-connecting-ip'];
    if (typeof cf === 'string') return cf.split(',')[0].trim();

    const real = headers['x-real-ip'];
    if (typeof real === 'string') return real.trim();

    const fwd = headers['x-forwarded-for'];
    if (fwd) {
        const raw = Array.isArray(fwd) ? fwd[0] : fwd;
        return raw.split(',')[0].trim();
    }

    return '0.0.0.0';
}

/** Hash djb2 para anonimizar chaves nos logs. */
function hashKey(value: string): string {
    let hash = 5381;
    for (let i = 0; i < value.length; i++) {
        hash = ((hash << 5) + hash) ^ value.charCodeAt(i);
        hash = hash >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
}

/** Sanitiza string para uso seguro em chaves de store. */
function sanitizeKey(value: string): string {
    return value.replace(/[^a-zA-Z0-9._\-:@]/g, '_').slice(0, 128);
}

/** Constrói o identificador para uma dimensão. */
async function resolveIdentifier(
    req: RateLimitRequest,
    rule: RateLimitRule,
): Promise<string> {
    if (rule.keyResolver) {
        return sanitizeKey(await rule.keyResolver(req));
    }

    const dimension = rule.dimension ?? 'ip';

    switch (dimension) {
        case 'ip':
            return sanitizeKey(req.ip || extractIP(req.headers));
        case 'user':
            return sanitizeKey(req.userId ?? req.ip ?? '0.0.0.0');
        case 'api-key':
            return sanitizeKey(
                req.apiKey ??
                getHeader(req.headers, 'x-api-key') ??
                req.ip ?? '0.0.0.0',
            );
        case 'tenant':
            return sanitizeKey(
                req.tenantId ??
                getHeader(req.headers, 'x-tenant-id') ??
                req.ip ?? '0.0.0.0',
            );
        case 'combined':
            return sanitizeKey(
                `${req.ip ?? '0.0.0.0'}:${req.userId ?? 'anon'}`,
            );
        case 'global':
            return 'global';
        case 'endpoint':
            return sanitizeKey(`${req.method}:${req.path}`);
        default:
            return sanitizeKey(req.ip ?? '0.0.0.0');
    }
}

/** Monta headers de rate limit conforme RFC e Draft IETF. */
function buildHeaders(
    limit: number,
    remaining: number,
    resetAt: number,
    windowMs: number,
    retryAfterSeconds?: number,
): RateLimitHeaders {
    const resetSeconds = Math.ceil(resetAt / 1000);
    const windowSeconds = Math.ceil(windowMs / 1000);
    const headers: RateLimitHeaders = {
        'RateLimit-Limit': String(limit),
        'RateLimit-Remaining': String(Math.max(0, remaining)),
        'RateLimit-Reset': String(resetSeconds),
        'RateLimit-Policy': `${limit};w=${windowSeconds}`,
    };

    if (retryAfterSeconds !== undefined) {
        headers['Retry-After'] = String(Math.ceil(retryAfterSeconds));
    }

    return headers;
}

// ─────────────────────────────────────────────────────────────────────────────
// Algoritmos de rate limiting
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fixed Window — janela fixa simples.
 *
 * Prós: mínimo de storage (1 counter por IP), reset previsível.
 * Contras: burst no boundary da janela (2× o limite em 1ms).
 *
 * Caso de uso: limites globais onde a precisão no boundary não é crítica.
 */
async function fixedWindow(
    store: RateLimitStore,
    key: string,
    rule: RateLimitRule,
    cost: number,
    now: number,
): Promise<{ count: number; resetAt: number; windowMs: number }> {
    const windowMs = rule.windowMs;
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const resetAt = windowStart + windowMs;
    const storeKey = `fw:${key}:${Math.floor(now / windowMs)}`;

    let count: number;
    if (cost === 1) {
        count = await store.increment(storeKey, windowMs + 1000);
    } else {
        const current = (await store.get(storeKey)) ?? 0;
        count = current + cost;
        await store.set(storeKey, count, resetAt - now + 1000);
    }

    return { count, resetAt, windowMs };
}

/**
 * Sliding Window — janela deslizante precisa.
 *
 * Prós: sem burst no boundary, mais preciso que fixed window.
 * Contras: maior overhead (armazena lista de timestamps ou usa dois contadores).
 *
 * Implementação com dois contadores (fixed window duplo):
 * approximation = count_current + count_previous × (1 - elapsed/window)
 *
 * Esta aproximação é usada pelo Redis e por Cloudflare — é precisa o suficiente
 * para rate limiting de segurança sem o overhead de armazenar todos os timestamps.
 */
async function slidingWindow(
    store: RateLimitStore,
    key: string,
    rule: RateLimitRule,
    cost: number,
    now: number,
): Promise<{ count: number; resetAt: number; windowMs: number }> {
    const windowMs = rule.windowMs;
    const currentWindow = Math.floor(now / windowMs);
    const windowStart = currentWindow * windowMs;
    const elapsed = now - windowStart;
    const prevWeight = 1 - (elapsed / windowMs);
    const resetAt = windowStart + windowMs;

    const currKey = `sw:curr:${key}:${currentWindow}`;
    const prevKey = `sw:prev:${key}:${currentWindow - 1}`;

    // Incrementa janela atual
    const currCount = await store.increment(currKey, windowMs * 2);
    const prevCount = (await store.get(prevKey)) ?? 0;

    // Aproximação da janela deslizante
    const approximateCount = Math.ceil(prevCount * prevWeight) + currCount;

    // Se custo > 1, ajusta o contador
    if (cost > 1) {
        await store.set(currKey, currCount + (cost - 1), windowMs * 2);
    }

    return {
        count: approximateCount + (cost - 1),
        resetAt,
        windowMs,
    };
}

/**
 * Token Bucket — burst natural com reposição gradual.
 *
 * Prós: permite burst legítimo (usuário abre várias abas), mais justo.
 * Contras: mais complexo, dois valores no store por IP.
 *
 * Funcionamento:
 *  - Bucket começa cheio (burstLimit tokens)
 *  - Cada requisição consome `cost` tokens
 *  - Tokens são repostos à taxa de limit/windowMs por ms
 *  - Quando vazio, rejeita até ter tokens suficientes
 *
 * Caso de uso ideal: APIs interativas onde picos de cliques são legítimos.
 */
async function tokenBucket(
    store: RateLimitStore,
    key: string,
    rule: RateLimitRule,
    cost: number,
    now: number,
): Promise<{ count: number; resetAt: number; windowMs: number; tokensLeft: number }> {
    const capacity = rule.burstLimit ?? rule.limit;
    const refillRateMs = capacity / rule.windowMs; // tokens por ms
    const tokensKey = `tb:tokens:${key}`;
    const lastRefillKey = `tb:last:${key}`;
    const ttl = rule.windowMs * 2;

    const [currentTokens, lastRefill] = await Promise.all([
        store.get(tokensKey),
        store.get(lastRefillKey),
    ]);

    const tokens = currentTokens ?? capacity;
    const last = lastRefill ?? now;
    const elapsed = now - last;
    const refilled = elapsed * refillRateMs;
    const newTokens = Math.min(capacity, tokens + refilled);

    // Calcula quando haverá tokens suficientes para o custo
    const deficit = cost - newTokens;
    const resetAt = deficit > 0
        ? now + Math.ceil(deficit / refillRateMs)
        : now + Math.ceil((capacity - (newTokens - cost)) / refillRateMs);

    if (newTokens < cost) {
        // Não tem tokens — não consume, retorna estado atual
        await Promise.all([
            store.set(tokensKey, newTokens, ttl),
            store.set(lastRefillKey, now, ttl),
        ]);
        return {
            count: rule.limit + 1,  // sinaliza excedido
            resetAt,
            windowMs: rule.windowMs,
            tokensLeft: Math.floor(newTokens),
        };
    }

    const consumed = newTokens - cost;
    await Promise.all([
        store.set(tokensKey, consumed, ttl),
        store.set(lastRefillKey, now, ttl),
    ]);

    return {
        count: rule.limit - Math.floor(consumed / (1 / refillRateMs / rule.limit)),
        resetAt,
        windowMs: rule.windowMs,
        tokensLeft: Math.floor(consumed),
    };
}

/**
 * Leaky Bucket — taxa constante de saída.
 *
 * Prós: suaviza bursts completamente, taxa de saída garantida.
 * Contras: pode acumular fila, primeira requisição pode ser atrasada.
 *
 * Funcionamento:
 *  - Bucket tem capacidade máxima (limit)
 *  - Água "escoa" a leakRate por segundo
 *  - Novos requests adicionam água (cost)
 *  - Se bucket transbordar, rejeita
 *
 * Caso de uso: proteção de APIs downstream com taxa máxima garantida.
 */
async function leakyBucket(
    store: RateLimitStore,
    key: string,
    rule: RateLimitRule,
    cost: number,
    now: number,
): Promise<{ count: number; resetAt: number; windowMs: number }> {
    const capacity = rule.limit;
    const leakRate = rule.leakRatePerSecond ?? (capacity / (rule.windowMs / 1000));
    const leakRateMs = leakRate / 1000;
    const levelKey = `lb:level:${key}`;
    const lastKey = `lb:last:${key}`;
    const ttl = rule.windowMs * 2;

    const [level, lastTime] = await Promise.all([
        store.get(levelKey),
        store.get(lastKey),
    ]);

    const currentLevel = level ?? 0;
    const last = lastTime ?? now;
    const elapsed = now - last;
    const leaked = elapsed * leakRateMs;
    const newLevel = Math.max(0, currentLevel - leaked);
    const afterCost = newLevel + cost;

    const resetAt = afterCost > capacity
        ? now + Math.ceil((afterCost - capacity) / leakRateMs)
        : now + Math.ceil(afterCost / leakRateMs);

    await Promise.all([
        store.set(levelKey, Math.min(capacity, afterCost), ttl),
        store.set(lastKey, now, ttl),
    ]);

    return {
        count: Math.ceil(afterCost),
        resetAt,
        windowMs: rule.windowMs,
    };
}

/**
 * Concurrent Limit — limite de requisições simultâneas.
 *
 * Diferente dos outros algoritmos, não conta requisições por janela
 * mas sim quantas estão em processamento agora.
 *
 * Requer que o caller chame `releaseConcurrentSlot()` ao finalizar.
 *
 * Caso de uso: uploads, processamentos pesados, websockets.
 */
async function concurrentLimit(
    store: RateLimitStore,
    key: string,
    rule: RateLimitRule,
    now: number,
): Promise<{ count: number; resetAt: number; windowMs: number; slotKey: string }> {
    const timeout = rule.concurrentTimeoutMs ?? 30_000;
    const countKey = `cl:count:${key}`;
    const count = await store.increment(countKey, timeout);
    const resetAt = now + timeout;

    return {
        count,
        resetAt,
        windowMs: timeout,
        slotKey: countKey,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class RateLimiter {
    private readonly config: Required<
        Omit<RateLimitConfig, 'onLimitReached' | 'onRequest'>
    > & Pick<RateLimitConfig, 'onLimitReached' | 'onRequest'>;

    constructor(config: RateLimitConfig) {
        this.config = {
            defaultRules: [
                { limit: 100, windowMs: 60_000, algorithm: 'sliding-window', dimension: 'ip' },
            ],
            routeRules: {},
            skip: [],
            keyPrefix: 'rl',
            onStoreError: 'open',
            sendHeaders: true,
            debug: false,
            onLimitReached: undefined,
            onRequest: undefined,
            ...config,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Avaliação principal
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica se uma requisição está dentro dos limites configurados.
     *
     * Aplica todas as regras aplicáveis e retorna o resultado mais restritivo.
     * Se qualquer regra for violada, retorna o bloqueio.
     */
    async check(req: RateLimitRequest): Promise<RateLimitResult> {
        const now = Date.now();
        const path = req.path;
        const ip = req.ip || extractIP(req.headers);
        req.ip = ip;

        // ── Verifica skip ────────────────────────────────────────────────
        for (const skipRule of this.config.skip) {
            if (typeof skipRule === 'string') {
                if (ip === skipRule) return this.buildAllowResult(req, now);
            } else {
                if (await skipRule(req)) return this.buildAllowResult(req, now);
            }
        }

        // ── Determina regras aplicáveis ──────────────────────────────────
        const rules = this.resolveRules(path);
        if (rules.length === 0) return this.buildAllowResult(req, now);

        // ── Avalia cada regra ────────────────────────────────────────────
        let mostRestrictiveResult: RateLimitResult | null = null;

        for (const rule of rules) {
            // Verifica condição da regra
            if (rule.condition) {
                const applies = await rule.condition(req);
                if (!applies) continue;
            }

            let result: RateLimitResult;
            try {
                result = await this.applyRule(req, rule, now);
            } catch (err) {
                this.debugLog('STORE-ERROR', err);

                if (this.config.onStoreError === 'closed') {
                    return this.buildBlockResult(req, rule, now, 'store-error');
                }
                continue; // fail open — tenta próxima regra
            }

            this.config.onRequest?.(result, req);

            if (!result.allowed) {
                void this.config.onLimitReached?.(result, req);
                this.debugLog('LIMIT-REACHED', ip, path, result.meta.key, result.remaining);

                // Retorna o resultado mais restritivo (menor remaining)
                if (!mostRestrictiveResult || result.remaining < mostRestrictiveResult.remaining) {
                    mostRestrictiveResult = result;
                }
            }
        }

        return mostRestrictiveResult ?? this.buildAllowResult(req, now);
    }

    /**
     * Aplica uma regra específica à requisição.
     */
    private async applyRule(
        req: RateLimitRequest,
        rule: RateLimitRule,
        now: number,
    ): Promise<RateLimitResult> {
        const algorithm = rule.algorithm ?? 'sliding-window';
        const dimension = rule.dimension ?? 'ip';
        const cost = req.cost ?? rule.costResolver?.(req) ?? rule.cost ?? 1;
        const limit = rule.limit;

        const identifier = await resolveIdentifier(req, rule);
        const storeKey = `${this.config.keyPrefix}:${algorithm}:${identifier}`;

        let count: number;
        let resetAt: number;
        let windowMs: number;
        let tokensLeft: number | undefined;

        switch (algorithm) {
            case 'fixed-window': {
                const r = await fixedWindow(this.config.store, storeKey, rule, cost, now);
                count = r.count; resetAt = r.resetAt; windowMs = r.windowMs;
                break;
            }
            case 'sliding-window': {
                const r = await slidingWindow(this.config.store, storeKey, rule, cost, now);
                count = r.count; resetAt = r.resetAt; windowMs = r.windowMs;
                break;
            }
            case 'token-bucket': {
                const r = await tokenBucket(this.config.store, storeKey, rule, cost, now);
                count = r.count; resetAt = r.resetAt; windowMs = r.windowMs;
                tokensLeft = r.tokensLeft;
                break;
            }
            case 'leaky-bucket': {
                const r = await leakyBucket(this.config.store, storeKey, rule, cost, now);
                count = r.count; resetAt = r.resetAt; windowMs = r.windowMs;
                break;
            }
            case 'concurrent': {
                const r = await concurrentLimit(this.config.store, storeKey, rule, now);
                count = r.count; resetAt = r.resetAt; windowMs = r.windowMs;
                break;
            }
            default:
                throw new Error(`[rate-limit] Algoritmo desconhecido: ${algorithm}`);
        }

        const allowed = count <= limit;
        const remaining = tokensLeft ?? Math.max(0, limit - count);
        const retryAfterSec = allowed ? 0 : Math.ceil((resetAt - now) / 1000);

        const headers = buildHeaders(limit, remaining, resetAt, windowMs,
            allowed ? undefined : retryAfterSec);

        const meta: RateLimitMeta = {
            key: hashKey(storeKey),  // anonimizado para logs
            dimension,
            endpoint: req.path,
            method: req.method,
            timestamp: now,
            identifier: hashKey(identifier),
        };

        // Modo dry-run — registra mas não bloqueia
        const effectiveAllowed = allowed || rule.action === 'dry-run';

        this.debugLog(effectiveAllowed ? 'OK' : 'BLOCKED', identifier, `${count}/${limit}`, algorithm);

        return {
            allowed: effectiveAllowed,
            algorithm,
            dimension,
            limit,
            remaining,
            resetAt,
            retryAfterSeconds: retryAfterSec,
            headers,
            meta,
        };
    }

    /**
     * Libera um slot concorrente após o processamento da requisição.
     * OBRIGATÓRIO quando usando o algoritmo 'concurrent'.
     *
     * @example
     * const result = await rateLimiter.check(req);
     * try {
     *   await handler(req, res);
     * } finally {
     *   if (result.algorithm === 'concurrent') {
     *     await rateLimiter.releaseConcurrentSlot(req, rule);
     *   }
     * }
     */
    async releaseConcurrentSlot(req: RateLimitRequest, rule: RateLimitRule): Promise<void> {
        const identifier = await resolveIdentifier(req, rule);
        const storeKey = `${this.config.keyPrefix}:concurrent:cl:count:${identifier}`;
        const current = await this.config.store.get(storeKey);

        if (current && current > 0) {
            await this.config.store.set(storeKey, current - 1,
                rule.concurrentTimeoutMs ?? 30_000);
        }
    }

    /**
     * Reseta o contador de um identificador específico.
     * Use para reverter penalizações manuais ou em testes.
     */
    async reset(identifier: string, rule: RateLimitRule): Promise<void> {
        const algorithm = rule.algorithm ?? 'sliding-window';
        const key = sanitizeKey(identifier);
        const prefix = this.config.keyPrefix;

        const keysToDelete = [
            `${prefix}:${algorithm}:${key}`,
            `${prefix}:tb:tokens:${key}`,
            `${prefix}:tb:last:${key}`,
            `${prefix}:lb:level:${key}`,
            `${prefix}:lb:last:${key}`,
        ];

        await Promise.all(keysToDelete.map(k => this.config.store.delete(k)));
        this.debugLog('RESET', identifier);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários
    // ─────────────────────────────────────────────────────────────────────────

    /** Resolve as regras para um path específico. */
    private resolveRules(path: string): RateLimitRule[] {
        // Procura match exato primeiro, depois prefixo
        for (const [routePattern, rules] of Object.entries(this.config.routeRules ?? {})) {
            if (path === routePattern || path.startsWith(routePattern + '/')) {
                return rules;
            }
        }
        return this.config.defaultRules ?? [];
    }

    private buildAllowResult(req: RateLimitRequest, now: number): RateLimitResult {
        return {
            allowed: true,
            algorithm: 'sliding-window',
            dimension: 'ip',
            limit: Infinity,
            remaining: Infinity,
            resetAt: now + 60_000,
            retryAfterSeconds: 0,
            headers: buildHeaders(Infinity, Infinity, now + 60_000, 60_000),
            meta: {
                key: 'skip', dimension: 'ip',
                endpoint: req.path, method: req.method, timestamp: now,
            },
        };
    }

    private buildBlockResult(
        req: RateLimitRequest,
        rule: RateLimitRule,
        now: number,
        reason: string,
    ): RateLimitResult {
        const resetAt = now + rule.windowMs;
        return {
            allowed: false,
            algorithm: rule.algorithm ?? 'sliding-window',
            dimension: rule.dimension ?? 'ip',
            limit: rule.limit,
            remaining: 0,
            resetAt,
            retryAfterSeconds: Math.ceil(rule.windowMs / 1000),
            headers: buildHeaders(rule.limit, 0, resetAt, rule.windowMs,
                Math.ceil(rule.windowMs / 1000)),
            meta: {
                key: reason, dimension: rule.dimension ?? 'ip',
                endpoint: req.path, method: req.method, timestamp: now,
            },
        };
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[rate-limit]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

type ExpressReq = {
    ip?: string; method: string; path: string;
    headers: Record<string, string | string[] | undefined>;
    user?: { id?: string; isPremium?: boolean };
};
type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    json(d: unknown): void;
    end(): void;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware Rate Limit para Express.
 *
 * Injeta `req.rateLimitResult` para uso nos handlers.
 *
 * @example
 * // Aplicação global
 * app.use(createExpressRateLimit(rateLimiter));
 *
 * // Por rota específica
 * app.post('/api/auth/login',
 *   createExpressRateLimit(loginLimiter),
 *   loginHandler,
 * );
 */
export function createExpressRateLimit(limiter: RateLimiter) {
    return async (
        req: ExpressReq & { rateLimitResult?: RateLimitResult },
        res: ExpressRes,
        next: NextFn,
    ): Promise<void> => {
        const rateLimitReq: RateLimitRequest = {
            ip: req.ip || '127.0.0.1',
            method: req.method,
            path: req.path,
            headers: req.headers,
            userId: req.user?.id,
        };

        const result = await limiter.check(rateLimitReq);
        req.rateLimitResult = result;

        if (limiter['config'].sendHeaders) {
            res.set(headersToRecord(result.headers));
        }

        if (!result.allowed) {
            res
                .status(429)
                .set({
                    'Content-Type': 'application/json',
                    'X-Content-Type-Options': 'nosniff',
                    'Cache-Control': 'no-store',
                })
                .json({
                    error: 'Too Many Requests',
                    message: 'Rate limit exceeded. Please try again later.',
                    retryAfter: result.retryAfterSeconds,
                });
            return;
        }

        next();
    };
}

/**
 * Handler Rate Limit para Next.js Edge Runtime.
 *
 * Retorna `Response` se bloqueado ou `null` para continuar.
 *
 * @example
 * // middleware.ts
 * const rl = createNextRateLimit(rateLimiter);
 * export default async function middleware(request: Request) {
 *   const blocked = await rl(request);
 *   if (blocked) return blocked;
 *   return NextResponse.next();
 * }
 */
export function createNextRateLimit(limiter: RateLimiter) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => { headers[key] = value; });

        const url = new URL(request.url);
        const result = await limiter.check({
            ip: headers['cf-connecting-ip'] ?? headers['x-real-ip'] ?? '0.0.0.0',
            method: request.method,
            path: url.pathname,
            headers,
        });

        if (!result.allowed) {
            const respHeaders: Record<string, string> = {
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff',
                'Cache-Control': 'no-store',
                ...headersToRecord(result.headers),
            };

            return new Response(
                JSON.stringify({
                    error: 'Too Many Requests',
                    message: 'Rate limit exceeded. Please try again later.',
                    retryAfter: result.retryAfterSeconds,
                }),
                { status: 429, headers: respHeaders },
            );
        }

        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factories com preset
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria um rate limiter com configuração padrão balanceada para produção.
 *
 * Inclui limites diferenciados para rotas de autenticação, APIs e
 * endpoints públicos.
 *
 * @example
 * const limiter = createDefaultRateLimiter(redisStore, {
 *   onLimitReached: (result, req) => {
 *     ipFilter.reportViolation(req.ip!, 'RATE_LIMIT_EXCEEDED');
 *   },
 * });
 */
export function createDefaultRateLimiter(
    store: RateLimitStore,
    overrides: Partial<RateLimitConfig> = {},
): RateLimiter {
    return new RateLimiter({
        store,
        keyPrefix: 'rl',
        sendHeaders: true,
        onStoreError: 'open',

        defaultRules: [
            {
                name: 'global-ip',
                limit: 100,
                windowMs: 60_000,
                algorithm: 'sliding-window',
                dimension: 'ip',
            },
        ],

        routeRules: {
            // ── Autenticação — mais restritivo para prevenir brute force ──
            '/api/auth/login': [
                {
                    name: 'login-ip',
                    limit: 5,
                    windowMs: 60_000,
                    algorithm: 'sliding-window',
                    dimension: 'ip',
                },
                {
                    name: 'login-global',
                    limit: 100,
                    windowMs: 60_000,
                    algorithm: 'fixed-window',
                    dimension: 'global',
                },
            ],
            '/api/auth/register': [
                { name: 'register-ip', limit: 3, windowMs: 60_000, algorithm: 'sliding-window', dimension: 'ip' },
            ],
            '/api/auth/forgot-password': [
                { name: 'forgot-ip', limit: 3, windowMs: 300_000, algorithm: 'sliding-window', dimension: 'ip' },
            ],
            '/api/auth/reset-password': [
                { name: 'reset-ip', limit: 3, windowMs: 300_000, algorithm: 'sliding-window', dimension: 'ip' },
            ],
            '/api/auth/otp': [
                { name: 'otp-ip', limit: 5, windowMs: 60_000, algorithm: 'sliding-window', dimension: 'ip' },
            ],
            '/api/auth/2fa': [
                { name: '2fa-ip', limit: 5, windowMs: 60_000, algorithm: 'sliding-window', dimension: 'ip' },
            ],

            // ── Payments — burst natural com token bucket ─────────────────
            '/api/payments': [
                {
                    name: 'payment-user',
                    limit: 10,
                    windowMs: 60_000,
                    algorithm: 'token-bucket',
                    burstLimit: 3,    // máximo 3 pagamentos em burst
                    dimension: 'user',
                },
            ],
            '/api/checkout': [
                { name: 'checkout-ip', limit: 15, windowMs: 60_000, algorithm: 'sliding-window', dimension: 'ip' },
            ],

            // ── API pública — leaky bucket para proteger downstream ───────
            '/api/search': [
                { name: 'search-ip', limit: 30, windowMs: 60_000, algorithm: 'leaky-bucket', dimension: 'ip' },
            ],

            // ── Exports — custo alto por operação ────────────────────────
            '/api/export': [
                {
                    name: 'export-user',
                    limit: 3,
                    windowMs: 300_000,
                    algorithm: 'token-bucket',
                    cost: 10,    // cada export custa 10 tokens
                    dimension: 'user',
                },
            ],

            // ── GraphQL — limite por usuário para evitar batch abuse ──────
            '/api/graphql': [
                {
                    name: 'graphql-user',
                    limit: 200,
                    windowMs: 60_000,
                    algorithm: 'sliding-window',
                    dimension: 'user',
                },
                {
                    name: 'graphql-ip',
                    limit: 100,
                    windowMs: 60_000,
                    algorithm: 'sliding-window',
                    dimension: 'ip',
                    condition: (req) => !req.userId, // só aplica para anônimos
                },
            ],

            // ── Upload — limite concorrente ───────────────────────────────
            '/api/upload': [
                {
                    name: 'upload-concurrent',
                    limit: 3,
                    windowMs: 60_000,
                    algorithm: 'concurrent',
                    concurrentTimeoutMs: 120_000, // 2 minutos para upload
                    dimension: 'user',
                },
            ],

            // ── Webhooks — mais permissivo (chamados por sistemas externos)
            '/api/webhooks': [
                { name: 'webhook-ip', limit: 500, windowMs: 60_000, algorithm: 'fixed-window', dimension: 'ip' },
            ],

            // ── Admin — restritivo por usuário ────────────────────────────
            '/api/admin': [
                { name: 'admin-user', limit: 200, windowMs: 60_000, algorithm: 'sliding-window', dimension: 'user' },
            ],
        },

        skip: [
            '127.0.0.1',
            '::1',
        ],

        ...overrides,
    });
}

/**
 * Rate limiter para API key B2B.
 * Limites mais altos, por chave em vez de IP.
 *
 * @example
 * const apiLimiter = createAPIKeyRateLimiter(store, {
 *   '/api/v1': [{ limit: 1000, windowMs: 60_000, dimension: 'api-key' }]
 * });
 */
export function createAPIKeyRateLimiter(
    store: RateLimitStore,
    routeRules?: Record<string, RateLimitRule[]>,
): RateLimiter {
    return new RateLimiter({
        store,
        keyPrefix: 'rl:api',
        defaultRules: [
            {
                name: 'api-key-default',
                limit: 1_000,
                windowMs: 60_000,
                algorithm: 'token-bucket',
                burstLimit: 100,
                dimension: 'api-key',
            },
        ],
        routeRules: routeRules ?? {},
    });
}

/**
 * Rate limiter para multi-tenant SaaS.
 * Cada tenant tem seu próprio bucket de limite.
 *
 * @example
 * const tenantLimiter = createTenantRateLimiter(store);
 */
export function createTenantRateLimiter(
    store: RateLimitStore,
    defaultLimitPerTenant = 5_000,
): RateLimiter {
    return new RateLimiter({
        store,
        keyPrefix: 'rl:tenant',
        defaultRules: [
            {
                name: 'tenant-default',
                limit: defaultLimitPerTenant,
                windowMs: 60_000,
                algorithm: 'sliding-window',
                dimension: 'tenant',
            },
        ],
    });
}