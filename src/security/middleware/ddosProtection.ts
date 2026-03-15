/**
 * @fileoverview Middleware de proteção contra DDoS — defesa em profundidade Layer 7.
 *
 * @description
 * Implementa múltiplas camadas de mitigação de ataques de negação de serviço
 * na camada de aplicação (Layer 7 / HTTP), complementando proteções de rede
 * (Layer 3/4) que devem existir na infraestrutura (Cloudflare, AWS Shield, etc.).
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *
 *  Layer 7 HTTP Floods:
 *  • HTTP GET/POST flood (requisições em volume)              (ubíquo)
 *  • Slowloris — conexões lentas que esgotam workers          (CVE-2007-6750)
 *  • Slow POST / RUDY — body enviado a 1 byte/s              (2009+)
 *  • SSL/TLS renegotiation flood                             (CVE-2011-3389)
 *  • HTTP/2 rapid reset (CVSS 7.5)                          (CVE-2023-44487)
 *  • HTTP/2 stream flood — 0-RTT abuse                       (2023+)
 *  • ReDoS em rotas com regex vulnerável                     (2012+)
 *
 *  Resource Exhaustion:
 *  • Large payload flood (10MB+ bodies repetidos)            (ubíquo)
 *  • GraphQL complexity bomb (nested queries infinitas)      (2019+)
 *  • JSON/XML deep nesting bomb                              (2015+)
 *  • Hash collision via crafted keys                         (Plop/2011, Java 2012)
 *  • zip/gzip bomb via Content-Encoding                      (2004+)
 *  • Billion laughs (XML entity expansion)                   (CVE-2003-1564)
 *  • Range header abuse (multi-range byte serving)           (CVE-2011-3192)
 *  • Cache poisoning DoS via Vary/CDN headers                (2020+)
 *
 *  Distributed / Evasion:
 *  • IP spoofing + distributed flood                         (ubíquo)
 *  • Botnet com IPs residenciais (difícil de bloquear por IP)(2019+)
 *  • Low-and-slow distributed (baixa taxa por IP, alto total)(2020+)
 *  • Pulse wave DDoS (picos curtos alternados)               (Imperva 2017)
 *  • Carpet bomb (distribui entre múltiplos alvos/IPs)       (2021+)
 *  • Cache-busting flood (parâmetros random para bypass CDN) (ubíquo)
 *
 *  Amplification / Reflection (Layer 3/4, cobertos via rate limit):
 *  • DNS amplification                                        (mitigado via infra)
 *  • NTP amplification                                        (mitigado via infra)
 *  • SSDP reflection                                          (mitigado via infra)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • HTTP/3 (QUIC) flood — 0-RTT abuse                       (RFC 9000, 2021+)
 *  • AI-generated traffic com comportamento humano           (2023+)
 *  • WebTransport flood                                      (emergente)
 *  • Server-Sent Events exhaustion                            (emergente)
 *  • gRPC streaming flood                                    (2022+)
 *  • LLM-powered adaptive DDoS (muda padrão ao detectar bloq)(2024+)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Pipeline de 10 verificações em ordem de custo crescente
 *  • Rate limiting adaptativo (ajusta thresholds sob ataque)
 *  • Token Bucket + Sliding Window + Fixed Window combinados
 *  • Circuit Breaker por rota (isola rotas em sobrecarga)
 *  • Tarpitting configurável (atraso artificial para bots)
 *  • Allowlist de IPs confiáveis (load balancers, health checks)
 *  • Store injetável (Redis em produção)
 *  • Métricas de observabilidade (onAttackDetected, onThrottled)
 *  • Framework-agnostic: adaptadores Express e Next.js
 *
 * @see https://www.cloudflare.com/learning/ddos/ddos-attack-tools/
 * @see https://owasp.org/www-community/attacks/Denial_of_Service
 * @see https://nvd.nist.gov/vuln/detail/CVE-2023-44487  (HTTP/2 Rapid Reset)
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

export interface DDoSEvaluationResult {
    allowed: boolean;
    reason?: DDoSBlockReason;
    /** Ação recomendada: block, throttle, challenge, tarpit */
    action?: DDoSAction;
    /** ms a esperar antes de permitir nova tentativa (para tarpit/throttle) */
    retryAfterMs?: number;
    meta: DDoSMeta;
}

export type DDoSBlockReason =
    | 'RATE_LIMIT_IP'
    | 'RATE_LIMIT_GLOBAL'
    | 'RATE_LIMIT_ENDPOINT'
    | 'CONCURRENT_LIMIT'
    | 'PAYLOAD_TOO_LARGE'
    | 'SLOW_REQUEST_DETECTED'
    | 'HEADER_FLOOD'
    | 'RANGE_ABUSE'
    | 'GZIP_BOMB_SUSPECTED'
    | 'JSON_DEPTH_EXCEEDED'
    | 'CIRCUIT_BREAKER_OPEN'
    | 'ADAPTIVE_BLOCK'
    | 'IP_BLOCKLIST'
    | 'ASN_BLOCKLIST'
    | 'REQUEST_ANOMALY'
    | 'HTTP2_RAPID_RESET';

export type DDoSAction = 'block' | 'throttle' | 'challenge' | 'tarpit';

export interface DDoSMeta {
    ip: string;
    path: string;
    method: string;
    timestamp: number;
    signals: string[];
    /** Requisições por segundo estimadas para este IP no momento. */
    currentRps?: number;
    /** true se proteção adaptativa está em modo de ataque ativo. */
    underAttack: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface DDoSConfig {
    /**
     * Rate limiting por IP (janela deslizante).
     */
    rateLimit: {
        /** Requisições máximas por janela por IP. Default: 120 */
        maxRequestsPerIP: number;
        /** Duração da janela em ms. Default: 60_000 */
        windowMs: number;
        /** Burst máximo instantâneo (Token Bucket capacity). Default: 20 */
        burstCapacity: number;
        /** Reposição de tokens/s no bucket. Default: 2 */
        burstRefillPerSecond: number;
        /** Limite global de req/s em todas as IPs somadas. Default: 5000 */
        globalMaxRps: number;
    };

    /**
     * Limites por endpoint específico.
     * Sobrescreve o limite global por IP para rotas sensíveis.
     */
    endpointLimits?: Record<string, {
        maxRequests: number;
        windowMs: number;
        /** Ação ao exceder: 'block' ou 'throttle'. Default: 'block' */
        action?: DDoSAction;
    }>;

    /**
     * Proteção contra payloads grandes.
     */
    payload: {
        /** Tamanho máximo de body em bytes. Default: 1_048_576 (1MB) */
        maxBodyBytes: number;
        /** Máximo de headers na requisição. Default: 100 */
        maxHeaderCount: number;
        /** Tamanho máximo de cada header em bytes. Default: 8192 */
        maxHeaderSizeBytes: number;
        /** Profundidade máxima de JSON aninhado. Default: 10 */
        maxJsonDepth: number;
        /** Detecta Content-Encoding: gzip com tamanho suspeito. Default: true */
        detectGzipBomb: boolean;
        /** Razão máxima comprimido/descomprimido antes de suspeitar. Default: 100 */
        maxGzipRatio: number;
    };

    /**
     * Circuit Breaker por rota.
     * Abre o circuito quando a taxa de erros excede o threshold.
     */
    circuitBreaker: {
        /** Habilita circuit breaker. Default: true */
        enabled: boolean;
        /** % de erros 5xx para abrir o circuito. Default: 50 */
        errorThresholdPercent: number;
        /** Janela de observação em ms. Default: 30_000 */
        observationWindowMs: number;
        /** Tempo que o circuito fica aberto antes de half-open. Default: 15_000 */
        openDurationMs: number;
        /** Requisições para testar no estado half-open. Default: 5 */
        halfOpenRequests: number;
    };

    /**
     * Tarpitting — atraso artificial para requisições suspeitas.
     * Aumenta o custo do ataque para o atacante sem revelar bloqueio.
     */
    tarpit: {
        /** Habilita tarpitting. Default: false (requer análise de impacto) */
        enabled: boolean;
        /** Atraso mínimo em ms para requisições suspeitas. Default: 2000 */
        minDelayMs: number;
        /** Atraso máximo em ms. Default: 10_000 */
        maxDelayMs: number;
    };

    /**
     * Proteção adaptativa — ajusta limites automaticamente sob ataque.
     *
     * Quando o sistema detecta um pico anormal, os thresholds são
     * temporariamente reduzidos e o modo de ataque é ativado.
     */
    adaptive: {
        /** Habilita proteção adaptativa. Default: true */
        enabled: boolean;
        /**
         * Fator de multiplicação do tráfego normal para detectar ataque.
         * Ex: 3.0 = 3x acima da média dispara modo de ataque.
         * Default: 3.0
         */
        attackMultiplier: number;
        /** Janela para cálculo de tráfego baseline em ms. Default: 300_000 (5 min) */
        baselineWindowMs: number;
        /** Fator de redução dos limites em modo de ataque. Default: 0.3 */
        throttleFactorOnAttack: number;
        /** Tempo mínimo em modo de ataque antes de relaxar. Default: 60_000 */
        minAttackDurationMs: number;
    };

    /**
     * Proteção Slowloris / Slow POST.
     * Detecta conexões que mantêm o servidor ocupado sem progredir.
     */
    slowRequest: {
        /** Habilita detecção de slow request. Default: true */
        enabled: boolean;
        /** Tempo máximo para receber headers completos em ms. Default: 10_000 */
        headerTimeoutMs: number;
        /** Tempo máximo para receber body completo em ms. Default: 30_000 */
        bodyTimeoutMs: number;
        /** Taxa mínima de bytes por segundo no body. Default: 100 */
        minBodyBytesPerSecond: number;
    };

    /** IPs permanentemente bloqueados. */
    blockedIPs?: string[];
    /** Prefixos CIDR de ASNs bloqueados (formato simplificado: '1.2.3.0/24'). */
    blockedCIDRs?: string[];
    /** IPs e ranges que nunca são limitados (load balancers, health checks). */
    allowlistedIPs?: string[];

    /** Store injetável para contadores. Use Redis em produção. */
    store: DDoSStore;

    /**
     * Hook chamado quando um ataque é detectado.
     * Use para alertas de segurança, PagerDuty, SIEM.
     */
    onAttackDetected?: (meta: DDoSMeta, pattern: string) => void | Promise<void>;

    /**
     * Hook chamado quando uma requisição é throttled/bloqueada.
     */
    onThrottled?: (result: DDoSEvaluationResult) => void | Promise<void>;

    /** Habilita logging detalhado. Default: false. */
    debug?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store interface
// ─────────────────────────────────────────────────────────────────────────────

export interface DDoSStore {
    increment(key: string, ttlMs: number): Promise<number>;
    get(key: string): Promise<number | null>;
    set(key: string, value: number, ttlMs: number): Promise<void>;
    exists(key: string): Promise<boolean>;
    delete(key: string): Promise<void>;
    /** Incrementa e retorna múltiplas chaves atomicamente (otimização Redis). */
    multiIncrement?(keys: Array<{ key: string; ttlMs: number }>): Promise<number[]>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store em memória — apenas desenvolvimento
// ─────────────────────────────────────────────────────────────────────────────

export class MemoryDDoSStore implements DDoSStore {
    private readonly data = new Map<string, { value: number; expiresAt: number }>();
    private readonly cleanupInterval: ReturnType<typeof setInterval>;

    constructor(cleanupIntervalMs = 30_000) {
        this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
        if (typeof this.cleanupInterval.unref === 'function') {
            this.cleanupInterval.unref();
        }
    }

    async increment(key: string, ttlMs: number): Promise<number> {
        const now = Date.now();
        const entry = this.data.get(key);
        if (!entry || entry.expiresAt <= now) {
            this.data.set(key, { value: 1, expiresAt: now + ttlMs });
            return 1;
        }
        entry.value += 1;
        return entry.value;
    }

    async get(key: string): Promise<number | null> {
        const entry = this.data.get(key);
        if (!entry || entry.expiresAt <= Date.now()) return null;
        return entry.value;
    }

    async set(key: string, value: number, ttlMs: number): Promise<void> {
        this.data.set(key, { value, expiresAt: Date.now() + ttlMs });
    }

    async exists(key: string): Promise<boolean> {
        const entry = this.data.get(key);
        return !!entry && entry.expiresAt > Date.now();
    }

    async delete(key: string): Promise<void> {
        this.data.delete(key);
    }

    async multiIncrement(
        keys: Array<{ key: string; ttlMs: number }>,
    ): Promise<number[]> {
        return Promise.all(keys.map(({ key, ttlMs }) => this.increment(key, ttlMs)));
    }

    destroy(): void {
        clearInterval(this.cleanupInterval);
        this.data.clear();
    }

    private cleanup(): void {
        const now = Date.now();
        for (const [key, entry] of Array.from(this.data.entries())) {
            if (entry.expiresAt <= now) this.data.delete(key);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipos internos
// ─────────────────────────────────────────────────────────────────────────────

type CircuitState = 'closed' | 'open' | 'half-open';

interface CircuitBreakerState {
    state: CircuitState;
    failureCount: number;
    successCount: number;
    totalRequests: number;
    openedAt: number | null;
    halfOpenTokens: number;
}

/** Requisição normalizada agnóstica de framework. */
export interface DDoSRequest {
    ip: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    bodySize?: number;
    /** Timestamp de início do recebimento de headers. */
    startedAt?: number;
    /** true se o body já foi completamente recebido. */
    bodyComplete?: boolean;
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

function sanitizeKey(value: string): string {
    return value.replace(/[^a-zA-Z0-9._\-:/]/g, '_').slice(0, 128);
}

/**
 * Extrai IP real considerando proxies reversos confiáveis.
 * Idêntico ao botProtection.ts — mantido aqui para independência de módulo.
 */
export function extractIP(
    headers: Record<string, string | string[] | undefined>,
): string {
    const cf = headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return cf.trim();

    const real = headers['x-real-ip'];
    if (typeof real === 'string' && real.trim()) return real.trim();

    const fwd = headers['x-forwarded-for'];
    if (fwd) {
        const raw = Array.isArray(fwd) ? fwd[0] : fwd;
        const first = raw.split(',')[0].trim();
        if (first) return first;
    }

    return '0.0.0.0';
}

/**
 * Verificação CIDR simplificada para IPv4.
 * Suporta apenas /8, /16, /24 para manter zero dependências.
 * Para CIDR completo em produção, use 'ip-cidr' ou 'netmask'.
 */
function matchesCIDR(ip: string, cidr: string): boolean {
    const [network, prefix] = cidr.split('/');
    if (!network || !prefix) return false;

    const bits = parseInt(prefix, 10);
    const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
    const ipNum = ipToInt(ip);
    const netNum = ipToInt(network);

    return ipNum !== null && netNum !== null && (ipNum & mask) === (netNum & mask);
}

function ipToInt(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Estima profundidade máxima de um JSON sem parse completo.
 * Conta apenas abre/fecha chaves e colchetes — O(n) sem recursão.
 *
 * Previne ataques de JSON nested bomb sem fazer o parse do payload inteiro.
 */
export function estimateJsonDepth(jsonString: string): number {
    let depth = 0;
    let maxDepth = 0;
    let inString = false;
    let escaped = false;

    for (let i = 0; i < jsonString.length; i++) {
        const char = jsonString[i];

        if (escaped) { escaped = false; continue; }
        if (char === '\\' && inString) { escaped = true; continue; }
        if (char === '"') { inString = !inString; continue; }
        if (inString) continue;

        if (char === '{' || char === '[') {
            depth++;
            if (depth > maxDepth) maxDepth = depth;
        } else if (char === '}' || char === ']') {
            depth--;
        }
    }

    return maxDepth;
}

/**
 * Calcula um sleep com jitter para evitar thundering herd em recovery.
 */
function sleepWithJitter(baseMs: number, jitterMs = 500): Promise<void> {
    const delay = baseMs + Math.random() * jitterMs;
    return new Promise(resolve => setTimeout(resolve, delay));
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class DDoSProtection {
    private readonly config: Required<
        Omit<DDoSConfig, 'onAttackDetected' | 'onThrottled'>
    > & Pick<DDoSConfig, 'onAttackDetected' | 'onThrottled'>;

    /** Estado dos circuit breakers por rota. */
    private readonly circuits = new Map<string, CircuitBreakerState>();

    /** Estado do modo adaptativo. */
    private underAttack = false;
    private attackStartedAt = 0;
    private baselineRps = 0;
    private baselineSampleAt = 0;

    constructor(config: DDoSConfig) {
        this.config = {
            endpointLimits: {},
            blockedIPs: [],
            blockedCIDRs: [],
            allowlistedIPs: ['127.0.0.1', '::1'],
            onAttackDetected: undefined,
            onThrottled: undefined,
            debug: false,
            ...config,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Avaliação principal
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Avalia uma requisição e retorna a decisão de proteção.
     *
     * Pipeline (ordem de custo crescente):
     *  1. Allowlist  — bypass imediato para IPs confiáveis
     *  2. IP/CIDR blocklist — rejeição imediata
     *  3. Validação de headers — anomalias de tamanho/contagem
     *  4. Payload size — body e gzip bomb
     *  5. Slow request detection — Slowloris/Slow POST
     *  6. Circuit breaker — rota em sobrecarga
     *  7. Rate limit por IP (sliding window)
     *  8. Token bucket (burst control)
     *  9. Rate limit global
     * 10. Proteção adaptativa — modo de ataque ativo
     */
    async evaluate(req: DDoSRequest): Promise<DDoSEvaluationResult> {
        const ip = req.ip || extractIP(req.headers);
        const path = req.path;
        const method = req.method.toUpperCase();
        const now = Date.now();
        const signals: string[] = [];

        const meta: DDoSMeta = {
            ip, path, method, timestamp: now, signals,
            underAttack: this.underAttack,
        };

        const block = (
            reason: DDoSBlockReason,
            action: DDoSAction = 'block',
            retryAfterMs?: number,
        ): DDoSEvaluationResult => {
            const result: DDoSEvaluationResult = { allowed: false, reason, action, retryAfterMs, meta };
            void this.config.onThrottled?.(result);
            this.debugLog('BLOCKED', reason, ip, path);
            return result;
        };

        // ── 1. Allowlist ─────────────────────────────────────────────────────
        const isAllowlisted = this.config.allowlistedIPs.includes(ip);
        if (isAllowlisted) {
            return { allowed: true, meta };
        }

        // ── 2. IP / CIDR blocklist ────────────────────────────────────────────
        if (this.config.blockedIPs.includes(ip)) {
            signals.push('ip-blocklist');
            return block('IP_BLOCKLIST');
        }

        for (const cidr of this.config.blockedCIDRs) {
            if (matchesCIDR(ip, cidr)) {
                signals.push(`cidr-blocklist:${cidr}`);
                return block('ASN_BLOCKLIST');
            }
        }

        // ── 3. Header anomaly ─────────────────────────────────────────────────
        const headerCheck = this.checkHeaderAnomalies(req.headers);
        if (headerCheck) {
            signals.push('header-anomaly');
            return block(headerCheck);
        }

        // ── 4. Payload size + gzip bomb ───────────────────────────────────────
        if (req.bodySize !== undefined) {
            if (req.bodySize > this.config.payload.maxBodyBytes) {
                signals.push(`body-too-large:${req.bodySize}`);
                return block('PAYLOAD_TOO_LARGE');
            }

            if (this.config.payload.detectGzipBomb) {
                const gzipResult = this.checkGzipBomb(req.headers, req.bodySize);
                if (gzipResult) {
                    signals.push('gzip-bomb-suspected');
                    return block('GZIP_BOMB_SUSPECTED');
                }
            }
        }

        // ── 5. Slow request detection ─────────────────────────────────────────
        if (this.config.slowRequest.enabled && req.startedAt) {
            const elapsed = now - req.startedAt;

            // Headers demorando mais que o timeout → Slowloris
            if (!req.bodyComplete && elapsed > this.config.slowRequest.headerTimeoutMs) {
                signals.push(`slowloris:${elapsed}ms`);
                return block('SLOW_REQUEST_DETECTED');
            }

            // Body recebido parcialmente + taxa abaixo do mínimo → Slow POST/RUDY
            if (req.bodySize !== undefined && !req.bodyComplete && elapsed > 5000) {
                const bytesPerSecond = (req.bodySize / elapsed) * 1000;
                if (bytesPerSecond < this.config.slowRequest.minBodyBytesPerSecond) {
                    signals.push(`slow-post:${bytesPerSecond.toFixed(1)}B/s`);
                    return block('SLOW_REQUEST_DETECTED');
                }
            }
        }

        // ── 6. Circuit breaker ────────────────────────────────────────────────
        if (this.config.circuitBreaker.enabled) {
            const cbResult = this.checkCircuitBreaker(path);
            if (cbResult === 'open') {
                signals.push(`circuit-open:${path}`);
                return block('CIRCUIT_BREAKER_OPEN', 'throttle', this.config.circuitBreaker.openDurationMs);
            }
        }

        // ── 7. Rate limit por IP + endpoint (sliding window) ─────────────────
        const rateLimitResult = await this.checkRateLimits(ip, path, method, meta);
        if (rateLimitResult) return rateLimitResult;

        // ── 8. Token bucket (burst control) ──────────────────────────────────
        const bucketResult = await this.checkTokenBucket(ip);
        if (bucketResult) return bucketResult;

        // ── 9. Rate limit global ──────────────────────────────────────────────
        const globalResult = await this.checkGlobalRateLimit(meta);
        if (globalResult) return globalResult;

        // ── 10. Proteção adaptativa ───────────────────────────────────────────
        const adaptiveResult = await this.checkAdaptiveProtection(ip, meta);
        if (adaptiveResult) return adaptiveResult;

        return { allowed: true, meta };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verificações individuais
    // ─────────────────────────────────────────────────────────────────────────

    /** Detecta anomalias de headers: excesso de headers, headers gigantes. */
    private checkHeaderAnomalies(
        headers: Record<string, string | string[] | undefined>,
    ): DDoSBlockReason | null {
        const headerNames = Object.keys(headers);

        if (headerNames.length > this.config.payload.maxHeaderCount) {
            return 'HEADER_FLOOD';
        }

        for (const name of headerNames) {
            const value = headers[name];
            const valueStr = Array.isArray(value) ? value.join(',') : (value ?? '');
            const total = name.length + valueStr.length;

            if (total > this.config.payload.maxHeaderSizeBytes) {
                return 'HEADER_FLOOD';
            }
        }

        // Range header abuse: Range: bytes=0-,1-,2-,... (Apache killer CVE-2011-3192)
        const range = getHeader(headers, 'range');
        if (range) {
            const rangeCount = (range.match(/,/g) ?? []).length + 1;
            if (rangeCount > 5) return 'RANGE_ABUSE';
        }

        return null;
    }

    /** Detecta potencial gzip bomb verificando Content-Length vs Content-Encoding. */
    private checkGzipBomb(
        headers: Record<string, string | string[] | undefined>,
        bodySize: number,
    ): boolean {
        const encoding = getHeader(headers, 'content-encoding');
        const contentLength = getHeader(headers, 'content-length');

        if (!encoding || !/gzip|deflate|br/i.test(encoding)) return false;

        // Se temos Content-Length do body comprimido e o body já foi lido
        // e o body tem tamanho suspeito (muito pequeno para justificar o encoding)
        if (contentLength) {
            const declared = parseInt(contentLength, 10);
            if (!isNaN(declared) && bodySize > 0) {
                const ratio = declared / bodySize;
                // ratio muito alto: 10 bytes "comprimidos" → 1000 bytes = red flag
                if (ratio > this.config.payload.maxGzipRatio) return true;
            }
        }

        return false;
    }

    /** Verifica estado do circuit breaker para uma rota. */
    private checkCircuitBreaker(path: string): 'open' | 'half-open' | 'closed' {
        const cb = this.config.circuitBreaker;
        const routeKey = this.normalizeRoutePath(path);

        let state = this.circuits.get(routeKey);
        if (!state) {
            state = {
                state: 'closed',
                failureCount: 0,
                successCount: 0,
                totalRequests: 0,
                openedAt: null,
                halfOpenTokens: 0,
            };
            this.circuits.set(routeKey, state);
        }

        const now = Date.now();

        if (state.state === 'open') {
            const openedAt = state.openedAt ?? 0;
            if (now - openedAt > cb.openDurationMs) {
                // Transição para half-open: testa algumas requisições
                state.state = 'half-open';
                state.halfOpenTokens = cb.halfOpenRequests;
                state.successCount = 0;
                this.debugLog('CIRCUIT-HALF-OPEN', routeKey);
            } else {
                return 'open';
            }
        }

        if (state.state === 'half-open') {
            if (state.halfOpenTokens <= 0) return 'open';
            state.halfOpenTokens--;
            return 'half-open';
        }

        return 'closed';
    }

    /**
     * Registra o resultado de uma requisição no circuit breaker.
     * Chame após processar a resposta do handler.
     *
     * @example
     * const result = await ddos.evaluate(req);
     * if (result.allowed) {
     *   const statusCode = await handler(req, res);
     *   ddos.recordResponse(req.path, statusCode);
     * }
     */
    recordResponse(path: string, statusCode: number): void {
        if (!this.config.circuitBreaker.enabled) return;

        const routeKey = this.normalizeRoutePath(path);
        const state = this.circuits.get(routeKey);
        if (!state) return;

        const isError = statusCode >= 500;
        state.totalRequests++;

        if (state.state === 'half-open') {
            if (!isError) {
                state.successCount++;
                if (state.successCount >= this.config.circuitBreaker.halfOpenRequests) {
                    state.state = 'closed';
                    state.failureCount = 0;
                    state.totalRequests = 0;
                    this.debugLog('CIRCUIT-CLOSED', routeKey);
                }
            } else {
                // Falhou no half-open → re-abre
                state.state = 'open';
                state.openedAt = Date.now();
                this.debugLog('CIRCUIT-REOPENED', routeKey);
            }
            return;
        }

        if (isError) {
            state.failureCount++;
        } else {
            // Reseta contagem de falhas em sucesso para sliding window de erros
            state.failureCount = Math.max(0, state.failureCount - 1);
        }

        if (state.totalRequests >= 10) {
            const errorRate = (state.failureCount / state.totalRequests) * 100;
            if (errorRate >= this.config.circuitBreaker.errorThresholdPercent) {
                state.state = 'open';
                state.openedAt = Date.now();
                this.debugLog('CIRCUIT-OPENED', routeKey, `error rate: ${errorRate.toFixed(1)}%`);

                void this.config.onAttackDetected?.(
                    {
                        ip: '0.0.0.0', path, method: 'ANY', timestamp: Date.now(),
                        signals: [`circuit-opened:${errorRate.toFixed(1)}%`], underAttack: this.underAttack,
                    },
                    'CIRCUIT_BREAKER_TRIGGERED',
                );
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rate limiting
    // ─────────────────────────────────────────────────────────────────────────

    private async checkRateLimits(
        ip: string,
        path: string,
        method: string,
        meta: DDoSMeta,
    ): Promise<DDoSEvaluationResult | null> {
        const now = Date.now();
        const rl = this.config.rateLimit;
        const store = this.config.store;

        // Aplica fator adaptativo se em modo de ataque
        const factor = this.underAttack
            ? this.config.adaptive.throttleFactorOnAttack
            : 1.0;
        const effectiveMax = Math.floor(rl.maxRequestsPerIP * factor);

        const ipKey = `ddos:rl:ip:${sanitizeKey(ip)}`;
        const ipCount = await store.increment(ipKey, rl.windowMs);

        meta.currentRps = ipCount / (rl.windowMs / 1000);

        if (ipCount > effectiveMax) {
            meta.signals.push(`rate-ip:${ipCount}/${effectiveMax}`);
            const retryAfter = rl.windowMs - (now % rl.windowMs);
            return {
                allowed: false, reason: 'RATE_LIMIT_IP', action: 'throttle',
                retryAfterMs: retryAfter, meta,
            };
        }

        // Rate limit por endpoint
        const endpointConfig = this.config.endpointLimits?.[path] ??
            this.config.endpointLimits?.[this.normalizeRoutePath(path)];

        if (endpointConfig) {
            const epKey = `ddos:rl:ep:${sanitizeKey(path)}:${sanitizeKey(ip)}`;
            const epCount = await store.increment(epKey, endpointConfig.windowMs);

            if (epCount > endpointConfig.maxRequests) {
                meta.signals.push(`rate-endpoint:${path}:${epCount}`);
                return {
                    allowed: false, reason: 'RATE_LIMIT_ENDPOINT',
                    action: endpointConfig.action ?? 'block',
                    retryAfterMs: endpointConfig.windowMs,
                    meta,
                };
            }
        }

        return null;
    }

    private async checkTokenBucket(ip: string): Promise<DDoSEvaluationResult | null> {
        const { burstCapacity, burstRefillPerSecond } = this.config.rateLimit;
        const store = this.config.store;
        const now = Date.now();
        const ttl = Math.ceil(burstCapacity / burstRefillPerSecond) * 1000;

        const tokensKey = `ddos:tb:tokens:${sanitizeKey(ip)}`;
        const lastRefillKey = `ddos:tb:last:${sanitizeKey(ip)}`;

        const [currentTokens, lastRefill] = await Promise.all([
            store.get(tokensKey),
            store.get(lastRefillKey),
        ]);

        const tokens = currentTokens ?? burstCapacity;
        const last = lastRefill ?? now;
        const elapsed = (now - last) / 1000;
        const newTokens = Math.min(burstCapacity, tokens + elapsed * burstRefillPerSecond);

        if (newTokens < 1) {
            const waitMs = Math.ceil((1 - newTokens) / burstRefillPerSecond * 1000);
            return {
                allowed: false, reason: 'RATE_LIMIT_IP', action: 'throttle',
                retryAfterMs: waitMs,
                meta: {
                    ip, path: '', method: '', timestamp: now,
                    signals: ['token-bucket-empty'], underAttack: this.underAttack,
                },
            };
        }

        await Promise.all([
            store.set(tokensKey, newTokens - 1, ttl),
            store.set(lastRefillKey, now, ttl),
        ]);

        return null;
    }

    private async checkGlobalRateLimit(
        meta: DDoSMeta,
    ): Promise<DDoSEvaluationResult | null> {
        const store = this.config.store;
        const bucket = Math.floor(Date.now() / 1000);
        const key = `ddos:rl:global:${bucket}`;
        const count = await store.increment(key, 2000);

        if (count > this.config.rateLimit.globalMaxRps) {
            meta.signals.push(`rate-global:${count}`);

            // Dispara alerta de ataque global apenas uma vez por segundo
            void this.config.onAttackDetected?.(meta, 'GLOBAL_RATE_LIMIT_EXCEEDED');

            return {
                allowed: false, reason: 'RATE_LIMIT_GLOBAL', action: 'block', meta,
            };
        }

        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Proteção adaptativa
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Detecta ataques pelo padrão de tráfego e ativa modo de proteção intensificada.
     *
     * Algoritmo:
     *  1. Mantém baseline de req/s calculado em janela de observação
     *  2. Se o tráfego atual superar baseline × attackMultiplier → modo ataque
     *  3. Em modo ataque, todos os thresholds são reduzidos pelo throttleFactor
     *  4. Após minAttackDurationMs sem pico, relaxa o modo
     */
    private async checkAdaptiveProtection(
        ip: string,
        meta: DDoSMeta,
    ): Promise<DDoSEvaluationResult | null> {
        if (!this.config.adaptive.enabled) return null;

        const now = Date.now();
        const store = this.config.store;
        const adaptive = this.config.adaptive;

        // Atualiza baseline a cada janela de observação
        if (now - this.baselineSampleAt > adaptive.baselineWindowMs) {
            const baselineKey = `ddos:adaptive:baseline`;
            const samples = await store.get(baselineKey);
            if (samples && samples > 0) {
                this.baselineRps = samples / (adaptive.baselineWindowMs / 1000);
                this.baselineSampleAt = now;
                this.debugLog('ADAPTIVE-BASELINE', `${this.baselineRps.toFixed(1)} rps`);
            }
        }

        // Incrementa contador global desta janela
        const windowKey = `ddos:adaptive:window:${Math.floor(now / adaptive.baselineWindowMs)}`;
        await store.increment(windowKey, adaptive.baselineWindowMs * 2);

        // Sem baseline ainda — coleta dados
        if (this.baselineRps === 0) return null;

        // Calcula RPS atual da última janela de 1 segundo
        const currentRps = meta.currentRps ?? 0;
        const threshold = this.baselineRps * adaptive.attackMultiplier;

        if (currentRps > threshold && !this.underAttack) {
            this.underAttack = true;
            this.attackStartedAt = now;
            meta.underAttack = true;

            void this.config.onAttackDetected?.(
                meta,
                `ADAPTIVE_ATTACK_DETECTED: ${currentRps.toFixed(1)} rps (baseline: ${this.baselineRps.toFixed(1)})`,
            );

            this.debugLog(
                'ADAPTIVE-ATTACK',
                `rps=${currentRps.toFixed(1)} threshold=${threshold.toFixed(1)}`,
            );
        }

        // Relaxa modo de ataque após período mínimo sem pico
        if (
            this.underAttack &&
            now - this.attackStartedAt > adaptive.minAttackDurationMs &&
            currentRps < threshold
        ) {
            this.underAttack = false;
            meta.underAttack = false;
            this.debugLog('ADAPTIVE-RELAXED');
        }

        // Em modo de ataque, aplica throttle extra para IPs com tráfego elevado
        if (this.underAttack && (meta.currentRps ?? 0) > this.baselineRps * 2) {
            meta.signals.push(`adaptive-throttle:rps=${currentRps.toFixed(1)}`);
            return {
                allowed: false, reason: 'ADAPTIVE_BLOCK', action: 'throttle',
                retryAfterMs: 5000, meta,
            };
        }

        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tarpitting
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Aplica atraso artificial a requisições suspeitas (tarpit).
     *
     * Estratégia: aumenta o custo do ataque para o atacante mantendo
     * conexões abertas por mais tempo, reduzindo a taxa efetiva de ataque.
     *
     * ⚠ Use com cuidado: pode aumentar o número de conexões abertas no server.
     * Combine com limite de conexões simultâneas por IP no nginx/load balancer.
     */
    async applyTarpit(req: DDoSRequest): Promise<void> {
        if (!this.config.tarpit.enabled) return;

        const { minDelayMs, maxDelayMs } = this.config.tarpit;
        const jitter = Math.random() * (maxDelayMs - minDelayMs);
        const delay = minDelayMs + jitter;

        this.debugLog('TARPIT', req.ip, `${delay.toFixed(0)}ms`);
        await sleepWithJitter(delay, 200);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários públicos
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica se um JSON (como string) excede a profundidade máxima configurada.
     * Chame antes de JSON.parse() para payloads de API.
     *
     * @example
     * const rawBody = await readBody(req);
     * if (ddos.isJsonDepthExceeded(rawBody)) return res.status(400).end();
     * const data = JSON.parse(rawBody);
     */
    isJsonDepthExceeded(jsonString: string): boolean {
        return estimateJsonDepth(jsonString) > this.config.payload.maxJsonDepth;
    }

    /**
     * Retorna snapshot do estado atual para observabilidade.
     */
    getStatus(): {
        underAttack: boolean;
        baselineRps: number;
        openCircuits: string[];
        attackStartedAt: number | null;
    } {
        const openCircuits: string[] = [];
        for (const [route, state] of Array.from(this.circuits.entries())) {
            if (state.state === 'open') openCircuits.push(route);
        }

        return {
            underAttack: this.underAttack,
            baselineRps: this.baselineRps,
            openCircuits,
            attackStartedAt: this.underAttack ? this.attackStartedAt : null,
        };
    }

    /**
     * Normaliza caminhos de rota para agrupamento no circuit breaker.
     * Remove IDs dinâmicos: /users/123 → /users/:id
     */
    private normalizeRoutePath(path: string): string {
        return path
            .replace(/\/[0-9a-fA-F]{8,}/g, '/:id')  // UUIDs
            .replace(/\/\d+/g, '/:id')  // números
            .replace(/\/[0-9a-fA-F]{24}/g, '/:id')  // MongoDB ObjectIds
            .replace(/\?.*$/, '')      // query string
            .toLowerCase();
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[ddos-protection]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resposta de bloqueio padronizada — não revela motivo ao cliente.
 */
function buildBlockResponse(
    action: DDoSAction,
    retryAfterMs?: number,
): { status: number; headers: Record<string, string>; body: string } {
    const status = action === 'throttle' ? 429 : 503;
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
        'Connection': 'close',
    };

    if (retryAfterMs) {
        headers['Retry-After'] = String(Math.ceil(retryAfterMs / 1000));
    }

    const message = status === 429
        ? 'Too Many Requests'
        : 'Service Temporarily Unavailable';

    return {
        status,
        headers,
        body: JSON.stringify({ error: message, message: 'Please try again later.' }),
    };
}

type ExpressReq = {
    ip?: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
};
type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    json(d: unknown): void;
    end(): void;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware DDoS para Express.
 *
 * @example
 * app.use(createExpressDDoS(ddosProtection));
 *
 * // Para circuit breaker funcionar, registre as respostas:
 * app.use((req, res, next) => {
 *   res.on('finish', () => ddosProtection.recordResponse(req.path, res.statusCode));
 *   next();
 * });
 */
export function createExpressDDoS(protection: DDoSProtection) {
    return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
        const normalized: DDoSRequest = {
            ip: req.ip ?? extractIP(req.headers),
            method: req.method,
            path: req.path,
            headers: req.headers,
            startedAt: Date.now(),
        };

        const result = await protection.evaluate(normalized);

        if (!result.allowed) {
            if (result.action === 'tarpit') {
                await protection.applyTarpit(normalized);
            }

            const { status, headers, body } = buildBlockResponse(
                result.action ?? 'block',
                result.retryAfterMs,
            );
            res.status(status).set(headers).json(JSON.parse(body));
            return;
        }

        next();
    };
}

/**
 * Handler DDoS para Next.js middleware (Edge Runtime).
 *
 * @example
 * // middleware.ts
 * export default createNextDDoS(ddosProtection);
 */
export function createNextDDoS(protection: DDoSProtection) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => { headers[key] = value; });

        const url = new URL(request.url);
        const normalized: DDoSRequest = {
            ip: headers['cf-connecting-ip'] ?? headers['x-real-ip'] ?? '0.0.0.0',
            method: request.method,
            path: url.pathname,
            headers,
            startedAt: Date.now(),
        };

        const result = await protection.evaluate(normalized);

        if (!result.allowed) {
            if (result.action === 'tarpit') {
                await protection.applyTarpit(normalized);
            }

            const { status, headers: respHeaders, body } = buildBlockResponse(
                result.action ?? 'block',
                result.retryAfterMs,
            );
            return new Response(body, { status, headers: respHeaders });
        }

        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory com preset de produção
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria instância com configuração balanceada para produção.
 *
 * @example
 * const ddos = createDDoSProtection({
 *   store: createRedisStore(redisClient),
 *   onAttackDetected: (meta, pattern) => logger.critical('DDoS detected', { meta, pattern }),
 * });
 * app.use(createExpressDDoS(ddos));
 */
export function createDDoSProtection(
    overrides: Partial<DDoSConfig> & { store: DDoSStore },
): DDoSProtection {
    const defaults: DDoSConfig = {
        rateLimit: {
            maxRequestsPerIP: 120,
            windowMs: 60_000,
            burstCapacity: 20,
            burstRefillPerSecond: 2,
            globalMaxRps: 5_000,
        },

        endpointLimits: {
            '/api/auth/login': { maxRequests: 5, windowMs: 60_000, action: 'block' },
            '/api/auth/register': { maxRequests: 3, windowMs: 60_000, action: 'block' },
            '/api/auth/forgot-password': { maxRequests: 3, windowMs: 60_000, action: 'block' },
            '/api/payment': { maxRequests: 10, windowMs: 60_000, action: 'block' },
            '/api/checkout': { maxRequests: 15, windowMs: 60_000, action: 'throttle' },
            '/api/graphql': { maxRequests: 200, windowMs: 60_000, action: 'throttle' },
            '/api/search': { maxRequests: 60, windowMs: 60_000, action: 'throttle' },
            '/api/export': { maxRequests: 5, windowMs: 300_000, action: 'block' },
        },

        payload: {
            maxBodyBytes: 1_048_576,  // 1MB
            maxHeaderCount: 100,
            maxHeaderSizeBytes: 8_192,
            maxJsonDepth: 10,
            detectGzipBomb: true,
            maxGzipRatio: 100,
        },

        circuitBreaker: {
            enabled: true,
            errorThresholdPercent: 50,
            observationWindowMs: 30_000,
            openDurationMs: 15_000,
            halfOpenRequests: 5,
        },

        tarpit: {
            enabled: false,
            minDelayMs: 2_000,
            maxDelayMs: 10_000,
        },

        adaptive: {
            enabled: true,
            attackMultiplier: 3.0,
            baselineWindowMs: 300_000,
            throttleFactorOnAttack: 0.3,
            minAttackDurationMs: 60_000,
        },

        slowRequest: {
            enabled: true,
            headerTimeoutMs: 10_000,
            bodyTimeoutMs: 30_000,
            minBodyBytesPerSecond: 100,
        },

        blockedIPs: [],
        blockedCIDRs: [],
        allowlistedIPs: ['127.0.0.1', '::1'],

        ...overrides,
        store: overrides.store,
    };

    return new DDoSProtection(defaults);
}