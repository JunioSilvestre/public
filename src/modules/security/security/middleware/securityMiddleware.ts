/**
 * @fileoverview Orquestrador central de segurança — Security Middleware Pipeline.
 *
 * @description
 * Compõe todos os middlewares de segurança numa pipeline única, ordenada por
 * custo computacional crescente e prioridade decrescente de detecção.
 *
 * ── Ordem da pipeline ─────────────────────────────────────────────────────
 *
 *  Fase 1 — IDENTIDADE (custo: O(1), lookup em Set/Map)
 *   1.1  IP Allowlist          — bypass imediato para IPs confiáveis
 *   1.2  IP Blocklist          — rejeição imediata para IPs banidos
 *   1.3  Bogon / Spoofed IP    — IPs que não deveriam existir na internet
 *
 *  Fase 2 — REQUISIÇÃO (custo: O(n) em headers/body)
 *   2.1  Request Integrity     — smuggling, Content-Type, tamanho, estrutura
 *   2.2  Request Anomaly       — headers suspeitos, UA ausente, headless
 *
 *  Fase 3 — COMPORTAMENTO (custo: I/O no store — Redis/memória)
 *   3.1  Rate Limiting         — janela deslizante por IP/usuário/endpoint
 *   3.2  DDoS Protection       — token bucket, circuit breaker, adaptive
 *   3.3  Bot Protection        — UA patterns, behavioral scoring
 *   3.4  IP Reputation         — score acumulado + auto-ban
 *
 *  Fase 4 — GEOLOCALIZAÇÃO (custo: I/O externo — CDN header ou API)
 *   4.1  Geo Blocking          — país, Tor, VPN, datacenter ASN
 *
 *  Fase 5 — CSRF (custo: criptografia — HMAC)
 *   5.1  CSRF Protection       — synchronizer token / signed double submit
 *
 * ── Por que esta ordem ─────────────────────────────────────────────────────
 *
 *  Colocar as verificações mais baratas primeiro garante que o máximo de
 *  requests maliciosos seja rejeitado antes de chegar nas verificações custosas.
 *  Um IP na blocklist é rejeitado em O(1) sem nunca chegar no Redis.
 *  Um bot é bloqueado antes de qualquer verificação criptográfica.
 *
 * ── Princípios de design ───────────────────────────────────────────────────
 *
 *  • Defense in depth — múltiplas camadas independentes
 *  • Fail secure — falhas do store bloqueiam por padrão (configurável)
 *  • Observabilidade — cada fase reporta detalhes para logging/SIEM
 *  • Composabilidade — cada fase pode ser habilitada/desabilitada
 *  • Framework-agnostic — adaptadores Express, Next.js e Fetch API
 *  • Zero acoplamento — cada middleware funciona de forma independente
 *
 * ── Integração com outros middlewares ─────────────────────────────────────
 *
 *  Violações registradas pelo securityMiddleware alimentam automaticamente
 *  o IPFilter via `reportViolation()`, construindo score de reputação ao
 *  longo do tempo sem que cada middleware precise conhecer os outros.
 *
 * @example
 * // Express — setup mínimo
 * const security = createSecurityPipeline({ store: redisStore });
 * app.use(createExpressSecurityPipeline(security));
 *
 * // Next.js middleware.ts
 * export default createNextSecurityPipeline(security);
 *
 * // Configuração completa com todos os módulos
 * const security = createSecurityPipeline({
 *   store: redisStore,
 *   geo: { mode: 'allowlist', allowedCountries: ['BR', 'PT'] },
 *   csrf: { strategy: 'signed-double-submit', secret: process.env.CSRF_SECRET! },
 *   onViolation: (event) => siem.send(event),
 * });
 */

import { BotProtection, createBotProtection, type BotProtectionConfig, type BotProtectionStore, type NormalizedRequest as BotRequest } from './botProtection';
import { CORSMiddleware, type CORSConfig } from './cors';
import { CSRFProtection, type CSRFConfig } from './csrfProtection';
import { DDoSProtection, createDDoSProtection, type DDoSConfig, type DDoSStore, type DDoSRequest } from './ddosProtection';
import { GeoBlockMiddleware, type GeoBlockConfig, type GeoRequest } from './geoBlock';
import { IPFilter, createBalancedIPFilter, type IPFilterConfig, type IPFilterStore, type IPFilterRequest, VIOLATION_SCORES } from './ipFilter';
import { RateLimiter, createDefaultRateLimiter, type RateLimitConfig, type RateLimitStore, type RateLimitRequest } from './rateLimit';
import { RequestIntegrityMiddleware, createDefaultIntegrity, type RequestIntegrityConfig, type IntegrityRequest } from './requestIntegrity';

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado de uma fase da pipeline. */
export interface PhaseResult {
    phase: SecurityPhase;
    allowed: boolean;
    reason?: string;
    action?: string;
    latencyMs: number;
}

export type SecurityPhase =
    | 'ip-filter'
    | 'request-integrity'
    | 'rate-limit'
    | 'ddos'
    | 'bot'
    | 'geo'
    | 'csrf'
    | 'cors';

/** Resultado completo da pipeline. */
export interface SecurityResult {
    allowed: boolean;
    /** Fase que bloqueou a requisição (undefined se allowed = true). */
    blockedBy?: SecurityPhase;
    reason?: string;
    action?: string;
    /** Todos os headers a adicionar na resposta (CORS + CSRF + Rate Limit). */
    headers: Record<string, string>;
    /** Detalhes de cada fase executada (para logging). */
    phases: PhaseResult[];
    /** Latência total da pipeline em ms. */
    totalLatencyMs: number;
    meta: SecurityMeta;
}

export interface SecurityMeta {
    ip: string;
    path: string;
    method: string;
    requestId?: string;
    timestamp: number;
}

/** Evento de violação — emitido em cada bloqueio para SIEM/logging. */
export interface SecurityViolationEvent {
    phase: SecurityPhase;
    reason: string;
    ip: string;
    path: string;
    method: string;
    requestId?: string;
    timestamp: number;
    /** Score de penalização sugerido para o IPFilter. */
    penaltyScore: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração da pipeline
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Store compartilhado entre todos os módulos que precisam de persistência.
 * Implementação única que satisfaz todas as interfaces.
 */
export interface SharedStore
    extends BotProtectionStore,
    DDoSStore,
    IPFilterStore,
    RateLimitStore { }

export interface SecurityPipelineConfig {
    /**
     * Store compartilhado (Redis em produção).
     * Usado por: BotProtection, DDoS, IPFilter, RateLimit.
     *
     * Use `createRedisSharedStore(redisClient)` para produção.
     * Use `createMemorySharedStore()` para desenvolvimento/testes.
     */
    store: SharedStore;

    /**
     * Fases habilitadas na pipeline.
     * Default: todas habilitadas exceto csrf e geo (opt-in por complexidade).
     */
    phases?: {
        ipFilter?: boolean;
        requestIntegrity?: boolean;
        rateLimit?: boolean;
        ddos?: boolean;
        bot?: boolean;
        geo?: boolean;
        csrf?: boolean;
        cors?: boolean;
    };

    /** Configuração do IPFilter. Se omitida, usa preset balanceado. */
    ipFilter?: Partial<IPFilterConfig>;

    /** Configuração de Request Integrity. */
    integrity?: RequestIntegrityConfig;

    /** Configuração de Rate Limiting. */
    rateLimit?: Partial<RateLimitConfig>;

    /** Configuração de DDoS Protection. */
    ddos?: Partial<DDoSConfig>;

    /** Configuração de Bot Protection. */
    bot?: Partial<BotProtectionConfig>;

    /**
     * Configuração de Geo Blocking.
     * Obrigatório quando phases.geo = true.
     */
    geo?: GeoBlockConfig;

    /**
     * Configuração de CSRF Protection.
     * Obrigatório quando phases.csrf = true.
     */
    csrf?: CSRFConfig;

    /** Configuração de CORS. */
    cors?: CORSConfig;

    /**
     * Comportamento quando qualquer store falha.
     * 'open':  permite a requisição (disponibilidade > segurança)
     * 'closed': bloqueia a requisição (segurança > disponibilidade)
     * Default: 'open'
     */
    onStoreFailure?: 'open' | 'closed';

    /**
     * Rotas completamente excluídas da pipeline de segurança.
     * Use apenas para health checks internos.
     */
    bypassRoutes?: Array<string | RegExp>;

    /**
     * Métodos HTTP excluídos da pipeline completa.
     * Default: ['OPTIONS'] — OPTIONS é tratado apenas pelo CORS.
     */
    bypassMethods?: string[];

    /**
     * Hook principal de violação — chamado em cada bloqueio.
     * Use para: SIEM, alertas, logging centralizado.
     *
     * @example
     * onViolation: async (event) => {
     *   await siem.send(event);
     *   if (event.penaltyScore >= 50) {
     *     await slack.alert(`High risk: ${event.ip} - ${event.reason}`);
     *   }
     * }
     */
    onViolation?: (event: SecurityViolationEvent) => void | Promise<void>;

    /**
     * Hook chamado em cada requisição (allowed ou não) para métricas.
     *
     * @example
     * onRequest: (result) => {
     *   metrics.histogram('security.pipeline.latency', result.totalLatencyMs);
     *   metrics.increment(`security.phase.${result.blockedBy ?? 'allowed'}`);
     * }
     */
    onRequest?: (result: SecurityResult) => void;

    /** Habilita logging detalhado de cada fase. Default: false. */
    debug?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalização de request
// ─────────────────────────────────────────────────────────────────────────────

export interface PipelineRequest {
    ip?: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    rawBody?: Uint8Array | Buffer;
    parsedBody?: unknown;
    cookies?: Record<string, string>;
    userId?: string;
    apiKey?: string;
    tenantId?: string;
    sessionId?: string;
    secure?: boolean;
    startedAt?: number;
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

function parseCookieHeader(cookieHeader: string): Record<string, string> {
    const cookies: Record<string, string> = {};
    for (const part of cookieHeader.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        const key = decodeURIComponent(part.slice(0, idx).trim());
        const value = decodeURIComponent(part.slice(idx + 1).trim());
        if (key) cookies[key] = value;
    }
    return cookies;
}

/** Mapa de fase → score de penalização para o IPFilter. */
const PHASE_PENALTY_SCORES: Record<SecurityPhase, number> = {
    'ip-filter': 0,   // já gerenciado internamente pelo IPFilter
    'request-integrity': 25,
    'rate-limit': 15,
    'ddos': 40,
    'bot': 30,
    'geo': 0,   // geo blocking não indica atividade maliciosa
    'csrf': 40,
    'cors': 10,
};

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class SecurityPipeline {
    private readonly config: Required<Omit<SecurityPipelineConfig, 'onViolation' | 'onRequest'>>
        & Pick<SecurityPipelineConfig, 'onViolation' | 'onRequest'>;

    private readonly ipFilter?: IPFilter;
    private readonly integrity?: RequestIntegrityMiddleware;
    private readonly rateLimiter?: RateLimiter;
    private readonly ddos?: DDoSProtection;
    private readonly bot?: BotProtection;
    private readonly geo?: GeoBlockMiddleware;
    private readonly csrf?: CSRFProtection;
    private readonly cors?: CORSMiddleware;

    constructor(config: SecurityPipelineConfig) {
        const phases = config.phases ?? {};

        this.config = {
            phases: {
                ipFilter: phases.ipFilter ?? true,
                requestIntegrity: phases.requestIntegrity ?? true,
                rateLimit: phases.rateLimit ?? true,
                ddos: phases.ddos ?? true,
                bot: phases.bot ?? true,
                geo: phases.geo ?? false,
                csrf: phases.csrf ?? false,
                cors: phases.cors ?? false,
            },
            ipFilter: config.ipFilter ?? {},
            integrity: config.integrity ?? {},
            rateLimit: config.rateLimit ?? {},
            ddos: config.ddos ?? {},
            bot: config.bot ?? {},
            geo: config.geo ?? { mode: 'blocklist' },
            csrf: config.csrf ?? { strategy: 'double-submit-cookie' },
            cors: config.cors ?? { allowedOrigins: [] },
            bypassRoutes: config.bypassRoutes ?? [],
            bypassMethods: config.bypassMethods ?? ['OPTIONS'],
            onStoreFailure: config.onStoreFailure ?? 'open',
            onViolation: config.onViolation,
            onRequest: config.onRequest,
            debug: config.debug ?? false,
            store: config.store,
        };

        const store = config.store;

        // Inicializa apenas as fases habilitadas
        if (this.config.phases.ipFilter) {
            this.ipFilter = createBalancedIPFilter(store, config.ipFilter?.externalEnrichment);
        }

        if (this.config.phases.requestIntegrity) {
            this.integrity = config.integrity
                ? new RequestIntegrityMiddleware(config.integrity)
                : createDefaultIntegrity();
        }

        if (this.config.phases.rateLimit) {
            this.rateLimiter = createDefaultRateLimiter(store, config.rateLimit ?? {});
        }

        if (this.config.phases.ddos) {
            this.ddos = createDDoSProtection({ store, ...(config.ddos ?? {}) });
        }

        if (this.config.phases.bot) {
            this.bot = createBotProtection({
                store,
                ...(config.bot ?? {}),
            } as BotProtectionConfig & { store: BotProtectionStore });
        }

        if (this.config.phases.geo && config.geo) {
            this.geo = new GeoBlockMiddleware(config.geo);
        }

        if (this.config.phases.csrf && config.csrf) {
            this.csrf = new CSRFProtection(config.csrf);
        }

        if (this.config.phases.cors && config.cors) {
            this.cors = new CORSMiddleware(config.cors);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pipeline principal
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Executa a pipeline de segurança completa para uma requisição.
     *
     * Cada fase é executada em ordem. Na primeira falha, a pipeline
     * para e retorna o resultado de bloqueio imediatamente.
     * As fases executadas antes da falha são registradas em `phases`.
     */
    async run(req: PipelineRequest): Promise<SecurityResult> {
        const pipelineStart = Date.now();
        const ip = req.ip ?? extractIP(req.headers);
        const path = req.path;
        const method = req.method.toUpperCase();
        const phases: PhaseResult[] = [];
        const responseHeaders: Record<string, string> = {};

        const meta: SecurityMeta = {
            ip, path, method, timestamp: pipelineStart,
            requestId: getHeader(req.headers, 'x-request-id'),
        };

        // Resolve cookies uma vez
        const cookies = req.cookies
            ?? parseCookieHeader(getHeader(req.headers, 'cookie') ?? '');

        // ── Bypass: rotas e métodos ignorados ─────────────────────────────
        if (this.shouldBypass(path, method)) {
            return this.buildAllowResult(phases, responseHeaders, meta, pipelineStart);
        }

        // ── CORS — executado antes de qualquer bloqueio ───────────────────
        // CORS deve ser avaliado primeiro para que os headers corretos
        // cheguem mesmo em respostas de bloqueio (ex: 429 precisa de CORS).
        if (this.cors) {
            const t0 = Date.now();
            const corsResult = this.cors.evaluate({
                method, path, headers: req.headers, secure: req.secure,
            });
            // Adiciona headers CORS a TODAS as respostas (inclusive bloqueios)
            Object.assign(responseHeaders, corsResult.headers);

            if (!corsResult.allowed) {
                return this.buildBlockResult(
                    'cors', 'CORS_REJECTED', 'block',
                    phases, responseHeaders, meta, pipelineStart, t0,
                );
            }

            // Preflight OPTIONS — responde aqui e encerra a pipeline
            if (corsResult.isPreflight) {
                phases.push({ phase: 'cors', allowed: true, latencyMs: Date.now() - t0 });
                return {
                    allowed: true,
                    headers: responseHeaders,
                    phases,
                    totalLatencyMs: Date.now() - pipelineStart,
                    meta,
                };
            }

            phases.push({ phase: 'cors', allowed: true, latencyMs: Date.now() - t0 });
        }

        // ── Fase 1: IP Filter ─────────────────────────────────────────────
        if (this.ipFilter) {
            const t0 = Date.now();
            try {
                const result = await this.ipFilter.evaluate({
                    ip, method, path, headers: req.headers,
                } as IPFilterRequest);

                phases.push({
                    phase: 'ip-filter', allowed: result.allowed,
                    reason: result.reason, action: result.action,
                    latencyMs: Date.now() - t0,
                });

                if (!result.allowed) {
                    void this.emitViolation('ip-filter', result.reason ?? 'IP_BLOCKED', ip, path, method, meta.requestId);
                    return this.buildBlockResult(
                        'ip-filter', result.reason ?? 'IP_BLOCKED', result.action ?? 'block',
                        phases, responseHeaders, meta, pipelineStart, t0,
                    );
                }
            } catch (err) {
                this.handleStoreError('ip-filter', err, phases, t0);
                if (this.config.onStoreFailure === 'closed') {
                    return this.buildBlockResult('ip-filter', 'STORE_ERROR', 'block', phases, responseHeaders, meta, pipelineStart, t0);
                }
            }
        }

        // ── Fase 2: Request Integrity ─────────────────────────────────────
        if (this.integrity) {
            const t0 = Date.now();
            try {
                const result = await this.integrity.verify({
                    method, path, headers: req.headers,
                    rawBody: req.rawBody,
                    parsedBody: req.parsedBody,
                    contentLength: req.rawBody?.length,
                } as IntegrityRequest);

                // Propaga o Request ID gerado
                if (result.requestId) {
                    meta.requestId = result.requestId;
                    responseHeaders['X-Request-Id'] = result.requestId;
                }

                phases.push({
                    phase: 'request-integrity', allowed: result.valid,
                    reason: result.reason, latencyMs: Date.now() - t0,
                });

                if (!result.valid) {
                    void this.emitViolation('request-integrity', result.reason ?? 'INTEGRITY_FAILED', ip, path, method, meta.requestId);
                    await this.penalizeIP(ip, 'request-integrity', result.reason ?? 'INTEGRITY_FAILED');
                    return this.buildBlockResult(
                        'request-integrity', result.reason ?? 'INTEGRITY_FAILED', 'block',
                        phases, responseHeaders, meta, pipelineStart, t0,
                    );
                }
            } catch (err) {
                this.handleStoreError('request-integrity', err, phases, Date.now());
                if (this.config.onStoreFailure === 'closed') {
                    return this.buildBlockResult('request-integrity', 'STORE_ERROR', 'block', phases, responseHeaders, meta, pipelineStart, Date.now());
                }
            }
        }

        // ── Fase 3: Rate Limiting ─────────────────────────────────────────
        if (this.rateLimiter) {
            const t0 = Date.now();
            try {
                const result = await this.rateLimiter.check({
                    ip, method, path,
                    headers: req.headers,
                    userId: req.userId,
                    apiKey: req.apiKey,
                    tenantId: req.tenantId,
                } as RateLimitRequest);

                // Sempre inclui headers de rate limit na resposta
                Object.assign(responseHeaders, result.headers);

                phases.push({
                    phase: 'rate-limit', allowed: result.allowed,
                    reason: result.allowed ? undefined : 'RATE_LIMIT_EXCEEDED',
                    latencyMs: Date.now() - t0,
                });

                if (!result.allowed) {
                    void this.emitViolation('rate-limit', 'RATE_LIMIT_EXCEEDED', ip, path, method, meta.requestId);
                    await this.penalizeIP(ip, 'rate-limit', 'RATE_LIMIT_EXCEEDED');
                    return this.buildBlockResult(
                        'rate-limit', 'RATE_LIMIT_EXCEEDED', 'throttle',
                        phases, responseHeaders, meta, pipelineStart, t0,
                    );
                }
            } catch (err) {
                this.handleStoreError('rate-limit', err, phases, Date.now());
                if (this.config.onStoreFailure === 'closed') {
                    return this.buildBlockResult('rate-limit', 'STORE_ERROR', 'block', phases, responseHeaders, meta, pipelineStart, Date.now());
                }
            }
        }

        // ── Fase 4: DDoS ──────────────────────────────────────────────────
        if (this.ddos) {
            const t0 = Date.now();
            try {
                const result = await this.ddos.evaluate({
                    ip, method, path,
                    headers: req.headers,
                    bodySize: req.rawBody?.length,
                    startedAt: req.startedAt,
                } as DDoSRequest);

                phases.push({
                    phase: 'ddos', allowed: result.allowed,
                    reason: result.reason, action: result.action,
                    latencyMs: Date.now() - t0,
                });

                if (!result.allowed) {
                    if (result.action === 'tarpit') await this.ddos.applyTarpit({ ip, method, path, headers: req.headers });
                    void this.emitViolation('ddos', result.reason ?? 'DDOS_DETECTED', ip, path, method, meta.requestId);
                    await this.penalizeIP(ip, 'ddos', result.reason ?? 'DDOS_DETECTED');
                    return this.buildBlockResult(
                        'ddos', result.reason ?? 'DDOS_DETECTED', result.action ?? 'block',
                        phases, responseHeaders, meta, pipelineStart, t0,
                    );
                }
            } catch (err) {
                this.handleStoreError('ddos', err, phases, Date.now());
                if (this.config.onStoreFailure === 'closed') {
                    return this.buildBlockResult('ddos', 'STORE_ERROR', 'block', phases, responseHeaders, meta, pipelineStart, Date.now());
                }
            }
        }

        // ── Fase 5: Bot Protection ────────────────────────────────────────
        if (this.bot) {
            const t0 = Date.now();
            try {
                const result = await this.bot.evaluate({
                    ip, method, path, headers: req.headers,
                    body: req.parsedBody,
                    timestamp: pipelineStart,
                } as BotRequest);

                phases.push({
                    phase: 'bot', allowed: result.allowed,
                    reason: result.reason, latencyMs: Date.now() - t0,
                });

                if (!result.allowed) {
                    void this.emitViolation('bot', result.reason ?? 'BOT_DETECTED', ip, path, method, meta.requestId);
                    await this.penalizeIP(ip, 'bot', result.reason ?? 'BOT_DETECTED');
                    return this.buildBlockResult(
                        'bot', result.reason ?? 'BOT_DETECTED', 'block',
                        phases, responseHeaders, meta, pipelineStart, t0,
                    );
                }
            } catch (err) {
                this.handleStoreError('bot', err, phases, Date.now());
                if (this.config.onStoreFailure === 'closed') {
                    return this.buildBlockResult('bot', 'STORE_ERROR', 'block', phases, responseHeaders, meta, pipelineStart, Date.now());
                }
            }
        }

        // ── Fase 6: Geo Blocking ──────────────────────────────────────────
        if (this.geo) {
            const t0 = Date.now();
            try {
                const result = await this.geo.evaluate({
                    ip, method, path, headers: req.headers,
                } as GeoRequest);

                phases.push({
                    phase: 'geo', allowed: result.allowed,
                    reason: result.reason, latencyMs: Date.now() - t0,
                });

                if (!result.allowed) {
                    void this.emitViolation('geo', result.reason ?? 'GEO_BLOCKED', ip, path, method, meta.requestId);
                    return this.buildBlockResult(
                        'geo', result.reason ?? 'GEO_BLOCKED', 'block',
                        phases, responseHeaders, meta, pipelineStart, t0,
                    );
                }
            } catch (err) {
                this.handleStoreError('geo', err, phases, Date.now());
                if (this.config.onStoreFailure === 'closed') {
                    return this.buildBlockResult('geo', 'STORE_ERROR', 'block', phases, responseHeaders, meta, pipelineStart, Date.now());
                }
            }
        }

        // ── Fase 7: CSRF ──────────────────────────────────────────────────
        if (this.csrf) {
            const t0 = Date.now();
            try {
                // Gera token para GET (usado pelo cliente nos próximos POST/PUT)
                if (method === 'GET') {
                    const { cookieHeader } = await this.csrf.generateToken(req.sessionId);
                    responseHeaders['Set-Cookie'] = cookieHeader;
                    phases.push({ phase: 'csrf', allowed: true, latencyMs: Date.now() - t0 });
                } else {
                    const result = await this.csrf.validate({
                        method, path, headers: req.headers,
                        cookies, body: req.parsedBody as Record<string, unknown>,
                        sessionId: req.sessionId,
                    });

                    phases.push({
                        phase: 'csrf', allowed: result.valid,
                        reason: result.reason, latencyMs: Date.now() - t0,
                    });

                    if (!result.valid) {
                        void this.emitViolation('csrf', result.reason ?? 'CSRF_INVALID', ip, path, method, meta.requestId);
                        await this.penalizeIP(ip, 'csrf', result.reason ?? 'CSRF_INVALID');
                        return this.buildBlockResult(
                            'csrf', result.reason ?? 'CSRF_INVALID', 'block',
                            phases, responseHeaders, meta, pipelineStart, t0,
                        );
                    }
                }
            } catch (err) {
                this.handleStoreError('csrf', err, phases, Date.now());
                if (this.config.onStoreFailure === 'closed') {
                    return this.buildBlockResult('csrf', 'STORE_ERROR', 'block', phases, responseHeaders, meta, pipelineStart, Date.now());
                }
            }
        }

        // ── Pipeline concluída com sucesso ────────────────────────────────
        const result = this.buildAllowResult(phases, responseHeaders, meta, pipelineStart);
        this.config.onRequest?.(result);
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Métodos públicos de integração
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Registra resultado de um handler no circuit breaker do DDoS.
     * Chame após cada handler para manter o circuit breaker atualizado.
     *
     * @example
     * const result = await security.run(req);
     * try {
     *   const response = await handler(req);
     *   security.recordHandlerResult(req.path, response.status);
     *   return response;
     * } catch (err) {
     *   security.recordHandlerResult(req.path, 500);
     *   throw err;
     * }
     */
    recordHandlerResult(path: string, statusCode: number): void {
        this.ddos?.recordResponse(path, statusCode);
    }

    /**
     * Reporta uma violação de segurança detectada pelo handler.
     * Alimenta o IPFilter com informações de contexto de negócio.
     *
     * @example
     * // No handler de login:
     * if (!isValidPassword) {
     *   await security.reportViolation(req.ip, 'AUTH_BRUTEFORCE');
     * }
     */
    async reportViolation(ip: string, type: string, customScore?: number): Promise<void> {
        await this.ipFilter?.reportViolation(ip, type, customScore);
    }

    /**
     * Banimento manual de um IP.
     */
    async banIP(ip: string): Promise<void> {
        await this.ipFilter?.reportViolation(ip, 'MANUAL_BAN', 100);
    }

    /**
     * Remove banimento de um IP.
     */
    async unbanIP(ip: string): Promise<void> {
        await this.ipFilter?.unban(ip);
    }

    /**
     * Atualiza lista de Tor exit nodes em runtime.
     */
    updateTorExitNodes(nodes: string[]): void {
        this.ipFilter?.updateTorExitNodes(nodes);
    }

    /**
     * Retorna status do sistema para health check / observabilidade.
     */
    getStatus(): {
        phases: Partial<Record<SecurityPhase, boolean>>;
        ddosStatus?: ReturnType<DDoSProtection['getStatus']>;
        cacheStats?: ReturnType<GeoBlockMiddleware['getCacheStats']>;
    } {
        return {
            phases: {
                'ip-filter': !!this.ipFilter,
                'request-integrity': !!this.integrity,
                'rate-limit': !!this.rateLimiter,
                'ddos': !!this.ddos,
                'bot': !!this.bot,
                'geo': !!this.geo,
                'csrf': !!this.csrf,
                'cors': !!this.cors,
            },
            ddosStatus: this.ddos?.getStatus(),
            cacheStats: this.geo?.getCacheStats(),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários privados
    // ─────────────────────────────────────────────────────────────────────────

    private shouldBypass(path: string, method: string): boolean {
        if (this.config.bypassMethods.includes(method)) return true;
        for (const route of this.config.bypassRoutes) {
            if (typeof route === 'string') {
                if (path === route || path.startsWith(route + '/')) return true;
            } else if (route.test(path)) {
                return true;
            }
        }
        return false;
    }

    private async penalizeIP(ip: string, phase: SecurityPhase, reason: string): Promise<void> {
        if (!this.ipFilter) return;
        const score = PHASE_PENALTY_SCORES[phase] ?? 10;
        if (score > 0) {
            await this.ipFilter.reportViolation(ip, reason, score).catch(() => {
                // Penalização é best-effort — não falha a pipeline
            });
        }
    }

    private emitViolation(
        phase: SecurityPhase,
        reason: string,
        ip: string,
        path: string,
        method: string,
        requestId?: string,
    ): void {
        if (!this.config.onViolation) return;
        const event: SecurityViolationEvent = {
            phase, reason, ip, path, method, requestId,
            timestamp: Date.now(),
            penaltyScore: PHASE_PENALTY_SCORES[phase] ?? 10,
        };
        void this.config.onViolation(event);
    }

    private handleStoreError(phase: SecurityPhase, err: unknown, phases: PhaseResult[], t0: number): void {
        this.debugLog('STORE-ERROR', phase, err);
        phases.push({ phase, allowed: true, reason: 'STORE_ERROR', latencyMs: Date.now() - t0 });
    }

    private buildBlockResult(
        phase: SecurityPhase,
        reason: string,
        action: string,
        phases: PhaseResult[],
        headers: Record<string, string>,
        meta: SecurityMeta,
        start: number,
        t0: number,
    ): SecurityResult {
        phases.push({ phase, allowed: false, reason, action, latencyMs: Date.now() - t0 });
        const result: SecurityResult = {
            allowed: false,
            blockedBy: phase,
            reason,
            action,
            headers,
            phases,
            totalLatencyMs: Date.now() - start,
            meta,
        };
        this.config.onRequest?.(result);
        this.debugLog('BLOCKED', phase, reason, meta.ip);
        return result;
    }

    private buildAllowResult(
        phases: PhaseResult[],
        headers: Record<string, string>,
        meta: SecurityMeta,
        start: number,
    ): SecurityResult {
        return {
            allowed: true, headers, phases,
            totalLatencyMs: Date.now() - start,
            meta,
        };
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[security-pipeline]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Monta a resposta HTTP de bloqueio padronizada.
 * Não vaza detalhes internos ao cliente.
 */
function buildBlockResponse(
    result: SecurityResult,
): { status: number; body: string; headers: Record<string, string> } {
    const phase = result.blockedBy;
    const action = result.action;

    // Status HTTP por fase e ação
    let status = 403;
    if (action === 'throttle' || phase === 'rate-limit') status = 429;
    else if (phase === 'csrf') status = 403;
    else if (phase === 'cors') status = 403;
    else if (action === 'challenge') status = 403;

    const body = JSON.stringify({
        error: status === 429 ? 'Too Many Requests' : 'Forbidden',
        message: 'Request blocked by security policy.',
        requestId: result.meta.requestId,
    });

    return {
        status,
        body,
        headers: {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': 'no-store',
            ...result.headers,
        },
    };
}

// ── Express ──────────────────────────────────────────────────────────────────

type ExpressReq = {
    ip?: string; method: string; path: string;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown; rawBody?: Buffer; cookies?: Record<string, string>;
    user?: { id?: string }; secure?: boolean;
    session?: { id?: string };
};
type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    json(d: unknown): void; end(): void;
    locals: Record<string, unknown>;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware de segurança completo para Express.
 *
 * @example
 * const security = createSecurityPipeline({ store });
 * app.use(createExpressSecurityPipeline(security));
 *
 * // No handler, registre o resultado:
 * app.use((req, res, next) => {
 *   res.on('finish', () => security.recordHandlerResult(req.path, res.statusCode));
 *   next();
 * });
 */
export function createExpressSecurityPipeline(pipeline: SecurityPipeline) {
    return async (
        req: ExpressReq & { securityResult?: SecurityResult },
        res: ExpressRes,
        next: NextFn,
    ): Promise<void> => {
        const result = await pipeline.run({
            ip: req.ip,
            method: req.method,
            path: req.path,
            headers: req.headers,
            rawBody: req.rawBody,
            parsedBody: req.body,
            cookies: req.cookies,
            userId: req.user?.id,
            sessionId: req.session?.id,
            secure: req.secure,
            startedAt: Date.now(),
        });

        req.securityResult = result;

        // Aplica headers CORS + Rate Limit + CSRF na resposta
        if (Object.keys(result.headers).length > 0) {
            res.set(result.headers);
        }

        if (!result.allowed) {
            const { status, body, headers } = buildBlockResponse(result);
            res.status(status).set(headers).json(JSON.parse(body));
            return;
        }

        next();
    };
}

/**
 * Handler de segurança para Next.js middleware (Edge Runtime).
 *
 * @example
 * // middleware.ts
 * import { createNextSecurityPipeline, createSecurityPipeline } from './securityMiddleware';
 * const pipeline = createSecurityPipeline({ store: memoryStore });
 * export default createNextSecurityPipeline(pipeline);
 * export const config = { matcher: ['/api/:path*'] };
 */
export function createNextSecurityPipeline(pipeline: SecurityPipeline) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => { headers[key] = value; });

        const url = new URL(request.url);
        const rawBodyBuf = request.body
            ? new Uint8Array(await request.clone().arrayBuffer())
            : undefined;

        const result = await pipeline.run({
            ip: headers['cf-connecting-ip'] ?? headers['x-real-ip'] ?? '0.0.0.0',
            method: request.method,
            path: url.pathname,
            headers,
            rawBody: rawBodyBuf,
            secure: url.protocol === 'https:',
            startedAt: Date.now(),
        });

        if (!result.allowed) {
            const { status, body, headers: respHeaders } = buildBlockResponse(result);
            return new Response(body, { status, headers: respHeaders });
        }

        // Retorna null para continuar — o caller deve adicionar result.headers ao NextResponse
        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factories
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria uma pipeline de segurança completa.
 *
 * @example
 * // Mínimo (desenvolvimento):
 * const security = createSecurityPipeline({ store: createMemorySharedStore() });
 *
 * // Produção completa:
 * const security = createSecurityPipeline({
 *   store:  createRedisSharedStore(redis),
 *   geo:    { mode: 'allowlist', allowedCountries: ['BR', 'PT'] },
 *   csrf:   { strategy: 'signed-double-submit', secret: process.env.CSRF_SECRET! },
 *   cors:   { allowedOrigins: ['https://app.exemplo.com'] },
 *   phases: { geo: true, csrf: true, cors: true },
 *   onViolation: (event) => logger.warn('security-violation', event),
 *   onRequest:   (result) => metrics.record(result),
 * });
 */
export function createSecurityPipeline(
    config: SecurityPipelineConfig,
): SecurityPipeline {
    return new SecurityPipeline(config);
}

// ─────────────────────────────────────────────────────────────────────────────
// Store em memória compartilhado
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Implementação de store em memória que satisfaz todas as interfaces.
 * ⚠ Use apenas em desenvolvimento e testes. Não persiste entre restarts.
 *
 * @example
 * const store = createMemorySharedStore();
 * const security = createSecurityPipeline({ store });
 */
export function createMemorySharedStore(): SharedStore {
    const data = new Map<string, { value: number; expiresAt: number }>();
    const sets = new Map<string, { items: Set<string>; expiresAt: number }>();
    const bans = new Map<string, number>();

    const cleanup = setInterval(() => {
        const now = Date.now();
        for (const [k, v] of Array.from(data.entries())) {
            if (v.expiresAt < now) data.delete(k);
        }
        for (const [k, v] of Array.from(sets.entries())) {
            if (v.expiresAt < now) sets.delete(k);
        }
        for (const [k, v] of Array.from(bans.entries())) {
            if (v < now) bans.delete(k);
        }
    }, 30_000);

    if (typeof cleanup.unref === 'function') cleanup.unref();

    const now = () => Date.now();

    const get = async (key: string): Promise<number | null> => {
        const entry = data.get(key);
        if (!entry || entry.expiresAt < now()) return null;
        return entry.value;
    };

    const set = async (key: string, value: number, ttlMs: number): Promise<void> => {
        data.set(key, { value, expiresAt: now() + ttlMs });
    };

    const increment = async (key: string, ttlMs: number): Promise<number> => {
        const entry = data.get(key);
        const n = now();
        if (!entry || entry.expiresAt < n) {
            data.set(key, { value: 1, expiresAt: n + ttlMs });
            return 1;
        }
        entry.value++;
        return entry.value;
    };

    const exists = async (key: string): Promise<boolean> => {
        const entry = data.get(key);
        return !!entry && entry.expiresAt >= now();
    };

    const del = async (key: string): Promise<void> => { data.delete(key); sets.delete(key); };

    const ttl = async (key: string): Promise<number | null> => {
        const entry = data.get(key);
        if (!entry) return null;
        const rem = entry.expiresAt - now();
        return rem > 0 ? rem : null;
    };

    return {
        // BotProtectionStore, DDoSStore, RateLimitStore
        increment,
        get,
        set,
        exists,
        delete: del,

        // RateLimitStore extras
        ttl,
        incrementWithTTL: async (key: string, ttlMs: number) => {
            const count = await increment(key, ttlMs);
            const remaining = await ttl(key);
            return { count, ttlMs: remaining ?? ttlMs };
        },
        addToWindow: async (key: string, timestamp: number, windowMs: number): Promise<number> => {
            const n = now(); const cutoff = n - windowMs;
            const existing = sets.get(key);
            if (!existing || existing.expiresAt < n) {
                const s = new Set([String(timestamp)]);
                sets.set(key, { items: s, expiresAt: n + windowMs });
                return 1;
            }
            for (const t of Array.from(existing.items)) {
                if (parseInt(t, 10) < cutoff) existing.items.delete(t);
            }
            existing.items.add(String(timestamp));
            return existing.items.size;
        },
        getWindowEntries: async (key: string, windowStart: number): Promise<number[]> => {
            const entry = sets.get(key);
            if (!entry || entry.expiresAt < now()) return [];
            return Array.from(entry.items)
                .map(t => parseInt(t, 10))
                .filter(t => t >= windowStart);
        },
        multiIncrement: async (keys: Array<{ key: string; ttlMs: number }>): Promise<number[]> => {
            return Promise.all(keys.map(({ key, ttlMs }) => increment(key, ttlMs)));
        },

        // IPFilterStore extras
        getReputation: async (ip: string) => {
            const entry = data.get(`rep:${ip}`);
            if (!entry || entry.expiresAt < now()) return null;
            return JSON.parse(String(entry.value)) as any;
        },
        setReputation: async (ip: string, rep: any): Promise<void> => {
            data.set(`rep:${ip}`, { value: JSON.stringify(rep) as any, expiresAt: now() + 86_400_000 });
        },
        incrementScore: async (ip: string, delta: number, ttlMs: number): Promise<number> => {
            return increment(`score:${ip}`, ttlMs).then(v => Math.min(100, v + delta - 1));
        },
        ban: async (ip: string, expiresAt: number) => { bans.set(ip, expiresAt); },
        unban: async (ip: string) => { bans.delete(ip); },
        isBanned: async (ip: string): Promise<boolean> => {
            const exp = bans.get(ip);
            if (!exp) return false;
            if (exp < now()) { bans.delete(ip); return false; }
            return true;
        },
        addFingerprint: async (ip: string, fp: string, ttlMs: number): Promise<number> => {
            const key = `fp:${ip}`; const n = now();
            const existing = sets.get(key);
            if (!existing || existing.expiresAt < n) {
                sets.set(key, { items: new Set([fp]), expiresAt: n + ttlMs });
                return 1;
            }
            existing.items.add(fp);
            return existing.items.size;
        },
        countIPv6Prefix: async (prefix: string, ttlMs: number): Promise<number> => {
            return increment(`ipv6:${prefix}`, ttlMs);
        },
    };
}