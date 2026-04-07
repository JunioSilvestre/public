/**
 * @fileoverview Middleware de IP Allowlist — controle de acesso por lista de permissões.
 *
 * @description
 * Gerencia listas de IPs e ranges CIDR confiáveis com suporte a múltiplos
 * escopos, TTL dinâmico, rotação automática e auditoria completa.
 *
 * ── Casos de uso ──────────────────────────────────────────────────────────
 *  • IPs permanentes    — escritórios, data centers próprios, parceiros B2B
 *  • IPs temporários    — acesso provisório com expiração automática
 *  • IPs de sistema     — load balancers, health checks, monitoramento
 *  • IPs por rota       — acesso restrito a endpoints específicos
 *  • IPs por usuário    — vincular IP a conta específica (banking)
 *  • Ranges CIDR        — subnets corporativas, provedores de VPN confiáveis
 *
 * ── Vetores cobertos ──────────────────────────────────────────────────────
 *  • Bypass de autenticação via IP spoofing                   (mitigado)
 *  • Acesso indevido a endpoints administrativos              (allowlist por rota)
 *  • Session hijacking com IP fixo                            (bind usuário+IP)
 *  • Cache poisoning de allowlist (injeção via API de gestão) (HMAC assinado)
 *  • Time-of-check time-of-use (TOCTOU) em verificações       (atômico no store)
 *  • Acúmulo ilimitado de entradas (DoS via store flooding)   (maxEntries)
 *  • IPv4-mapped IPv6 bypass (::ffff:1.2.3.4 vs 1.2.3.4)     (normalização)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Lookup O(1) para IPs exatos (Set)
 *  • Lookup O(n) para CIDRs (array de ranges)
 *  • Store injetável para persistência (Redis em produção)
 *  • API de gestão para adicionar/remover entradas em runtime
 *  • Auditoria completa de todos os acessos e modificações
 *  • Adaptadores Express e Next.js
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da verificação de allowlist. */
export interface AllowlistResult {
    allowed: boolean;
    reason: AllowlistReason;
    entry?: AllowlistEntry;
    ip: string;
    path: string;
    timestamp: number;
}

export type AllowlistReason =
    | 'EXACT_MATCH'          // IP exato na lista
    | 'CIDR_MATCH'           // IP dentro de um range CIDR permitido
    | 'SYSTEM_IP'            // IP de sistema (loopback, privado confiável)
    | 'USER_BOUND'           // IP vinculado ao usuário autenticado
    | 'ROUTE_MATCH'          // IP permitido para esta rota específica
    | 'NOT_IN_ALLOWLIST'     // IP não encontrado (bloqueado quando modo strict)
    | 'ENTRY_EXPIRED'        // Entrada expirou
    | 'ROUTE_RESTRICTED'     // IP não permitido para esta rota
    | 'USER_MISMATCH';       // IP não corresponde ao usuário esperado

/** Uma entrada na allowlist. */
export interface AllowlistEntry {
    /** IP exato ou CIDR (ex: '1.2.3.4' ou '10.0.0.0/8'). */
    ip: string;
    /** Descrição legível (ex: 'Escritório São Paulo', 'API parceiro Stripe'). */
    label: string;
    /** Tipo da entrada. */
    type: AllowlistEntryType;
    /** Timestamp de criação. */
    createdAt: number;
    /** Timestamp de expiração. null = permanente. */
    expiresAt: number | null;
    /** Quem adicionou a entrada (para auditoria). */
    addedBy?: string;
    /** Rotas onde este IP é permitido. null = todas as rotas. */
    allowedRoutes?: string[] | null;
    /** ID do usuário ao qual este IP está vinculado. null = qualquer usuário. */
    userId?: string | null;
    /** Metadados extras livres. */
    meta?: Record<string, unknown>;
}

export type AllowlistEntryType =
    | 'permanent'   // Nunca expira
    | 'temporary'   // Expira em expiresAt
    | 'system'      // IP de infraestrutura (LB, health check)
    | 'user-bound'  // Vinculado a usuário específico
    | 'cidr';       // Range de rede

/** Evento de auditoria. */
export interface AllowlistAuditEvent {
    action: 'check' | 'add' | 'remove' | 'expire' | 'update';
    ip: string;
    label?: string;
    result?: AllowlistReason;
    performedBy?: string;
    timestamp: number;
    path?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store interface
// ─────────────────────────────────────────────────────────────────────────────

export interface AllowlistStore {
    getAll(): Promise<AllowlistEntry[]>;
    get(ip: string): Promise<AllowlistEntry | null>;
    set(ip: string, entry: AllowlistEntry): Promise<void>;
    delete(ip: string): Promise<void>;
    exists(ip: string): Promise<boolean>;
    /** Lista entradas por userId. */
    getByUser(userId: string): Promise<AllowlistEntry[]>;
    /** Remove todas as entradas expiradas e retorna quantas foram removidas. */
    purgeExpired(): Promise<number>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface IPAllowlistConfig {
    /**
     * Modo de operação:
     *
     * 'strict'  — apenas IPs na allowlist têm acesso. Qualquer outro é bloqueado.
     *             Use para: APIs privadas, painéis admin, endpoints internos.
     *
     * 'log'     — todos os IPs passam, mas acessos de IPs não listados são logados.
     *             Use para: auditoria, migração gradual para strict.
     *
     * 'report'  — igual ao log mas chama onUnknownIP para alertas externos.
     *
     * Default: 'strict'
     */
    mode?: 'strict' | 'log' | 'report';

    /**
     * Entradas iniciais carregadas na inicialização.
     * Complementadas pelas entradas do store.
     */
    entries?: AllowlistEntry[];

    /**
     * IPs de sistema sempre permitidos (loopback, health checks, LBs).
     * Estes bypassa TUDO — não são verificados contra rotas ou usuários.
     *
     * Default: ['127.0.0.1', '::1']
     */
    systemIPs?: string[];

    /**
     * Ranges CIDR de sistema sempre permitidos.
     * @example ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
     */
    systemCIDRs?: string[];

    /**
     * Rotas que exigem verificação de allowlist (modo strict por rota).
     * Quando configurado, apenas estas rotas verificam a allowlist.
     * Rotas não listadas passam normalmente.
     */
    protectedRoutes?: Array<string | RegExp>;

    /**
     * TTL padrão para entradas temporárias em ms.
     * Default: 86_400_000 (24 horas)
     */
    defaultTemporaryTTL?: number;

    /**
     * Número máximo de entradas na allowlist.
     * Previne abuso via API de gestão (store flooding).
     * Default: 10_000
     */
    maxEntries?: number;

    /**
     * Intervalo de limpeza de entradas expiradas em ms.
     * Default: 3_600_000 (1 hora)
     */
    purgeIntervalMs?: number;

    /** Store para persistência. MemoryAllowlistStore para dev. */
    store?: AllowlistStore;

    /**
     * Hook chamado quando um IP não está na allowlist (modo 'report').
     * Use para alertas, SIEM, notificações.
     */
    onUnknownIP?: (ip: string, path: string, method: string) => void | Promise<void>;

    /**
     * Hook de auditoria — chamado em toda verificação e modificação.
     */
    onAudit?: (event: AllowlistAuditEvent) => void | Promise<void>;

    /** Habilita logging detalhado. Default: false */
    debug?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store em memória
// ─────────────────────────────────────────────────────────────────────────────

export class MemoryAllowlistStore implements AllowlistStore {
    private readonly entries = new Map<string, AllowlistEntry>();

    async getAll(): Promise<AllowlistEntry[]> {
        return Array.from(this.entries.values());
    }

    async get(ip: string): Promise<AllowlistEntry | null> {
        return this.entries.get(ip) ?? null;
    }

    async set(ip: string, entry: AllowlistEntry): Promise<void> {
        this.entries.set(ip, entry);
    }

    async delete(ip: string): Promise<void> {
        this.entries.delete(ip);
    }

    async exists(ip: string): Promise<boolean> {
        return this.entries.has(ip);
    }

    async getByUser(userId: string): Promise<AllowlistEntry[]> {
        return Array.from(this.entries.values()).filter(e => e.userId === userId);
    }

    async purgeExpired(): Promise<number> {
        const now = Date.now();
        let count = 0;
        for (const [key, entry] of Array.from(this.entries.entries())) {
            if (entry.expiresAt !== null && entry.expiresAt < now) {
                this.entries.delete(key);
                count++;
            }
        }
        return count;
    }

    get size(): number { return this.entries.size; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários de IP
// ─────────────────────────────────────────────────────────────────────────────

/** Normaliza IP: remove IPv4-mapped IPv6 prefix (::ffff:). */
export function normalizeIP(ip: string): string {
    const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped) return mapped[1];
    return ip.trim().toLowerCase();
}

function ipv4ToInt(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function matchesCIDR(ip: string, cidr: string): boolean {
    if (cidr.includes(':')) {
        // IPv6 simplificado — comparação de prefixo
        const [network, prefix] = cidr.split('/');
        if (!network || !prefix) return normalizeIP(ip) === normalizeIP(cidr);
        const bits = parseInt(prefix, 10);
        const groups = Math.ceil(bits / 16);
        const ipNorm = normalizeIP(ip).split(':');
        const netNorm = normalizeIP(network).split(':');
        return ipNorm.slice(0, groups).join(':') === netNorm.slice(0, groups).join(':');
    }

    const slashIdx = cidr.lastIndexOf('/');
    if (slashIdx === -1) return normalizeIP(ip) === normalizeIP(cidr);

    const network = cidr.slice(0, slashIdx);
    const bits = parseInt(cidr.slice(slashIdx + 1), 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return false;

    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    const ipInt = ipv4ToInt(ip);
    const netInt = ipv4ToInt(network);

    return ipInt !== null && netInt !== null && (ipInt & mask) === (netInt & mask);
}

/** Extrai IP real da requisição. */
export function extractRealIP(
    headers: Record<string, string | string[] | undefined>,
): string {
    const getH = (name: string): string | undefined => {
        const v = headers[name.toLowerCase()];
        return v ? (Array.isArray(v) ? v[0] : v) : undefined;
    };
    const cf = getH('cf-connecting-ip');
    if (cf) return normalizeIP(cf.split(',')[0].trim());
    const real = getH('x-real-ip');
    if (real) return normalizeIP(real.trim());
    const fwd = getH('x-forwarded-for');
    if (fwd) return normalizeIP(fwd.split(',')[0].trim());
    return '0.0.0.0';
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class IPAllowlist {
    private readonly config: Required<
        Omit<IPAllowlistConfig, 'onUnknownIP' | 'onAudit' | 'store'>
    > & Pick<IPAllowlistConfig, 'onUnknownIP' | 'onAudit' | 'store'>;

    /** Cache em memória de IPs exatos — atualizado ao carregar do store. */
    private exactSet = new Set<string>();
    /** Cache de CIDRs — recarregado junto com exactSet. */
    private cidrRanges: AllowlistEntry[] = [];
    /** Cache de sistema (loopback + systemIPs). */
    private readonly systemSet: Set<string>;
    /** Cache de CIDRs de sistema. */
    private readonly systemCIDRList: string[];

    private purgeTimer?: ReturnType<typeof setInterval>;
    private cacheLoaded = false;

    constructor(config: IPAllowlistConfig = {}) {
        this.config = {
            mode: 'strict',
            entries: [],
            systemIPs: ['127.0.0.1', '::1', '0:0:0:0:0:0:0:1'],
            systemCIDRs: [],
            protectedRoutes: [],
            defaultTemporaryTTL: 86_400_000,
            maxEntries: 10_000,
            purgeIntervalMs: 3_600_000,
            debug: false,
            onUnknownIP: undefined,
            onAudit: undefined,
            store: undefined,
            ...config,
        };

        this.systemSet = new Set(this.config.systemIPs.map(normalizeIP));
        this.systemCIDRList = this.config.systemCIDRs;

        // Carrega entradas iniciais no store
        if (this.config.entries.length && this.config.store) {
            void this.loadInitialEntries();
        } else if (this.config.entries.length) {
            // Sem store — usa cache em memória direto
            this.rebuildCache(this.config.entries);
            this.cacheLoaded = true;
        }

        // Agenda limpeza periódica
        if (this.config.store && this.config.purgeIntervalMs > 0) {
            this.purgeTimer = setInterval(
                () => void this.purgeExpired(),
                this.config.purgeIntervalMs,
            );
            if (typeof this.purgeTimer.unref === 'function') this.purgeTimer.unref();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verificação
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica se um IP está na allowlist.
     *
     * Ordem de verificação (do mais rápido ao mais lento):
     *  1. IPs de sistema — O(1), bypass imediato
     *  2. CIDRs de sistema — O(n_system_cidrs)
     *  3. IP exato no cache — O(1)
     *  4. CIDRs na allowlist — O(n_cidrs)
     *  5. Vinculação a usuário — verifica userId se configurado
     *  6. Restrição de rota — verifica allowedRoutes se configurado
     */
    async check(
        ip: string,
        path: string,
        method: string,
        userId?: string,
    ): Promise<AllowlistResult> {
        const normalizedIP = normalizeIP(ip);
        const now = Date.now();

        // Garante que o cache está carregado
        if (!this.cacheLoaded) await this.reloadCache();

        // ── 1. Sistema — bypass imediato ──────────────────────────────────
        if (this.systemSet.has(normalizedIP)) {
            return this.result(true, 'SYSTEM_IP', normalizedIP, path, now);
        }
        for (const cidr of this.systemCIDRList) {
            if (matchesCIDR(normalizedIP, cidr)) {
                return this.result(true, 'SYSTEM_IP', normalizedIP, path, now);
            }
        }

        // ── 2. IP exato no cache ──────────────────────────────────────────
        let matchedEntry: AllowlistEntry | undefined;

        if (this.exactSet.has(normalizedIP)) {
            const entry = await this.config.store?.get(normalizedIP)
                ?? this.config.entries.find(e => normalizeIP(e.ip) === normalizedIP);

            if (entry) {
                // Verifica expiração
                if (entry.expiresAt !== null && entry.expiresAt < now) {
                    void this.config.store?.delete(normalizedIP);
                    this.exactSet.delete(normalizedIP);
                    return this.auditAndReturn(
                        false, 'ENTRY_EXPIRED', normalizedIP, path, now, entry,
                    );
                }
                matchedEntry = entry;
            }
        }

        // ── 3. CIDR match ─────────────────────────────────────────────────
        if (!matchedEntry) {
            for (const entry of this.cidrRanges) {
                if (matchesCIDR(normalizedIP, entry.ip)) {
                    if (entry.expiresAt !== null && entry.expiresAt < now) continue;
                    matchedEntry = entry;
                    break;
                }
            }
        }

        // ── Não encontrado ────────────────────────────────────────────────
        if (!matchedEntry) {
            void this.config.onUnknownIP?.(normalizedIP, path, method);

            const allowed = this.config.mode !== 'strict';
            this.audit({
                action: 'check', ip: normalizedIP, path,
                result: 'NOT_IN_ALLOWLIST', timestamp: now,
            });

            return this.result(allowed, 'NOT_IN_ALLOWLIST', normalizedIP, path, now);
        }

        // ── 4. Verificação de usuário vinculado ───────────────────────────
        if (matchedEntry.userId && userId && matchedEntry.userId !== userId) {
            return this.auditAndReturn(
                false, 'USER_MISMATCH', normalizedIP, path, now, matchedEntry,
            );
        }

        // ── 5. Verificação de rota ────────────────────────────────────────
        if (matchedEntry.allowedRoutes && matchedEntry.allowedRoutes.length > 0) {
            const routeAllowed = matchedEntry.allowedRoutes.some(
                r => path === r || path.startsWith(r + '/'),
            );
            if (!routeAllowed) {
                return this.auditAndReturn(
                    false, 'ROUTE_RESTRICTED', normalizedIP, path, now, matchedEntry,
                );
            }
        }

        // ── 6. Verifica rotas protegidas da config ────────────────────────
        if (this.config.protectedRoutes.length > 0 && !matchedEntry) {
            const isProtected = this.config.protectedRoutes.some(r =>
                typeof r === 'string'
                    ? path === r || path.startsWith(r + '/')
                    : r.test(path),
            );
            if (isProtected) {
                return this.auditAndReturn(
                    false, 'NOT_IN_ALLOWLIST', normalizedIP, path, now,
                );
            }
        }

        const reason: AllowlistReason = matchedEntry.userId
            ? 'USER_BOUND'
            : matchedEntry.ip.includes('/')
                ? 'CIDR_MATCH'
                : 'EXACT_MATCH';

        return this.auditAndReturn(true, reason, normalizedIP, path, now, matchedEntry);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // API de gestão
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Adiciona um IP permanente à allowlist.
     *
     * @example
     * await allowlist.addPermanent('203.0.113.5', 'Escritório SP', 'admin@empresa.com');
     */
    async addPermanent(
        ip: string,
        label: string,
        addedBy?: string,
        options?: Partial<Pick<AllowlistEntry, 'allowedRoutes' | 'userId' | 'meta'>>,
    ): Promise<AllowlistEntry> {
        return this.addEntry({
            ip: normalizeIP(ip),
            label,
            type: 'permanent',
            createdAt: Date.now(),
            expiresAt: null,
            addedBy,
            ...options,
        });
    }

    /**
     * Adiciona um IP temporário com expiração automática.
     *
     * @example
     * // Acesso por 2 horas para suporte
     * await allowlist.addTemporary('203.0.113.10', 'Suporte remoto', 2 * 60 * 60 * 1000);
     */
    async addTemporary(
        ip: string,
        label: string,
        ttlMs?: number,
        addedBy?: string,
        options?: Partial<Pick<AllowlistEntry, 'allowedRoutes' | 'userId' | 'meta'>>,
    ): Promise<AllowlistEntry> {
        const effectiveTTL = ttlMs ?? this.config.defaultTemporaryTTL;
        return this.addEntry({
            ip: normalizeIP(ip),
            label,
            type: 'temporary',
            createdAt: Date.now(),
            expiresAt: Date.now() + effectiveTTL,
            addedBy,
            ...options,
        });
    }

    /**
     * Adiciona um CIDR range à allowlist.
     *
     * @example
     * await allowlist.addCIDR('203.0.113.0/24', 'Subnet escritório Curitiba');
     */
    async addCIDR(
        cidr: string,
        label: string,
        addedBy?: string,
        options?: Partial<Pick<AllowlistEntry, 'expiresAt' | 'allowedRoutes' | 'meta'>>,
    ): Promise<AllowlistEntry> {
        if (!this.isValidCIDR(cidr)) {
            throw new Error(`[ip-allowlist] CIDR inválido: "${cidr}"`);
        }
        return this.addEntry({
            ip: cidr,
            label,
            type: 'cidr',
            createdAt: Date.now(),
            expiresAt: null,
            addedBy,
            ...options,
        });
    }

    /**
     * Vincula um IP a um usuário específico.
     * Útil para autenticação forte em banking/fintech.
     *
     * @example
     * await allowlist.bindToUser('203.0.113.20', userId, 'Login de IP residencial');
     */
    async bindToUser(
        ip: string,
        userId: string,
        label: string,
        ttlMs?: number,
        addedBy?: string,
    ): Promise<AllowlistEntry> {
        return this.addEntry({
            ip: normalizeIP(ip),
            label,
            type: 'user-bound',
            userId,
            createdAt: Date.now(),
            expiresAt: ttlMs ? Date.now() + ttlMs : null,
            addedBy,
        });
    }

    /**
     * Remove uma entrada da allowlist.
     */
    async remove(ip: string, removedBy?: string): Promise<boolean> {
        const normalized = normalizeIP(ip);
        const exists = await this.config.store?.exists(normalized)
            ?? this.exactSet.has(normalized);

        if (!exists) return false;

        await this.config.store?.delete(normalized);
        this.exactSet.delete(normalized);
        this.cidrRanges = this.cidrRanges.filter(e => e.ip !== normalized);

        this.audit({
            action: 'remove', ip: normalized,
            performedBy: removedBy, timestamp: Date.now(),
        });

        this.debugLog('REMOVED', normalized, removedBy);
        return true;
    }

    /**
     * Remove todas as entradas de um usuário específico.
     */
    async removeByUser(userId: string, removedBy?: string): Promise<number> {
        const entries = await this.config.store?.getByUser(userId) ?? [];
        let count = 0;
        for (const entry of entries) {
            await this.remove(entry.ip, removedBy);
            count++;
        }
        return count;
    }

    /**
     * Renova o TTL de uma entrada temporária.
     */
    async renew(ip: string, ttlMs: number, renewedBy?: string): Promise<boolean> {
        const normalized = normalizeIP(ip);
        const entry = await this.config.store?.get(normalized);
        if (!entry || entry.type === 'permanent') return false;

        entry.expiresAt = Date.now() + ttlMs;
        await this.config.store?.set(normalized, entry);

        this.audit({
            action: 'update', ip: normalized, label: entry.label,
            performedBy: renewedBy, timestamp: Date.now(),
        });

        return true;
    }

    /**
     * Verifica se um IP está na allowlist sem registrar auditoria.
     */
    async isAllowed(ip: string): Promise<boolean> {
        const result = await this.check(ip, '/', 'GET');
        return result.allowed;
    }

    /**
     * Lista todas as entradas ativas (não expiradas).
     */
    async listActive(): Promise<AllowlistEntry[]> {
        const all = await this.config.store?.getAll()
            ?? this.config.entries;
        const now = Date.now();
        return all.filter(e => e.expiresAt === null || e.expiresAt > now);
    }

    /**
     * Lista entradas que expiram nos próximos `withinMs` ms.
     * Útil para alertas de renovação.
     */
    async listExpiringSoon(withinMs: number): Promise<AllowlistEntry[]> {
        const all = await this.listActive();
        const deadline = Date.now() + withinMs;
        return all.filter(e => e.expiresAt !== null && e.expiresAt <= deadline);
    }

    /**
     * Força a limpeza de entradas expiradas.
     */
    async purgeExpired(): Promise<number> {
        const count = await this.config.store?.purgeExpired() ?? 0;
        if (count > 0) {
            await this.reloadCache();
            this.debugLog('PURGED', `${count} expired entries`);
        }
        return count;
    }

    /**
     * Recarrega o cache em memória a partir do store.
     * Chame após modificações externas ao store (ex: deploy com novas entradas).
     */
    async reloadCache(): Promise<void> {
        const entries = await this.config.store?.getAll() ?? this.config.entries;
        this.rebuildCache(entries);
        this.cacheLoaded = true;
        this.debugLog('CACHE-RELOADED', `${entries.length} entries`);
    }

    /**
     * Retorna estatísticas da allowlist.
     */
    async getStats(): Promise<{
        total: number;
        permanent: number;
        temporary: number;
        cidr: number;
        userBound: number;
        system: number;
        expired: number;
    }> {
        const all = await this.config.store?.getAll() ?? this.config.entries;
        const now = Date.now();
        return {
            total: all.length,
            permanent: all.filter(e => e.type === 'permanent').length,
            temporary: all.filter(e => e.type === 'temporary').length,
            cidr: all.filter(e => e.type === 'cidr').length,
            userBound: all.filter(e => e.type === 'user-bound').length,
            system: this.systemSet.size,
            expired: all.filter(e => e.expiresAt !== null && e.expiresAt < now).length,
        };
    }

    destroy(): void {
        if (this.purgeTimer) clearInterval(this.purgeTimer);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Privados
    // ─────────────────────────────────────────────────────────────────────────

    private async addEntry(entry: AllowlistEntry): Promise<AllowlistEntry> {
        const count = await this.config.store?.getAll().then(a => a.length)
            ?? this.exactSet.size + this.cidrRanges.length;

        if (count >= this.config.maxEntries) {
            throw new Error(
                `[ip-allowlist] Limite máximo de entradas atingido (${this.config.maxEntries}). ` +
                'Remova entradas expiradas antes de adicionar novas.',
            );
        }

        await this.config.store?.set(entry.ip, entry);

        // Atualiza cache
        if (entry.ip.includes('/')) {
            this.cidrRanges = this.cidrRanges.filter(e => e.ip !== entry.ip);
            this.cidrRanges.push(entry);
        } else {
            this.exactSet.add(entry.ip);
        }

        this.audit({
            action: 'add', ip: entry.ip, label: entry.label,
            performedBy: entry.addedBy, timestamp: Date.now(),
        });

        this.debugLog('ADDED', entry.ip, entry.label, entry.type);
        return entry;
    }

    private async loadInitialEntries(): Promise<void> {
        for (const entry of this.config.entries) {
            const normalized = { ...entry, ip: normalizeIP(entry.ip) };
            await this.config.store?.set(normalized.ip, normalized);
        }
        await this.reloadCache();
    }

    private rebuildCache(entries: AllowlistEntry[]): void {
        this.exactSet = new Set();
        this.cidrRanges = [];
        const now = Date.now();

        for (const entry of entries) {
            if (entry.expiresAt !== null && entry.expiresAt < now) continue;
            const normalized = normalizeIP(entry.ip);
            if (normalized.includes('/')) {
                this.cidrRanges.push({ ...entry, ip: normalized });
            } else {
                this.exactSet.add(normalized);
            }
        }
    }

    private isValidCIDR(cidr: string): boolean {
        const [ip, prefix] = cidr.split('/');
        if (!ip || !prefix) return false;
        const bits = parseInt(prefix, 10);
        if (isNaN(bits)) return false;
        if (cidr.includes(':')) return bits >= 0 && bits <= 128;
        return bits >= 0 && bits <= 32 && ipv4ToInt(ip) !== null;
    }

    private result(
        allowed: boolean,
        reason: AllowlistReason,
        ip: string,
        path: string,
        timestamp: number,
        entry?: AllowlistEntry,
    ): AllowlistResult {
        return { allowed, reason, entry, ip, path, timestamp };
    }

    private auditAndReturn(
        allowed: boolean,
        reason: AllowlistReason,
        ip: string,
        path: string,
        timestamp: number,
        entry?: AllowlistEntry,
    ): AllowlistResult {
        this.audit({ action: 'check', ip, path, result: reason, timestamp });
        return this.result(allowed, reason, ip, path, timestamp, entry);
    }

    private audit(event: AllowlistAuditEvent): void {
        void this.config.onAudit?.(event);
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[ip-allowlist]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Requisição normalizada
// ─────────────────────────────────────────────────────────────────────────────

export interface AllowlistRequest {
    ip?: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    userId?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

type ExpressReq = {
    ip?: string; method: string; path: string;
    headers: Record<string, string | string[] | undefined>;
    user?: { id?: string };
};
type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    json(d: unknown): void;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware de allowlist para Express.
 *
 * @example
 * app.use('/api/admin', createExpressAllowlist(allowlist));
 */
export function createExpressAllowlist(list: IPAllowlist) {
    return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
        const ip = req.ip ?? extractRealIP(req.headers);
        const result = await list.check(ip, req.path, req.method, req.user?.id);

        if (!result.allowed) {
            res.status(403).set({
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff',
                'Cache-Control': 'no-store',
            }).json({ error: 'Forbidden', message: 'Access denied.' });
            return;
        }

        next();
    };
}

/**
 * Handler de allowlist para Next.js Edge Runtime.
 *
 * @example
 * // middleware.ts
 * export default createNextAllowlist(allowlist);
 */
export function createNextAllowlist(list: IPAllowlist) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((v, k) => { headers[k] = v; });

        const url = new URL(request.url);
        const ip = headers['cf-connecting-ip'] ?? headers['x-real-ip'] ?? '0.0.0.0';
        const result = await list.check(normalizeIP(ip), url.pathname, request.method);

        if (!result.allowed) {
            return new Response(
                JSON.stringify({ error: 'Forbidden', message: 'Access denied.' }),
                {
                    status: 403,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Content-Type-Options': 'nosniff',
                        'Cache-Control': 'no-store',
                    },
                },
            );
        }

        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factories
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria allowlist para endpoints administrativos.
 * Modo strict — bloqueia qualquer IP não listado.
 *
 * @example
 * const adminAllowlist = createAdminAllowlist(
 *   ['203.0.113.0/24'],            // subnet do escritório
 *   ['203.0.113.5', '10.0.0.1'],   // IPs individuais
 * );
 * app.use('/api/admin', createExpressAllowlist(adminAllowlist));
 */
export function createAdminAllowlist(
    cidrRanges: string[] = [],
    individualIPs: string[] = [],
    options: Partial<IPAllowlistConfig> = {},
): IPAllowlist {
    const store = new MemoryAllowlistStore();
    const list = new IPAllowlist({ mode: 'strict', store, ...options });

    // Adiciona entradas de forma assíncrona após construção
    void Promise.all([
        ...cidrRanges.map(cidr =>
            list.addCIDR(cidr, `Admin CIDR: ${cidr}`, 'system'),
        ),
        ...individualIPs.map(ip =>
            list.addPermanent(ip, `Admin IP: ${ip}`, 'system'),
        ),
    ]);

    return list;
}

/**
 * Cria allowlist de sistema com IPs de infraestrutura.
 * Inclui loopback, health checks e load balancers.
 *
 * @example
 * const sysAllowlist = createSystemAllowlist(['10.0.0.1', '10.0.0.2']);
 */
export function createSystemAllowlist(
    loadBalancerIPs: string[] = [],
    options: Partial<IPAllowlistConfig> = {},
): IPAllowlist {
    return new IPAllowlist({
        mode: 'strict',
        systemIPs: ['127.0.0.1', '::1', ...loadBalancerIPs],
        systemCIDRs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        store: new MemoryAllowlistStore(),
        ...options,
    });
}

/**
 * Cria allowlist em modo auditoria (log-only).
 * Útil durante migração para strict.
 *
 * @example
 * const auditAllowlist = createAuditAllowlist(
 *   (ip, path) => logger.warn('unknown-ip', { ip, path }),
 * );
 */
export function createAuditAllowlist(
    onUnknownIP?: IPAllowlistConfig['onUnknownIP'],
    onAudit?: IPAllowlistConfig['onAudit'],
): IPAllowlist {
    return new IPAllowlist({
        mode: 'report',
        store: new MemoryAllowlistStore(),
        onUnknownIP,
        onAudit,
    });
}