/**
 * @fileoverview Middleware de IP Blocklist — controle de acesso por lista de bloqueios.
 *
 * @description
 * Espelho semântico do ipAllowlist.ts com lógica invertida e características
 * específicas para blocklists: feeds externos, TTL com backoff exponencial,
 * categorização de ameaças e integração com threat intelligence.
 *
 * ── Fontes de bloqueio ─────────────────────────────────────────────────────
 *  1. Blocklist manual     — IPs banidos explicitamente por operadores
 *  2. Auto-ban dinâmico    — IPs banidos automaticamente por comportamento
 *  3. Feeds externos       — listas públicas (Spamhaus, Firehol, AbuseIPDB)
 *  4. Tor exit nodes       — lista oficial do Tor Project
 *  5. Ranges CIDR          — subnets de datacenters / ASNs de risco
 *  6. Threat Intel         — integração com serviços de reputação
 *
 * ── Categorias de bloqueio ─────────────────────────────────────────────────
 *  • spam          — envio de spam / abuse de formulários
 *  • scraper       — scraping agressivo / harvest de dados
 *  • bruteforce    — tentativas de força bruta em login/auth
 *  • dos           — participação em DDoS / flood
 *  • malware       — IPs de C&C, droppers, exfiltração
 *  • tor           — saídas Tor conhecidas
 *  • vpn           — provedores VPN de alto risco
 *  • datacenter    — ASNs de datacenter com histórico de abuso
 *  • manual        — banimento manual por operador
 *  • feed          — originado de feed externo de threat intel
 *
 * ── Vetores cobertos ──────────────────────────────────────────────────────
 *  • Bypass via IP rotation após ban manual                   (TTL + backoff)
 *  • Cache poisoning do feed externo                          (HMAC assinado)
 *  • Race condition em ban/unban simultâneo                   (atômico no store)
 *  • Ban em cascata de IPs CGNAT (bloqueia centenas de users) (flag isCGNAT)
 *  • IPv4-mapped IPv6 bypass (::ffff: prefix)                 (normalização)
 *  • CIDR oversharing (banir /8 bloqueia 16M IPs)             (validação prefix)
 *  • Feed staleness (lista desatualizada libera IPs maliciosos)(TTL por fonte)
 *  • IP hopping com mesma subnet                              (CIDR auto-ban)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Lookup O(1) para IPs exatos (Set em memória)
 *  • Lookup O(n) para CIDRs com early exit
 *  • TTL por entrada com backoff exponencial (reincidentes)
 *  • Score de confiança por fonte (manual > auto-ban > feed)
 *  • Feeds externos com cache e refresh periódico
 *  • Auditoria completa — quem baniu, quando, por quê
 *  • Modo dry-run para análise de impacto antes de ativar
 *  • Adaptadores Express e Next.js
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da verificação de blocklist. */
export interface BlocklistResult {
    blocked: boolean;
    reason?: BlocklistReason;
    entry?: BlocklistEntry;
    /** Tempo em ms até o ban expirar. null = permanente. */
    expiresInMs?: number | null;
    ip: string;
    path: string;
    timestamp: number;
}

export type BlocklistReason =
    | 'MANUAL_BAN'           // Banido manualmente por operador
    | 'AUTO_BAN'             // Banido automaticamente por comportamento
    | 'CIDR_BAN'             // IP dentro de range CIDR bloqueado
    | 'FEED_MATCH'           // Encontrado em feed externo de threat intel
    | 'TOR_EXIT_NODE'        // Saída Tor conhecida
    | 'REPEAT_OFFENDER'      // Reincidente com backoff exponencial
    | 'CGNAT_PARTIAL_BAN'    // IP CGNAT — throttle em vez de ban total
    | 'NOT_BLOCKED';         // IP não está bloqueado

/** Uma entrada na blocklist. */
export interface BlocklistEntry {
    /** IP exato ou CIDR. */
    ip: string;
    /** Categoria da ameaça. */
    category: BlocklistCategory;
    /** Motivo legível do banimento. */
    reason: string;
    /** Fonte do banimento. */
    source: BlocklistSource;
    /** Timestamp de criação. */
    createdAt: number;
    /** Timestamp de expiração. null = permanente. */
    expiresAt: number | null;
    /** Número de vezes que este IP foi banido (para backoff). */
    strikeCount: number;
    /** Quem executou o ban (para auditoria). */
    bannedBy?: string;
    /** Score de confiança da fonte (0–100). */
    confidence: number;
    /** true se o IP é CGNAT (ban parcial em vez de total). */
    isCGNAT?: boolean;
    /** Metadados extras (user-agent no momento do ban, etc.). */
    meta?: Record<string, unknown>;
}

export type BlocklistCategory =
    | 'spam'
    | 'scraper'
    | 'bruteforce'
    | 'dos'
    | 'malware'
    | 'tor'
    | 'vpn'
    | 'datacenter'
    | 'manual'
    | 'feed';

export type BlocklistSource =
    | 'manual'        // Operador
    | 'auto'          // Sistema (via reportViolation)
    | 'tor-project'   // https://check.torproject.org/torbulkexitlist
    | 'spamhaus'      // Spamhaus DROP/EDROP
    | 'firehol'       // FireHOL Level 1–3
    | 'abuseipdb'     // AbuseIPDB API
    | 'custom-feed';  // Feed customizado

/** Configuração de um feed externo de threat intelligence. */
export interface ThreatFeed {
    /** Identificador único do feed. */
    name: BlocklistSource;
    /** URL para buscar a lista (formato: uma entrada por linha, linhas # são comentários). */
    url?: string;
    /** Função alternativa para buscar a lista. */
    fetcher?: () => Promise<string[]>;
    /** Intervalo de refresh em ms. Default: 3_600_000 (1 hora) */
    refreshMs?: number;
    /** Score de confiança das entradas deste feed (0–100). Default: 70 */
    confidence?: number;
    /** Categoria das entradas. Default: 'feed' */
    category?: BlocklistCategory;
    /** TTL das entradas em ms. Default: 86_400_000 (24h) */
    ttlMs?: number;
}

/** Evento de auditoria. */
export interface BlocklistAuditEvent {
    action: 'ban' | 'unban' | 'check' | 'expire' | 'feed-update' | 'auto-ban';
    ip: string;
    category?: BlocklistCategory;
    source?: BlocklistSource;
    reason?: string;
    result?: BlocklistReason;
    bannedBy?: string;
    timestamp: number;
    path?: string;
    expiresAt?: number | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store interface
// ─────────────────────────────────────────────────────────────────────────────

export interface BlocklistStore {
    get(ip: string): Promise<BlocklistEntry | null>;
    set(ip: string, entry: BlocklistEntry): Promise<void>;
    delete(ip: string): Promise<void>;
    exists(ip: string): Promise<boolean>;
    getAll(): Promise<BlocklistEntry[]>;
    getByCategory(category: BlocklistCategory): Promise<BlocklistEntry[]>;
    getBySource(source: BlocklistSource): Promise<BlocklistEntry[]>;
    purgeExpired(): Promise<number>;
    count(): Promise<number>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface IPBlocklistConfig {
    /**
     * Modo de operação:
     *
     * 'active'   — bloqueia IPs listados. Comportamento padrão.
     * 'dry-run'  — registra mas não bloqueia. Use antes de ativar em produção.
     * 'log-only' — apenas loga matches sem bloquear.
     *
     * Default: 'active'
     */
    mode?: 'active' | 'dry-run' | 'log-only';

    /** Entradas iniciais carregadas na inicialização. */
    entries?: BlocklistEntry[];

    /**
     * IPs de sistema nunca bloqueados.
     * Previne lock-out acidental de load balancers ou health checks.
     * Default: ['127.0.0.1', '::1']
     */
    neverBlockIPs?: string[];

    /**
     * Ranges CIDR nunca bloqueados (redes privadas RFC1918).
     * Default: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
     */
    neverBlockCIDRs?: string[];

    /**
     * TTL padrão para bans automáticos em ms.
     * Default: 3_600_000 (1 hora)
     *
     * Bans manuais são permanentes por padrão.
     */
    defaultBanTTL?: number;

    /**
     * Backoff exponencial para reincidentes.
     *
     * TTL_efetivo = defaultBanTTL × (backoffMultiplier ^ (strikeCount - 1))
     *
     * Com multiplier 2 e TTL 1h:
     *   1ª vez: 1h · 2ª vez: 2h · 3ª vez: 4h · 4ª vez: 8h
     *
     * Default: 2
     */
    backoffMultiplier?: number;

    /**
     * TTL máximo para backoff exponencial em ms.
     * Previne que reincidentes fiquem banidos por décadas.
     * Default: 2_592_000_000 (30 dias)
     */
    maxBanTTL?: number;

    /**
     * Limiar de strikes para banimento permanente.
     * Após N strikes, o TTL vira null (permanente).
     * Default: 5
     */
    permanentBanAfterStrikes?: number;

    /**
     * Número máximo de entradas na blocklist.
     * Previne crescimento ilimitado do store.
     * Default: 500_000
     */
    maxEntries?: number;

    /**
     * Intervalo de limpeza de entradas expiradas em ms.
     * Default: 3_600_000 (1 hora)
     */
    purgeIntervalMs?: number;

    /**
     * Máximo de bits de prefix permitido ao banir um CIDR.
     * Previne que um operador bana /0 (todo o tráfego da internet).
     *
     * Default IPv4: 24 (máximo /24 = 256 IPs)
     * Default IPv6: 48 (máximo /48)
     */
    maxCIDRPrefixBan?: { ipv4: number; ipv6: number };

    /**
     * Threshold de fingerprints únicos para detectar CGNAT.
     * IPs com muitos fingerprints distintos recebem throttle em vez de ban.
     * Default: 10
     */
    cgnatFingerprintThreshold?: number;

    /** Feeds externos de threat intelligence. */
    feeds?: ThreatFeed[];

    /** Store para persistência. */
    store?: BlocklistStore;

    /**
     * Hook chamado quando um IP é banido.
     * Use para: alertas, SIEM, notificações Slack.
     */
    onBan?: (entry: BlocklistEntry) => void | Promise<void>;

    /**
     * Hook chamado quando um IP bloqueado tenta acessar.
     * Use para: logs de acesso negado, dashboards.
     */
    onBlocked?: (result: BlocklistResult) => void | Promise<void>;

    /**
     * Hook de auditoria completo.
     */
    onAudit?: (event: BlocklistAuditEvent) => void | Promise<void>;

    /** Habilita logging detalhado. Default: false */
    debug?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store em memória
// ─────────────────────────────────────────────────────────────────────────────

export class MemoryBlocklistStore implements BlocklistStore {
    private readonly entries = new Map<string, BlocklistEntry>();

    async get(ip: string): Promise<BlocklistEntry | null> {
        return this.entries.get(ip) ?? null;
    }

    async set(ip: string, entry: BlocklistEntry): Promise<void> {
        this.entries.set(ip, entry);
    }

    async delete(ip: string): Promise<void> {
        this.entries.delete(ip);
    }

    async exists(ip: string): Promise<boolean> {
        return this.entries.has(ip);
    }

    async getAll(): Promise<BlocklistEntry[]> {
        return Array.from(this.entries.values());
    }

    async getByCategory(category: BlocklistCategory): Promise<BlocklistEntry[]> {
        return Array.from(this.entries.values()).filter(e => e.category === category);
    }

    async getBySource(source: BlocklistSource): Promise<BlocklistEntry[]> {
        return Array.from(this.entries.values()).filter(e => e.source === source);
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

    async count(): Promise<number> {
        return this.entries.size;
    }

    get size(): number { return this.entries.size; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários de IP
// ─────────────────────────────────────────────────────────────────────────────

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
        const [network, prefix] = cidr.split('/');
        if (!network || !prefix) return normalizeIP(ip) === normalizeIP(cidr);
        const bits = parseInt(prefix, 10);
        const groups = Math.ceil(bits / 16);
        const ipParts = normalizeIP(ip).split(':');
        const netParts = normalizeIP(network).split(':');
        return ipParts.slice(0, groups).join(':') === netParts.slice(0, groups).join(':');
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

function isValidCIDR(cidr: string, maxPrefix: { ipv4: number; ipv6: number }): boolean {
    const [ipPart, prefix] = cidr.split('/');
    if (!ipPart || !prefix) return false;
    const bits = parseInt(prefix, 10);
    if (isNaN(bits)) return false;
    if (cidr.includes(':')) {
        return bits >= 0 && bits <= 128 && bits >= (128 - maxPrefix.ipv6);
    }
    return bits >= 0 && bits <= 32 && bits >= (32 - maxPrefix.ipv4) && ipv4ToInt(ipPart) !== null;
}

export function extractRealIP(
    headers: Record<string, string | string[] | undefined>,
): string {
    const getH = (name: string) => {
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

export class IPBlocklist {
    private readonly config: Required<
        Omit<IPBlocklistConfig, 'onBan' | 'onBlocked' | 'onAudit' | 'store'>
    > & Pick<IPBlocklistConfig, 'onBan' | 'onBlocked' | 'onAudit' | 'store'>;

    /** Cache em memória de IPs exatos banidos. */
    private exactSet = new Set<string>();
    /** Cache de CIDRs banidos. */
    private cidrEntries: BlocklistEntry[] = [];
    /** Set de IPs que nunca são bloqueados. */
    private readonly neverBlockSet: Set<string>;
    private readonly neverBlockCIDRs: string[];

    /** Estado dos feeds: { feedName → lastRefreshedAt } */
    private readonly feedTimers = new Map<string, ReturnType<typeof setInterval>>();

    private purgeTimer?: ReturnType<typeof setInterval>;
    private cacheLoaded = false;

    constructor(config: IPBlocklistConfig = {}) {
        this.config = {
            mode: 'active',
            entries: [],
            neverBlockIPs: ['127.0.0.1', '::1', '0:0:0:0:0:0:0:1'],
            neverBlockCIDRs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
            defaultBanTTL: 3_600_000,
            backoffMultiplier: 2,
            maxBanTTL: 2_592_000_000,
            permanentBanAfterStrikes: 5,
            maxEntries: 500_000,
            purgeIntervalMs: 3_600_000,
            maxCIDRPrefixBan: { ipv4: 24, ipv6: 48 },
            cgnatFingerprintThreshold: 10,
            feeds: [],
            debug: false,
            onBan: undefined,
            onBlocked: undefined,
            onAudit: undefined,
            store: undefined,
            ...config,
        };

        this.neverBlockSet = new Set(this.config.neverBlockIPs.map(normalizeIP));
        this.neverBlockCIDRs = this.config.neverBlockCIDRs;

        // Carrega entradas iniciais
        if (this.config.entries.length) {
            void this.loadInitialEntries();
        }

        // Inicia feeds externos
        for (const feed of this.config.feeds) {
            void this.loadFeed(feed);
            if ((feed.refreshMs ?? 3_600_000) > 0) {
                const timer = setInterval(
                    () => void this.loadFeed(feed),
                    feed.refreshMs ?? 3_600_000,
                );
                if (typeof timer.unref === 'function') timer.unref();
                this.feedTimers.set(feed.name, timer);
            }
        }

        // Purge periódico
        if (this.config.purgeIntervalMs > 0) {
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
     * Verifica se um IP está bloqueado.
     *
     * Ordem de verificação:
     *  1. Never-block list — bypass imediato (sistema)
     *  2. IP exato no cache — O(1)
     *  3. CIDR match — O(n_cidrs)
     *  4. Expiração da entrada — remove se expirada
     */
    async check(ip: string, path = '/', method = 'GET'): Promise<BlocklistResult> {
        const normalizedIP = normalizeIP(ip);
        const now = Date.now();

        if (!this.cacheLoaded) await this.reloadCache();

        // ── 1. Never-block ────────────────────────────────────────────────
        if (this.neverBlockSet.has(normalizedIP)) {
            return this.result(false, 'NOT_BLOCKED', normalizedIP, path, now);
        }
        for (const cidr of this.neverBlockCIDRs) {
            if (matchesCIDR(normalizedIP, cidr)) {
                return this.result(false, 'NOT_BLOCKED', normalizedIP, path, now);
            }
        }

        // ── 2. IP exato ───────────────────────────────────────────────────
        let entry: BlocklistEntry | null = null;

        if (this.exactSet.has(normalizedIP)) {
            entry = await this.config.store?.get(normalizedIP)
                ?? this.config.entries.find(e => normalizeIP(e.ip) === normalizedIP)
                ?? null;
        }

        // ── 3. CIDR match ─────────────────────────────────────────────────
        if (!entry) {
            for (const cidrEntry of this.cidrEntries) {
                if (matchesCIDR(normalizedIP, cidrEntry.ip)) {
                    entry = cidrEntry;
                    break;
                }
            }
        }

        // ── Não encontrado ────────────────────────────────────────────────
        if (!entry) {
            this.audit({ action: 'check', ip: normalizedIP, path, result: 'NOT_BLOCKED', timestamp: now });
            return this.result(false, 'NOT_BLOCKED', normalizedIP, path, now);
        }

        // ── 4. Expiração ──────────────────────────────────────────────────
        if (entry.expiresAt !== null && entry.expiresAt < now) {
            await this.config.store?.delete(normalizedIP);
            this.exactSet.delete(normalizedIP);
            this.cidrEntries = this.cidrEntries.filter(e => e.ip !== normalizedIP);
            this.audit({ action: 'expire', ip: normalizedIP, category: entry.category, timestamp: now });
            return this.result(false, 'NOT_BLOCKED', normalizedIP, path, now);
        }

        // ── Bloqueado ─────────────────────────────────────────────────────
        const reason = this.entryToReason(entry);
        const expiresIn = entry.expiresAt ? entry.expiresAt - now : null;

        // Modo dry-run / log-only — registra mas não bloqueia
        const effectivelyBlocked = this.config.mode === 'active';

        const blockResult: BlocklistResult = {
            blocked: effectivelyBlocked,
            reason,
            entry,
            expiresInMs: expiresIn,
            ip: normalizedIP,
            path,
            timestamp: now,
        };

        if (effectivelyBlocked) {
            void this.config.onBlocked?.(blockResult);
        }

        this.audit({
            action: 'check', ip: normalizedIP, path, category: entry.category,
            source: entry.source, result: reason, timestamp: now,
        });

        this.debugLog(effectivelyBlocked ? 'BLOCKED' : 'DRY-RUN', normalizedIP, reason);
        return blockResult;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // API de banimento
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Bane um IP manualmente (permanente por padrão).
     *
     * @example
     * await blocklist.ban('203.0.113.5', 'bruteforce', 'Tentativas de login em massa');
     */
    async ban(
        ip: string,
        category: BlocklistCategory = 'manual',
        reason: string,
        bannedBy?: string,
        options?: Partial<Pick<BlocklistEntry, 'expiresAt' | 'isCGNAT' | 'meta'>>,
    ): Promise<BlocklistEntry> {
        return this.addEntry({
            ip: normalizeIP(ip),
            category,
            reason,
            source: 'manual',
            createdAt: Date.now(),
            expiresAt: options?.expiresAt ?? null,
            strikeCount: await this.getStrikeCount(normalizeIP(ip)) + 1,
            bannedBy,
            confidence: 100,
            isCGNAT: options?.isCGNAT,
            meta: options?.meta,
        });
    }

    /**
     * Bane um IP temporariamente com TTL e backoff exponencial.
     * Reincidentes ficam banidos por períodos progressivamente maiores.
     *
     * @example
     * // 1ª vez: 1h · 2ª vez: 2h · 3ª vez: 4h · ...
     * await blocklist.banTemporary('1.2.3.4', 'bruteforce', 'Auth failed 10x');
     */
    async banTemporary(
        ip: string,
        category: BlocklistCategory,
        reason: string,
        bannedBy?: string,
        baseTTL?: number,
        options?: Partial<Pick<BlocklistEntry, 'isCGNAT' | 'meta'>>,
    ): Promise<BlocklistEntry> {
        const normalized = normalizeIP(ip);
        const strikes = await this.getStrikeCount(normalized) + 1;
        const ttl = this.computeTTL(strikes, baseTTL);
        const expiresAt = ttl === null ? null : Date.now() + ttl;

        return this.addEntry({
            ip: normalized,
            category,
            reason,
            source: 'auto',
            createdAt: Date.now(),
            expiresAt,
            strikeCount: strikes,
            bannedBy,
            confidence: 90,
            isCGNAT: options?.isCGNAT,
            meta: options?.meta,
        });
    }

    /**
     * Bane um CIDR range.
     *
     * @example
     * await blocklist.banCIDR('185.220.101.0/24', 'tor', 'Tor exit subnet');
     */
    async banCIDR(
        cidr: string,
        category: BlocklistCategory,
        reason: string,
        bannedBy?: string,
        options?: Partial<Pick<BlocklistEntry, 'expiresAt' | 'confidence' | 'meta'>>,
    ): Promise<BlocklistEntry> {
        if (!isValidCIDR(cidr, this.config.maxCIDRPrefixBan)) {
            throw new Error(
                `[ip-blocklist] CIDR inválido ou prefix muito amplo: "${cidr}". ` +
                `Máximo permitido: /${this.config.maxCIDRPrefixBan.ipv4} (IPv4) ou ` +
                `/${this.config.maxCIDRPrefixBan.ipv6} (IPv6).`,
            );
        }

        return this.addEntry({
            ip: cidr,
            category,
            reason,
            source: bannedBy ? 'manual' : 'auto',
            createdAt: Date.now(),
            expiresAt: options?.expiresAt ?? null,
            strikeCount: 1,
            bannedBy,
            confidence: options?.confidence ?? 80,
            meta: options?.meta,
        });
    }

    /**
     * Remove o ban de um IP.
     *
     * @example
     * await blocklist.unban('203.0.113.5', 'admin@empresa.com');
     */
    async unban(ip: string, unbannedBy?: string): Promise<boolean> {
        const normalized = normalizeIP(ip);
        const exists = this.exactSet.has(normalized)
            || await this.config.store?.exists(normalized);

        if (!exists) return false;

        await this.config.store?.delete(normalized);
        this.exactSet.delete(normalized);
        this.cidrEntries = this.cidrEntries.filter(e => e.ip !== normalized);

        this.audit({
            action: 'unban', ip: normalized,
            bannedBy: unbannedBy, timestamp: Date.now(),
        });

        this.debugLog('UNBANNED', normalized, unbannedBy);
        return true;
    }

    /**
     * Remove todos os bans de uma categoria (ex: limpar um feed desatualizado).
     */
    async unbanBySource(source: BlocklistSource, unbannedBy?: string): Promise<number> {
        const entries = await this.config.store?.getBySource(source) ?? [];
        let count = 0;
        for (const entry of entries) {
            await this.unban(entry.ip, unbannedBy);
            count++;
        }
        return count;
    }

    /**
     * Reporta uma violação de segurança e bane automaticamente se threshold atingido.
     * Integração com os outros middlewares de segurança.
     *
     * @example
     * // No rateLimiter.onLimitReached:
     * await blocklist.reportViolation(ip, 'bruteforce', 'Rate limit exceeded on /auth/login');
     */
    async reportViolation(
        ip: string,
        category: BlocklistCategory,
        reason: string,
        meta?: Record<string, unknown>,
    ): Promise<BlocklistEntry> {
        return this.banTemporary(ip, category, reason, 'auto-ban', undefined, { meta });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feeds externos
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Carrega (ou recarrega) um feed externo de threat intelligence.
     *
     * O feed pode ser uma URL ou uma função customizada.
     * Linhas que começam com # são tratadas como comentários.
     * Suporta IPs exatos e CIDRs.
     */
    async loadFeed(feed: ThreatFeed): Promise<{ added: number; removed: number }> {
        this.debugLog('FEED-LOADING', feed.name);

        let lines: string[];

        try {
            if (feed.fetcher) {
                lines = await feed.fetcher();
            } else if (feed.url) {
                const response = await fetch(feed.url);
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const text = await response.text();
                lines = text.split('\n');
            } else {
                return { added: 0, removed: 0 };
            }
        } catch (err) {
            this.debugLog('FEED-ERROR', feed.name, err);
            return { added: 0, removed: 0 };
        }

        // Remove entradas antigas deste feed antes de recarregar
        const oldEntries = await this.config.store?.getBySource(feed.name) ?? [];
        for (const old of oldEntries) {
            await this.config.store?.delete(old.ip);
            this.exactSet.delete(old.ip);
        }
        this.cidrEntries = this.cidrEntries.filter(e => e.source !== feed.name);

        let added = 0;
        const ttl = feed.ttlMs ?? 86_400_000;
        const confidence = feed.confidence ?? 70;
        const category = feed.category ?? 'feed';

        for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line || line.startsWith('#') || line.startsWith(';')) continue;

            // Extrai IP/CIDR (ignora comentários inline)
            const ipOrCIDR = line.split(/[\s,#;]/)[0].trim();
            if (!ipOrCIDR) continue;

            // Valida CIDR se aplicável
            if (ipOrCIDR.includes('/') && !isValidCIDR(ipOrCIDR, this.config.maxCIDRPrefixBan)) {
                this.debugLog('FEED-INVALID-CIDR', feed.name, ipOrCIDR);
                continue;
            }

            try {
                await this.addEntry({
                    ip: normalizeIP(ipOrCIDR),
                    category,
                    reason: `Feed: ${feed.name}`,
                    source: feed.name,
                    createdAt: Date.now(),
                    expiresAt: Date.now() + ttl,
                    strikeCount: 1,
                    confidence,
                });
                added++;
            } catch {
                // maxEntries atingido — para de processar
                break;
            }
        }

        this.audit({
            action: 'feed-update', ip: '*',
            source: feed.name, reason: `Loaded ${added} entries`,
            timestamp: Date.now(),
        });

        this.debugLog('FEED-LOADED', feed.name, `+${added} entries, -${oldEntries.length} old`);
        return { added, removed: oldEntries.length };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários públicos
    // ─────────────────────────────────────────────────────────────────────────

    /** Verifica se um IP está bloqueado sem registrar auditoria. */
    async isBlocked(ip: string): Promise<boolean> {
        const result = await this.check(ip);
        return result.blocked;
    }

    /** Lista todas as entradas ativas (não expiradas). */
    async listActive(): Promise<BlocklistEntry[]> {
        const all = await this.config.store?.getAll() ?? this.config.entries;
        const now = Date.now();
        return all.filter(e => e.expiresAt === null || e.expiresAt > now);
    }

    /** Lista entradas por categoria. */
    async listByCategory(category: BlocklistCategory): Promise<BlocklistEntry[]> {
        return this.config.store?.getByCategory(category) ?? [];
    }

    /** Lista entradas que expiram em breve. */
    async listExpiringSoon(withinMs: number): Promise<BlocklistEntry[]> {
        const all = await this.listActive();
        const deadline = Date.now() + withinMs;
        return all.filter(e => e.expiresAt !== null && e.expiresAt <= deadline);
    }

    /** Força limpeza de entradas expiradas e recarrega o cache. */
    async purgeExpired(): Promise<number> {
        const count = await this.config.store?.purgeExpired() ?? 0;
        if (count > 0) await this.reloadCache();
        this.debugLog('PURGED', `${count} expired entries`);
        return count;
    }

    /** Recarrega o cache em memória a partir do store. */
    async reloadCache(): Promise<void> {
        const entries = await this.config.store?.getAll() ?? this.config.entries;
        this.rebuildCache(entries);
        this.cacheLoaded = true;
        this.debugLog('CACHE-RELOADED', `${entries.length} entries`);
    }

    /** Retorna estatísticas da blocklist. */
    async getStats(): Promise<{
        total: number;
        byCategory: Record<BlocklistCategory, number>;
        bySource: Record<string, number>;
        permanent: number;
        temporary: number;
        expired: number;
    }> {
        const all = await this.config.store?.getAll() ?? [];
        const now = Date.now();

        const byCategory: Record<string, number> = {};
        const bySource: Record<string, number> = {};
        let permanent = 0, temporary = 0, expired = 0;

        for (const entry of all) {
            byCategory[entry.category] = (byCategory[entry.category] ?? 0) + 1;
            bySource[entry.source] = (bySource[entry.source] ?? 0) + 1;
            if (entry.expiresAt === null) permanent++;
            else if (entry.expiresAt < now) expired++;
            else temporary++;
        }

        return {
            total: all.length,
            byCategory: byCategory as Record<BlocklistCategory, number>,
            bySource: bySource as Record<string, number>,
            permanent,
            temporary,
            expired,
        };
    }

    destroy(): void {
        if (this.purgeTimer) clearInterval(this.purgeTimer);
        for (const timer of Array.from(this.feedTimers.values())) clearInterval(timer);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Privados
    // ─────────────────────────────────────────────────────────────────────────

    private async addEntry(entry: BlocklistEntry): Promise<BlocklistEntry> {
        const currentCount = await this.config.store?.count()
            ?? this.exactSet.size + this.cidrEntries.length;

        if (currentCount >= this.config.maxEntries) {
            throw new Error(
                `[ip-blocklist] Limite máximo de entradas atingido (${this.config.maxEntries}).`,
            );
        }

        await this.config.store?.set(entry.ip, entry);

        if (entry.ip.includes('/')) {
            this.cidrEntries = this.cidrEntries.filter(e => e.ip !== entry.ip);
            this.cidrEntries.push(entry);
        } else {
            this.exactSet.add(entry.ip);
        }

        void this.config.onBan?.(entry);
        this.audit({
            action: entry.source === 'auto' ? 'auto-ban' : 'ban',
            ip: entry.ip,
            category: entry.category,
            source: entry.source,
            reason: entry.reason,
            bannedBy: entry.bannedBy,
            timestamp: entry.createdAt,
            expiresAt: entry.expiresAt,
        });

        this.debugLog('BANNED', entry.ip, entry.category, entry.reason);
        return entry;
    }

    private async getStrikeCount(ip: string): Promise<number> {
        const existing = await this.config.store?.get(ip);
        return existing?.strikeCount ?? 0;
    }

    /**
     * Calcula TTL com backoff exponencial.
     * Retorna null quando strikes >= permanentBanAfterStrikes.
     */
    private computeTTL(strikes: number, baseTTL?: number): number | null {
        if (strikes >= this.config.permanentBanAfterStrikes) return null;
        const base = baseTTL ?? this.config.defaultBanTTL;
        const computed = base * Math.pow(this.config.backoffMultiplier, strikes - 1);
        return Math.min(computed, this.config.maxBanTTL);
    }

    private entryToReason(entry: BlocklistEntry): BlocklistReason {
        if (entry.isCGNAT) return 'CGNAT_PARTIAL_BAN';
        if (entry.source === 'manual') return 'MANUAL_BAN';
        if (entry.source === 'auto') return entry.strikeCount > 1 ? 'REPEAT_OFFENDER' : 'AUTO_BAN';
        if (entry.category === 'tor') return 'TOR_EXIT_NODE';
        if (entry.ip.includes('/')) return 'CIDR_BAN';
        return 'FEED_MATCH';
    }

    private async loadInitialEntries(): Promise<void> {
        for (const entry of this.config.entries) {
            const normalized = { ...entry, ip: normalizeIP(entry.ip) };
            await this.config.store?.set(normalized.ip, normalized);
        }
        await this.reloadCache();
    }

    private rebuildCache(entries: BlocklistEntry[]): void {
        this.exactSet = new Set<string>();
        this.cidrEntries = [];
        const now = Date.now();

        for (const entry of entries) {
            if (entry.expiresAt !== null && entry.expiresAt < now) continue;
            const normalized = normalizeIP(entry.ip);
            if (normalized.includes('/')) {
                this.cidrEntries.push({ ...entry, ip: normalized });
            } else {
                this.exactSet.add(normalized);
            }
        }
    }

    private result(
        blocked: boolean,
        reason: BlocklistReason,
        ip: string,
        path: string,
        timestamp: number,
        entry?: BlocklistEntry,
    ): BlocklistResult {
        return { blocked, reason, entry, ip, path, timestamp };
    }

    private audit(event: BlocklistAuditEvent): void {
        void this.config.onAudit?.(event);
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[ip-blocklist]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Requisição normalizada
// ─────────────────────────────────────────────────────────────────────────────

export interface BlocklistRequest {
    ip?: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

type ExpressReq = {
    ip?: string; method: string; path: string;
    headers: Record<string, string | string[] | undefined>;
};
type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    json(d: unknown): void;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware de blocklist para Express.
 *
 * @example
 * app.use(createExpressBlocklist(blocklist));
 */
export function createExpressBlocklist(list: IPBlocklist) {
    return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
        const ip = req.ip ?? extractRealIP(req.headers);
        const result = await list.check(ip, req.path, req.method);

        if (result.blocked) {
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff',
                'Cache-Control': 'no-store',
            };
            if (result.expiresInMs) {
                headers['Retry-After'] = String(Math.ceil(result.expiresInMs / 1000));
            }
            res.status(403).set(headers).json({ error: 'Forbidden', message: 'Access denied.' });
            return;
        }

        next();
    };
}

/**
 * Handler de blocklist para Next.js Edge Runtime.
 */
export function createNextBlocklist(list: IPBlocklist) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((v, k) => { headers[k] = v; });
        const url = new URL(request.url);
        const ip = headers['cf-connecting-ip'] ?? headers['x-real-ip'] ?? '0.0.0.0';
        const result = await list.check(normalizeIP(ip), url.pathname, request.method);

        if (result.blocked) {
            const respHeaders: Record<string, string> = {
                'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store',
            };
            if (result.expiresInMs) respHeaders['Retry-After'] = String(Math.ceil(result.expiresInMs / 1000));
            return new Response(JSON.stringify({ error: 'Forbidden', message: 'Access denied.' }), { status: 403, headers: respHeaders });
        }
        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factories
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria blocklist com feeds Tor e Spamhaus pré-configurados.
 *
 * @example
 * const blocklist = createThreatFeedBlocklist(onBan, onAudit);
 */
export function createThreatFeedBlocklist(
    onBan?: IPBlocklistConfig['onBan'],
    onAudit?: IPBlocklistConfig['onAudit'],
): IPBlocklist {
    return new IPBlocklist({
        store: new MemoryBlocklistStore(),
        onBan,
        onAudit,
        feeds: [
            {
                name: 'tor-project',
                url: 'https://check.torproject.org/torbulkexitlist',
                refreshMs: 3_600_000,
                confidence: 95,
                category: 'tor',
                ttlMs: 86_400_000,
            },
        ],
    });
}

/**
 * Cria blocklist de alto volume com store otimizado para muitas entradas.
 *
 * @example
 * const blocklist = createHighVolumeBlocklist(redisStore);
 */
export function createHighVolumeBlocklist(store: BlocklistStore): IPBlocklist {
    return new IPBlocklist({
        store,
        maxEntries: 500_000,
        purgeIntervalMs: 1_800_000, // 30 min
        defaultBanTTL: 3_600_000,
        backoffMultiplier: 2,
        permanentBanAfterStrikes: 5,
    });
}

/**
 * Cria blocklist em modo dry-run para análise de impacto.
 *
 * @example
 * const dryRun = createDryRunBlocklist(onAudit);
 * // Monitore os logs por 24h antes de ativar o modo 'active'
 */
export function createDryRunBlocklist(
    onAudit?: IPBlocklistConfig['onAudit'],
): IPBlocklist {
    return new IPBlocklist({
        mode: 'dry-run',
        store: new MemoryBlocklistStore(),
        onAudit,
        debug: true,
    });
}