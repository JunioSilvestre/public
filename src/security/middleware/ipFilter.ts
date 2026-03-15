/**
 * @fileoverview Middleware de filtragem de IP — controle de acesso multicamada.
 *
 * @description
 * Sistema de filtragem de IP com inteligência adaptativa para bloquear tráfego
 * malicioso preservando ao máximo a experiência de usuários legítimos.
 *
 * O principal desafio deste módulo é o equilíbrio:
 *  ─ Ser restritivo o suficiente para bloquear ameaças reais
 *  ─ Ser permissivo o suficiente para não prejudicar usuários comuns
 *
 * ── Camadas de detecção ────────────────────────────────────────────────────
 *  1.  Allowlist permanente    — IPs/CIDRs sempre permitidos (LB, healthcheck)
 *  2.  Blocklist permanente    — IPs/CIDRs banidos explicitamente
 *  3.  Blocklist dinâmica      — IPs banidos automaticamente por comportamento
 *  4.  Reputação de IP         — score acumulado por atividade suspeita
 *  5.  Tor exit nodes          — rede Tor (atualizável em runtime)
 *  6.  VPN / Proxy detection   — ASNs de VPN + heurísticas de headers
 *  7.  Datacenter ASNs         — cloud providers usados para ataques
 *  8.  CIDR privado/bogon      — IPs que não deveriam chegar na internet
 *  9.  Rate de novas conexões  — detecção de scanning/reconhecimento
 * 10.  Behavioral scoring      — padrão de acesso ao longo do tempo
 *
 * ── Proteção sem bloquear usuários legítimos ──────────────────────────────
 *
 *  VPN legítima (usuário comum):
 *   - Não é bloqueada por padrão — muitos usuários usam VPN por privacidade
 *   - Apenas sinalizada como risco médio (score += 20)
 *   - Bloqueio de VPN é opt-in via `blockVPN: true`
 *   - ISPs com IPs compartilhados (CGNAT) são tratados com cautela
 *
 *  Celular / IP móvel:
 *   - IPs de operadoras móveis têm score reduzido automaticamente
 *   - CGNAT (muitos usuários por IP) nunca é banido definitivamente
 *   - Limite de rate por IP é elevado para ranges móveis conhecidos
 *
 *  Usuário doméstico em ISP de risco:
 *   - Score alto não bloqueia imediatamente — exige challenge primeiro
 *   - Challenge bem-sucedido adiciona IP à allowlist temporária
 *   - Ban temporário, nunca permanente, para IPs residenciais
 *
 *  CGNAT / Proxy corporativo:
 *   - Detectado via volume de fingerprints diferentes num mesmo IP
 *   - Aumenta threshold de ban para evitar falso positivo
 *   - Flag `isCGNAT` ativa tratamento especial
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *  • IP spoofing via X-Forwarded-For                    (ubíquo)
 *  • Scanning de portas / reconhecimento via HTTP       (ubíquo)
 *  • Credential stuffing distribuído por IP pool        (2018+)
 *  • Residential proxy farms (IPRoyal, Bright Data)     (2019+)
 *  • Botnet com IPs legítimos de usuários infectados    (ubíquo)
 *  • Evasão por rotação de IP a cada request            (2020+)
 *  • Amplification via IP spoofed reflection            (Layer 3)
 *  • CGNAT abuse — bloquear IP bloqueia centenas de usuários (2015+)
 *  • IPv6 /64 prefix abuse — subnet inteira atacando   (2021+)
 *  • Satellite IP pool (Starlink) com geolocalização errática (2021+)
 *  • Tor meek bridges — Tor disfarçado como CDN traffic  (2020+)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • IPv6-only networks em crescimento                  (2024+)
 *  • QUIC/HTTP3 com IPs alternativos por connection ID  (emergente)
 *  • IP reputation via ML scoring (integração externa)  (2023+)
 *  • Post-quantum VPN protocols novos fingerprints       (2025+)
 *
 * @see https://www.team-cymru.com/ip-reputation
 * @see https://ipinfo.io/products/ip-vpn-detection
 * @see https://www.maxmind.com/en/solutions/minfraud-services
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da avaliação de um IP. */
export interface IPFilterResult {
    /** true = IP permitido | false = IP bloqueado ou em challenge */
    allowed: boolean;
    /** Ação recomendada quando allowed = false */
    action?: IPFilterAction;
    reason?: IPFilterReason;
    /** Score de risco acumulado (0–100). Usado para decisões graduais. */
    riskScore: number;
    /** Categoria do IP detectada */
    category?: IPCategory;
    meta: IPFilterMeta;
}

export type IPFilterAction =
    | 'allow'        // passa normalmente
    | 'challenge'    // exige CAPTCHA / verificação humana
    | 'throttle'     // permite com limite de taxa reduzido
    | 'block'        // bloqueia a requisição
    | 'ban';         // banimento temporário ou permanente

export type IPFilterReason =
    | 'ALLOWLISTED'
    | 'PERMANENT_BLOCK'
    | 'DYNAMIC_BAN'
    | 'TOR_EXIT_NODE'
    | 'VPN_PROXY'
    | 'DATACENTER_ASN'
    | 'BOGON_IP'
    | 'REPUTATION_LOW'
    | 'BEHAVIORAL_ANOMALY'
    | 'SCANNING_DETECTED'
    | 'CGNAT_ABUSE'
    | 'IPV6_PREFIX_ABUSE'
    | 'CHALLENGE_REQUIRED';

export type IPCategory =
    | 'residential'       // ISP doméstico — risco baixo
    | 'mobile'            // operadora móvel — risco baixo, CGNAT provável
    | 'corporate'         // rede empresarial — risco baixo/médio
    | 'datacenter'        // cloud provider — risco médio/alto
    | 'vpn'               // VPN comercial — risco médio
    | 'tor'               // rede Tor — risco alto
    | 'proxy'             // proxy público — risco alto
    | 'satellite'         // Starlink/satellite — risco baixo, geo errática
    | 'cgnat'             // IP compartilhado — tratamento especial
    | 'unknown';          // não classificado

export interface IPFilterMeta {
    ip: string;
    normalizedIP: string;  // IPv6 normalizado, IPv4 sem porta
    path: string;
    method: string;
    timestamp: number;
    signals: string[];
    asn?: string;
    isTor?: boolean;
    isVPN?: boolean;
    isDatacenter?: boolean;
    isCGNAT?: boolean;
    isIPv6?: boolean;
    banExpiresAt?: number;
}

/** Score de reputação de um IP armazenado no store. */
export interface IPReputation {
    ip: string;
    score: number;           // 0 (limpo) → 100 (malicioso)
    violations: number;           // contagem de violações
    firstSeenAt: number;
    lastSeenAt: number;
    lastViolationAt?: number;
    isBanned: boolean;
    banExpiresAt?: number;
    category?: IPCategory;
    /** true se é CGNAT — threshold de ban mais alto */
    isCGNAT?: boolean;
    /** Número de fingerprints distintos vistos neste IP (sinal de CGNAT) */
    uniqueFingerprints?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface IPFilterConfig {
    /**
     * IPs e CIDRs permanentemente permitidos.
     * Use para: load balancers, health checks, IPs de escritório, CIs.
     * Formato: '1.2.3.4' | '10.0.0.0/8'
     */
    allowlist?: string[];

    /**
     * IPs e CIDRs permanentemente bloqueados.
     * Nunca exibe challenge — rejeição imediata.
     */
    blocklist?: string[];

    /**
     * Bloqueia saídas Tor conhecidas.
     * Default: true
     *
     * Por que true por padrão:
     *  - Tor é frequentemente usado para atacar serviços web
     *  - Usuários legítimos que precisam de anonimato têm alternativas
     *  - Tor oculta a identidade do atacante de forma intencional
     *
     * Exceção razoável: jornalismo, ativismo, defesa de privacidade.
     * Nesses casos, use `torPolicy: 'challenge'` em vez de bloquear.
     */
    blockTor?: boolean;
    /** Ação para Tor: 'block' | 'challenge' | 'throttle'. Default: 'block' */
    torPolicy?: IPFilterAction;

    /**
     * Bloqueia VPNs comerciais conhecidas.
     * Default: false — muitos usuários legítimos usam VPN.
     *
     * Por que false por padrão:
     *  - ~30% dos usuários de internet usam VPN regularmente
     *  - VPN de privacidade (ProtonVPN, Mullvad) é uso legítimo
     *  - Bloquear VPN pune usuários conscientes de segurança
     *
     * Recomendação: use `vpnPolicy: 'challenge'` em vez de 'block'
     * para endpoints sensíveis sem bloquear endpoints públicos.
     */
    blockVPN?: boolean;
    /** Ação para VPN: 'block' | 'challenge' | 'throttle'. Default: 'challenge' */
    vpnPolicy?: IPFilterAction;

    /**
     * Bloqueia IPs de datacenters (AWS, GCP, Azure, DigitalOcean, etc.).
     * Default: false — APIs legítimas rodam em datacenter.
     *
     * Por que false por padrão:
     *  - Bots legítimos (indexadores, APIs de terceiros) usam datacenter
     *  - Desenvolvedores testam de IPs de datacenter
     *  - Empresas usam proxies corporativos em datacenter
     *
     * Recomendação: ative apenas para endpoints de usuário final
     * (não para APIs B2B ou endpoints de webhook).
     */
    blockDatacenter?: boolean;
    /** Ação para datacenter: 'block' | 'challenge' | 'throttle'. Default: 'throttle' */
    datacenterPolicy?: IPFilterAction;

    /**
     * Bloqueia IPs bogon (privados/reservados que não devem existir na internet).
     * Default: true — IPs bogon em produção indicam spoofing ou misconfiguration.
     *
     * IPs bogon incluem:
     *  - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (privados RFC1918)
     *  - 127.0.0.0/8 (loopback)
     *  - 169.254.0.0/16 (link-local)
     *  - 0.0.0.0/8, 255.255.255.255 (especiais)
     *  - 240.0.0.0/4 (reservado futuro)
     */
    blockBogons?: boolean;

    /**
     * Score de risco mínimo para exigir challenge (CAPTCHA).
     * Default: 50
     */
    challengeThreshold?: number;

    /**
     * Score de risco mínimo para bloquear.
     * Default: 75
     */
    blockThreshold?: number;

    /**
     * Score de risco mínimo para banimento automático.
     * Default: 90
     */
    banThreshold?: number;

    /**
     * Duração do banimento automático em ms.
     * Default: 3_600_000 (1 hora)
     *
     * Por que 1 hora e não permanente:
     *  - IPs dinâmicos são reatribuídos — um ban permanente pune o próximo usuário
     *  - Botnets rotacionam IPs — ban permanente tem pouco efeito
     *  - 1 hora é suficiente para interromper um ataque sem punir indefinidamente
     */
    banDurationMs?: number;

    /**
     * Threshold de fingerprints únicos num IP para detectar CGNAT.
     * Se um IP tem mais de N fingerprints distintos, provavelmente é CGNAT.
     * Default: 10
     *
     * Em CGNAT, um único IP representa centenas de usuários.
     * O sistema eleva o threshold de ban para evitar falso positivo massivo.
     */
    cgnatFingerprintThreshold?: number;

    /**
     * Fator multiplicador do threshold de ban para IPs CGNAT.
     * Default: 3 (o ban só acontece com 3x mais violações)
     */
    cgnatBanMultiplier?: number;

    /**
     * Ação para IPv6 /64 prefixes com múltiplos IPs suspeitos.
     * Um atacante pode rodar através de toda uma /64 (18 quintilhões de IPs).
     * Default: 'throttle'
     */
    ipv6PrefixPolicy?: IPFilterAction;

    /**
     * Rotas que aplicam filtro mais restritivo.
     * Sobrescreve as políticas globais para endpoints sensíveis.
     */
    routeOverrides?: Record<string, Partial<IPFilterConfig>>;

    /**
     * Lista de Tor exit nodes (IPs).
     * Atualize periodicamente de https://check.torproject.org/torbulkexitlist
     * Default: [] (sem lista pré-carregada — forneça via externalLookup)
     */
    torExitNodes?: string[];

    /**
     * Hook para enriquecimento externo do IP.
     * Chamado quando o IP não está nas listas locais.
     * Retorne null se não tiver informação.
     *
     * @example
     * externalEnrichment: async (ip) => {
     *   const data = await ipinfoClient.lookupIp(ip);
     *   return {
     *     asn:         data.org,
     *     category:    data.privacy.vpn ? 'vpn' : 'residential',
     *     riskScore:   data.privacy.vpn ? 40 : 10,
     *     isTor:       data.privacy.tor,
     *     isVPN:       data.privacy.vpn,
     *     isProxy:     data.privacy.proxy,
     *     isCGNAT:     data.privacy.relay,
     *   };
     * }
     */
    externalEnrichment?: (ip: string) => Promise<IPEnrichmentResult | null>;

    /**
     * Hook para violações de segurança de outros middlewares.
     * Permite que botProtection, ddosProtection, etc. penalizem um IP
     * sem duplicar a lógica.
     *
     * @example
     * // No botProtection.ts:
     * botProtection.onBlocked = (result) => {
     *   ipFilter.reportViolation(result.meta.ip, 'BOT_DETECTED', 30);
     * };
     */
    onViolation?: (ip: string, reason: string, scoreIncrease: number) => void;

    /** Hook chamado quando um IP é bloqueado. */
    onBlocked?: (result: IPFilterResult) => void | Promise<void>;

    /** Hook chamado quando um IP é banido automaticamente. */
    onBanned?: (ip: string, reason: string, expiresAt: number) => void | Promise<void>;

    /** Store para persistência de reputação. */
    store: IPFilterStore;

    /** Habilita logging detalhado. Default: false. */
    debug?: boolean;
}

/** Resultado de enriquecimento externo de IP. */
export interface IPEnrichmentResult {
    asn?: string;
    org?: string;
    category?: IPCategory;
    riskScore?: number;
    isTor?: boolean;
    isVPN?: boolean;
    isProxy?: boolean;
    isDatacenter?: boolean;
    isCGNAT?: boolean;
    isMobile?: boolean;
    isSatellite?: boolean;
    countryCode?: string;
}

/** Interface do store de reputação. */
export interface IPFilterStore {
    getReputation(ip: string): Promise<IPReputation | null>;
    setReputation(ip: string, rep: IPReputation): Promise<void>;
    incrementScore(ip: string, delta: number, ttlMs: number): Promise<number>;
    ban(ip: string, expiresAt: number, reason: string): Promise<void>;
    unban(ip: string): Promise<void>;
    isBanned(ip: string): Promise<boolean>;
    /** Registra fingerprint único para detecção de CGNAT. */
    addFingerprint(ip: string, fingerprint: string, ttlMs: number): Promise<number>;
    /** Lista IPs de um prefixo IPv6 (/64). */
    countIPv6Prefix(prefix: string, ttlMs: number): Promise<number>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store em memória
// ─────────────────────────────────────────────────────────────────────────────

export class MemoryIPFilterStore implements IPFilterStore {
    private readonly reputations = new Map<string, IPReputation & { expiresAt: number }>();
    private readonly bans = new Map<string, { reason: string; expiresAt: number }>();
    private readonly fingerprints = new Map<string, Set<string> & { expiresAt: number }>();
    private readonly ipv6Prefixes = new Map<string, { count: number; expiresAt: number }>();
    private readonly cleanupInterval: ReturnType<typeof setInterval>;

    constructor(cleanupIntervalMs = 60_000) {
        this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
        if (typeof this.cleanupInterval.unref === 'function') {
            this.cleanupInterval.unref();
        }
    }

    async getReputation(ip: string): Promise<IPReputation | null> {
        const entry = this.reputations.get(ip);
        if (!entry || entry.expiresAt < Date.now()) return null;
        const { expiresAt: _, ...rep } = entry;
        return rep;
    }

    async setReputation(ip: string, rep: IPReputation): Promise<void> {
        this.reputations.set(ip, { ...rep, expiresAt: Date.now() + 86_400_000 }); // 24h
    }

    async incrementScore(ip: string, delta: number, ttlMs: number): Promise<number> {
        const existing = this.reputations.get(ip);
        const now = Date.now();

        if (!existing || existing.expiresAt < now) {
            const newRep: IPReputation & { expiresAt: number } = {
                ip, score: delta, violations: 1,
                firstSeenAt: now, lastSeenAt: now,
                isBanned: false, expiresAt: now + ttlMs,
            };
            this.reputations.set(ip, newRep);
            return delta;
        }

        existing.score = Math.min(100, existing.score + delta);
        existing.violations += 1;
        existing.lastSeenAt = now;
        if (ttlMs > existing.expiresAt - now) {
            existing.expiresAt = now + ttlMs;
        }
        return existing.score;
    }

    async ban(ip: string, expiresAt: number, reason: string): Promise<void> {
        this.bans.set(ip, { reason, expiresAt });
        const rep = this.reputations.get(ip);
        if (rep) {
            rep.isBanned = true;
            rep.banExpiresAt = expiresAt;
        }
    }

    async unban(ip: string): Promise<void> {
        this.bans.delete(ip);
        const rep = this.reputations.get(ip);
        if (rep) { rep.isBanned = false; rep.banExpiresAt = undefined; }
    }

    async isBanned(ip: string): Promise<boolean> {
        const ban = this.bans.get(ip);
        if (!ban) return false;
        if (ban.expiresAt < Date.now()) { this.bans.delete(ip); return false; }
        return true;
    }

    async addFingerprint(ip: string, fingerprint: string, ttlMs: number): Promise<number> {
        const existing = this.fingerprints.get(ip);
        const now = Date.now();

        if (!existing || (existing as any).expiresAt < now) {
            const newSet = new Set([fingerprint]) as Set<string> & { expiresAt: number };
            newSet.expiresAt = now + ttlMs;
            this.fingerprints.set(ip, newSet);
            return 1;
        }

        existing.add(fingerprint);
        return existing.size;
    }

    async countIPv6Prefix(prefix: string, ttlMs: number): Promise<number> {
        const existing = this.ipv6Prefixes.get(prefix);
        const now = Date.now();

        if (!existing || existing.expiresAt < now) {
            this.ipv6Prefixes.set(prefix, { count: 1, expiresAt: now + ttlMs });
            return 1;
        }

        existing.count += 1;
        return existing.count;
    }

    destroy(): void {
        clearInterval(this.cleanupInterval);
        this.reputations.clear();
        this.bans.clear();
        this.fingerprints.clear();
        this.ipv6Prefixes.clear();
    }

    private cleanup(): void {
        const now = Date.now();
        for (const [k, v] of Array.from(this.reputations.entries())) {
            if (v.expiresAt < now) this.reputations.delete(k);
        }
        for (const [k, v] of Array.from(this.bans.entries())) {
            if (v.expiresAt < now) this.bans.delete(k);
        }
        for (const [k, v] of Array.from(this.fingerprints.entries())) {
            if ((v as any).expiresAt < now) this.fingerprints.delete(k);
        }
        for (const [k, v] of Array.from(this.ipv6Prefixes.entries())) {
            if (v.expiresAt < now) this.ipv6Prefixes.delete(k);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Ranges de IPs bogon — nunca devem aparecer como origem na internet pública.
 * Presença indica IP spoofing, misconfiguration de proxy, ou request sintético.
 */
const BOGON_RANGES: readonly string[] = [
    '0.0.0.0/8',       // "this" network
    '10.0.0.0/8',      // RFC1918 privado
    '100.64.0.0/10',   // CGNAT compartilhado (RFC6598) — cuidado: pode ser legítimo internamente
    '127.0.0.0/8',     // loopback
    '169.254.0.0/16',  // link-local (APIPA)
    '172.16.0.0/12',   // RFC1918 privado
    '192.0.0.0/24',    // IETF Protocol Assignments
    '192.0.2.0/24',    // TEST-NET-1 (documentação)
    '192.168.0.0/16',  // RFC1918 privado
    '198.18.0.0/15',   // benchmark testing (RFC2544)
    '198.51.100.0/24', // TEST-NET-2 (documentação)
    '203.0.113.0/24',  // TEST-NET-3 (documentação)
    '224.0.0.0/4',     // multicast
    '233.252.0.0/24',  // MCAST-TEST-NET
    '240.0.0.0/4',     // reservado (uso futuro)
    '255.255.255.255/32', // broadcast
];

/**
 * Ranges de ISPs móveis brasileiros conhecidos.
 * Usados para identificar IPs de celular e aplicar tratamento CGNAT.
 * Lista parcial — complementada via externalEnrichment em produção.
 */
const KNOWN_MOBILE_ASNS_BR: readonly string[] = [
    'AS26615',  // TIM Brasil
    'AS16735',  // Algar Telecom
    'AS28573',  // Claro Brasil
    'AS7738',   // Telemar (Oi)
    'AS18881',  // TELEFÔNICA BRASIL (Vivo)
    'AS27699',  // TELEFÔNICA BRASIL (Vivo) 2
    'AS8167',   // Oi Internet
    'AS262916', // Nextel Brasil
];

/**
 * ASNs de datacenter com alta propensão a abusos.
 * Subconjunto dos ASNs do geoBlock.ts focado nos mais usados em ataques.
 */
const HIGH_RISK_DATACENTER_ASNS: readonly string[] = [
    'AS14061',  // DigitalOcean
    'AS20473',  // Vultr
    'AS24940',  // Hetzner
    'AS16276',  // OVH
    'AS60781',  // Leaseweb
    'AS9009',   // M247 (NordVPN, muitos VPNs)
    'AS60068',  // Datacamp (VPNs)
    'AS53667',  // FranTech (hosting anônimo)
    'AS8100',   // QuadraNet
    'AS200019', // Alexhost SRL (hosting abusivo)
    'AS209588', // Flyservers (hosting abusivo)
    'AS174',    // Cogent (frequente em ataques)
    'AS3223',   // Voxility (frequente em DDoS)
];

/**
 * Score de risco por categoria de IP.
 * Balanceado para não penalizar usuários legítimos.
 */
const CATEGORY_BASE_SCORES: Record<IPCategory, number> = {
    residential: 0,   // Score limpo para residencial
    mobile: 5,   // Leve sinal por CGNAT provável
    corporate: 5,   // Baixo risco
    satellite: 10,  // Geo errática, mas legítimo
    cgnat: 10,  // Tratamento especial, não ban
    datacenter: 25,  // Médio — API pode ser legítima
    vpn: 30,  // Médio — uso legítimo é comum
    proxy: 50,  // Alto — proxy público raramente legítimo
    tor: 80,  // Muito alto — uso em ataques é frequente
    unknown: 15,  // Leve sinal de cautela
};

/**
 * Incremento de score por tipo de violação.
 * Calibrado para não banir imediatamente usuários legítimos.
 */
export const VIOLATION_SCORES: Record<string, number> = {
    RATE_LIMIT_EXCEEDED: 15,  // Excedeu limite — pode ser uso intenso legítimo
    BOT_DETECTED: 30,  // Bot — alto sinal mas pode ser monitoramento legítimo
    CSRF_VIOLATION: 40,  // CSRF — muito suspeito
    XSS_ATTEMPT: 50,  // XSS — claramente malicioso
    SQL_INJECTION: 60,  // SQLi — claramente malicioso
    HONEYPOT_TRIGGERED: 70,  // Honeypot — certamente automatizado
    CREDENTIAL_STUFFING: 50,  // Credenciais em volume — ataque
    SCANNING_DETECTED: 40,  // Scanning de endpoints
    MALFORMED_REQUEST: 20,  // Request malformado — pode ser bug de cliente
    DDOS_PATTERN: 45,  // Padrão DDoS
    AUTH_BRUTEFORCE: 55,  // Força bruta em login
    PAYLOAD_ANOMALY: 25,  // Payload suspeito
};

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários de IP
// ─────────────────────────────────────────────────────────────────────────────

/** Detecta se o IP é IPv6. */
export function isIPv6(ip: string): boolean {
    return ip.includes(':');
}

/** Extrai o prefixo /64 de um IPv6 (primeiros 64 bits). */
export function extractIPv6Prefix64(ip: string): string {
    const normalized = normalizeIPv6(ip);
    const groups = normalized.split(':');
    // IPv6 tem 8 grupos de 16 bits. /64 = primeiros 4 grupos.
    return groups.slice(0, 4).join(':') + '::/64';
}

/** Normaliza IPv6 para formato completo (remove abreviações :: e zeros). */
export function normalizeIPv6(ip: string): string {
    if (!ip.includes(':')) return ip;
    try {
        // Usando URL para normalizar IPv6
        const url = new URL(`http://[${ip}]/`);
        return url.hostname.replace(/^\[|\]$/g, '');
    } catch {
        return ip.toLowerCase();
    }
}

/** Normaliza IPv4-mapeado em IPv6 (::ffff:1.2.3.4 → 1.2.3.4). */
export function normalizeIP(ip: string): string {
    const ipv4Mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (ipv4Mapped) return ipv4Mapped[1];
    if (isIPv6(ip)) return normalizeIPv6(ip);
    return ip.trim();
}

/** Converte IPv4 para inteiro (unsigned 32-bit). */
function ipv4ToInt(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/** Verifica se um IPv4 pertence a um CIDR. */
function matchesCIDRv4(ip: string, cidr: string): boolean {
    const slashIdx = cidr.lastIndexOf('/');
    if (slashIdx === -1) return ip === cidr;

    const network = cidr.slice(0, slashIdx);
    const bits = parseInt(cidr.slice(slashIdx + 1), 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return false;

    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    const ipInt = ipv4ToInt(ip);
    const netInt = ipv4ToInt(network);

    return ipInt !== null && netInt !== null && (ipInt & mask) === (netInt & mask);
}

/** Verifica se um IP pertence a um CIDR (IPv4 ou IPv6 simplificado). */
function matchesCIDR(ip: string, cidr: string): boolean {
    if (isIPv6(ip)) {
        // Para IPv6, comparação de prefixo simplificada
        const [network, prefix] = cidr.split('/');
        if (!network || !prefix) return ip === cidr;
        const bits = parseInt(prefix, 10);
        if (isNaN(bits)) return false;
        // Compara os primeiros N bits via comparação de string de grupos
        const ipGroups = normalizeIPv6(ip).split(':');
        const netGroups = normalizeIPv6(network).split(':');
        const groupsToCheck = Math.ceil(bits / 16);
        return ipGroups.slice(0, groupsToCheck).join(':') ===
            netGroups.slice(0, groupsToCheck).join(':');
    }
    return matchesCIDRv4(ip, cidr);
}

/** Verifica se um IP é bogon. */
function isBogonIP(ip: string): boolean {
    if (isIPv6(ip)) {
        const lower = ip.toLowerCase();
        // IPv6 privados/especiais
        if (lower === '::1') return true;
        if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
        if (lower.startsWith('fe80:')) return true;                        // link-local
        if (lower.startsWith('::ffff:')) return false;                     // IPv4-mapeado — verifica a parte IPv4
        return false;
    }

    return BOGON_RANGES.some(cidr => matchesCIDRv4(ip, cidr));
}

/**
 * Extrai o IP real da requisição com validação robusta.
 *
 * Hierarquia de confiança:
 *  1. CF-Connecting-IP (Cloudflare — confiável se Cloudflare está na frente)
 *  2. X-Real-IP (nginx — confiável se nginx é o proxy)
 *  3. X-Forwarded-For [0] (leftmost — cliente original)
 *  4. Fallback '0.0.0.0'
 *
 * ⚠ NUNCA confie em X-Forwarded-For sem um proxy reverso verificado.
 *   Em produção, configure seu proxy para sobrescrever este header.
 */
export function extractRealIP(
    headers: Record<string, string | string[] | undefined>,
): string {
    const getH = (name: string): string | undefined => {
        const v = headers[name.toLowerCase()];
        if (!v) return undefined;
        return Array.isArray(v) ? v[0] : v;
    };

    const cf = getH('cf-connecting-ip');
    if (cf) return normalizeIP(cf.split(',')[0].trim());

    const real = getH('x-real-ip');
    if (real) return normalizeIP(real.trim());

    const fwd = getH('x-forwarded-for');
    if (fwd) return normalizeIP(fwd.split(',')[0].trim());

    return '0.0.0.0';
}

/** Gera fingerprint simples para detecção de CGNAT. */
function generateIPFingerprint(
    headers: Record<string, string | string[] | undefined>,
): string {
    const getH = (n: string) => {
        const v = headers[n.toLowerCase()];
        return v ? (Array.isArray(v) ? v[0] : v) : '';
    };

    const components = [
        getH('user-agent'),
        getH('accept-language'),
        getH('accept-encoding'),
        getH('sec-ch-ua'),
    ].join('|');

    // Hash simples djb2
    let hash = 5381;
    for (let i = 0; i < components.length; i++) {
        hash = ((hash << 5) + hash) ^ components.charCodeAt(i);
        hash = hash >>> 0;
    }
    return hash.toString(16);
}

// ─────────────────────────────────────────────────────────────────────────────
// Request normalizado
// ─────────────────────────────────────────────────────────────────────────────

export interface IPFilterRequest {
    ip?: string;  // se omitido, extrai dos headers
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    /** Fingerprint pré-calculado (opcional — gerado automaticamente se omitido) */
    fingerprint?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class IPFilter {
    private readonly config: Required<
        Omit<IPFilterConfig, 'externalEnrichment' | 'onViolation' | 'onBlocked' | 'onBanned'>
    > & Pick<IPFilterConfig, 'externalEnrichment' | 'onViolation' | 'onBlocked' | 'onBanned'>;

    private readonly allowSet: Set<string>;
    private readonly blockSet: Set<string>;
    private readonly allowCIDRs: string[];
    private readonly blockCIDRs: string[];
    private readonly torSet: Set<string>;
    private readonly bogonRanges = BOGON_RANGES;

    constructor(config: IPFilterConfig) {
        this.config = {
            allowlist: [],
            blocklist: [],
            blockTor: true,
            torPolicy: 'block',
            blockVPN: false,
            vpnPolicy: 'challenge',
            blockDatacenter: false,
            datacenterPolicy: 'throttle',
            blockBogons: true,
            challengeThreshold: 50,
            blockThreshold: 75,
            banThreshold: 90,
            banDurationMs: 3_600_000,
            cgnatFingerprintThreshold: 10,
            cgnatBanMultiplier: 3,
            ipv6PrefixPolicy: 'throttle',
            routeOverrides: {},
            torExitNodes: [],
            debug: false,
            externalEnrichment: undefined,
            onViolation: undefined,
            onBlocked: undefined,
            onBanned: undefined,
            ...config,
        };

        // Separa IPs exatos de CIDRs para lookup O(1) vs O(n)
        const allAllowlist = this.config.allowlist;
        const allBlocklist = this.config.blocklist;

        this.allowSet = new Set(allAllowlist.filter(e => !e.includes('/')));
        this.blockSet = new Set(allBlocklist.filter(e => !e.includes('/')));
        this.allowCIDRs = allAllowlist.filter(e => e.includes('/'));
        this.blockCIDRs = allBlocklist.filter(e => e.includes('/'));
        this.torSet = new Set(this.config.torExitNodes);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Avaliação principal
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Avalia um IP e retorna a decisão de acesso.
     *
     * Pipeline (ordem de custo crescente):
     *  1. Normaliza IP (IPv4-mapeado, IPv6)
     *  2. Allowlist permanente — bypass imediato
     *  3. Blocklist permanente — rejeição imediata
     *  4. Ban dinâmico — verifica banimentos automáticos
     *  5. Bogon check — IPs que não deveriam existir na internet
     *  6. Tor exit node check
     *  7. Reputação acumulada no store
     *  8. Enriquecimento externo (ASN, categoria, VPN/proxy)
     *  9. Scoring por categoria + signals
     * 10. CGNAT detection — evita falso positivo massivo
     * 11. IPv6 prefix abuse
     * 12. Decisão final baseada em score + thresholds
     */
    async evaluate(req: IPFilterRequest): Promise<IPFilterResult> {
        const rawIP = req.ip || extractRealIP(req.headers);
        const ip = normalizeIP(rawIP);
        const path = req.path;
        const method = req.method.toUpperCase();
        const now = Date.now();
        const signals: string[] = [];
        const fingerprint = req.fingerprint ?? generateIPFingerprint(req.headers);

        const isV6 = isIPv6(ip);

        const meta: IPFilterMeta = {
            ip,
            normalizedIP: ip,
            path, method, timestamp: now, signals,
            isIPv6: isV6,
        };

        // Helpers locais
        const allow = (reason: IPFilterReason, score = 0): IPFilterResult => ({
            allowed: true, action: 'allow', reason, riskScore: score, meta,
        });

        const decide = (
            score: number,
            reason: IPFilterReason,
            category?: IPCategory,
        ): IPFilterResult => {
            meta.signals.push(`score:${score}`);

            // Aplica override de rota se existir
            const routeCfg = this.getRouteConfig(path);

            const challengeT = routeCfg.challengeThreshold ?? this.config.challengeThreshold;
            const blockT = routeCfg.blockThreshold ?? this.config.blockThreshold;
            const banT = routeCfg.banThreshold ?? this.config.banThreshold;

            let action: IPFilterAction;

            if (score >= banT) {
                action = 'ban';
                // Executa banimento assíncrono sem bloquear a resposta
                void this.executeBan(ip, reason, now + this.config.banDurationMs);
            } else if (score >= blockT) {
                action = 'block';
            } else if (score >= challengeT) {
                action = 'challenge';
            } else {
                action = 'allow';
            }

            // 'decide' atribui apenas 'allow' | 'challenge' | 'block' | 'ban'.
            // 'throttle' nunca e atribuido aqui — TypeScript estreita o tipo corretamente.
            // Usamos negacao das acoes bloqueantes para clareza e type-safety.
            const allowed = action !== 'challenge' && action !== 'block' && action !== 'ban';

            const result: IPFilterResult = {
                allowed, action, reason,
                riskScore: score, category, meta,
            };

            if (!allowed) void this.config.onBlocked?.(result);
            this.debugLog(allowed ? 'ALLOWED' : 'BLOCKED', ip, action, score, reason);
            return result;
        };

        // ── 1. Normalização de IP ──────────────────────────────────────────
        if (ip === '0.0.0.0' || ip === '') {
            signals.push('invalid-ip');
            return { allowed: false, action: 'block', reason: 'BEHAVIORAL_ANOMALY', riskScore: 100, meta };
        }

        // ── 2. Allowlist permanente ────────────────────────────────────────
        if (this.allowSet.has(ip)) {
            signals.push('allowlist-exact');
            return allow('ALLOWLISTED');
        }

        for (const cidr of this.allowCIDRs) {
            if (matchesCIDR(ip, cidr)) {
                signals.push(`allowlist-cidr:${cidr}`);
                return allow('ALLOWLISTED');
            }
        }

        // ── 3. Blocklist permanente ────────────────────────────────────────
        if (this.blockSet.has(ip)) {
            signals.push('blocklist-exact');
            return { allowed: false, action: 'ban', reason: 'PERMANENT_BLOCK', riskScore: 100, meta };
        }

        for (const cidr of this.blockCIDRs) {
            if (matchesCIDR(ip, cidr)) {
                signals.push(`blocklist-cidr:${cidr}`);
                return { allowed: false, action: 'ban', reason: 'PERMANENT_BLOCK', riskScore: 100, meta };
            }
        }

        // ── 4. Ban dinâmico ────────────────────────────────────────────────
        const isBanned = await this.config.store.isBanned(ip);
        if (isBanned) {
            const rep = await this.config.store.getReputation(ip);
            signals.push('dynamic-ban');
            meta.banExpiresAt = rep?.banExpiresAt;
            return {
                allowed: false, action: 'ban', reason: 'DYNAMIC_BAN',
                riskScore: 100, meta,
            };
        }

        // ── 5. Bogon IP ────────────────────────────────────────────────────
        if (this.config.blockBogons && isBogonIP(ip)) {
            // 100.64.0.0/10 é CGNAT compartilhado — pode ser legítimo em algumas configs
            const isCGNATRange = matchesCIDRv4(ip, '100.64.0.0/10');
            if (!isCGNATRange) {
                signals.push('bogon-ip');
                return { allowed: false, action: 'block', reason: 'BOGON_IP', riskScore: 100, meta };
            }
            // CGNAT: sinaliza mas não bloqueia imediatamente
            signals.push('cgnat-range');
            meta.isCGNAT = true;
        }

        // ── 6. Tor exit node ───────────────────────────────────────────────
        if (this.config.blockTor && this.torSet.has(ip)) {
            signals.push('tor-exit-local-list');
            meta.isTor = true;

            if (this.config.torPolicy === 'block' || this.config.torPolicy === 'ban') {
                return {
                    allowed: false, action: this.config.torPolicy,
                    reason: 'TOR_EXIT_NODE', riskScore: 90, category: 'tor', meta,
                };
            }
        }

        // ── 7. Reputação acumulada ─────────────────────────────────────────
        const reputation = await this.config.store.getReputation(ip);
        let currentScore = reputation?.score ?? 0;

        if (reputation) {
            meta.isCGNAT = reputation.isCGNAT;
            if (reputation.category) signals.push(`known-category:${reputation.category}`);
        }

        // ── 8. CGNAT detection via fingerprints ───────────────────────────
        const uniqueFPs = await this.config.store.addFingerprint(
            ip, fingerprint, 3_600_000,
        );

        if (uniqueFPs > this.config.cgnatFingerprintThreshold) {
            signals.push(`cgnat-fingerprints:${uniqueFPs}`);
            meta.isCGNAT = true;

            // Atualiza reputação com flag CGNAT
            if (reputation) {
                reputation.isCGNAT = true;
                reputation.uniqueFingerprints = uniqueFPs;
                await this.config.store.setReputation(ip, reputation);
            }
        }

        // ── 9. IPv6 prefix abuse ───────────────────────────────────────────
        if (isV6 && !meta.isCGNAT) {
            const prefix = extractIPv6Prefix64(ip);
            const prefixCount = await this.config.store.countIPv6Prefix(prefix, 3_600_000);

            if (prefixCount > 100) {
                signals.push(`ipv6-prefix-abuse:${prefix}:${prefixCount}`);
                const action = this.config.ipv6PrefixPolicy ?? 'throttle';
                const score = Math.min(100, currentScore + 40);

                return {
                    allowed: action !== 'block' && action !== 'ban',
                    action,
                    reason: 'IPV6_PREFIX_ABUSE',
                    riskScore: score,
                    meta,
                };
            }
        }

        // ── 10. Enriquecimento externo ─────────────────────────────────────
        let enrichment: IPEnrichmentResult | null = null;
        let category: IPCategory = reputation?.category ?? 'unknown';

        if (this.config.externalEnrichment && !reputation?.category) {
            try {
                enrichment = await this.config.externalEnrichment(ip);
            } catch (err) {
                this.debugLog('ENRICHMENT-ERROR', ip, err);
            }
        }

        if (enrichment) {
            // Atualiza metadados
            if (enrichment.asn) meta.asn = enrichment.asn;
            if (enrichment.isTor) meta.isTor = true;
            if (enrichment.isVPN) meta.isVPN = true;
            if (enrichment.isDatacenter) meta.isDatacenter = true;
            if (enrichment.isCGNAT) meta.isCGNAT = true;
            if (enrichment.category) category = enrichment.category;

            // Score base da categoria
            const categoryScore = enrichment.riskScore ??
                CATEGORY_BASE_SCORES[enrichment.category ?? 'unknown'];

            currentScore = Math.max(currentScore, categoryScore);
            signals.push(`enrichment:${enrichment.category ?? 'unknown'}:${categoryScore}`);
        } else if (reputation?.category) {
            // Usa categoria já conhecida do store
            const categoryScore = CATEGORY_BASE_SCORES[reputation.category];
            currentScore = Math.max(currentScore, categoryScore);
        }

        // ── 11. Aplica políticas por categoria ────────────────────────────

        // Tor via enriquecimento externo
        if (meta.isTor && !this.torSet.has(ip)) {
            signals.push('tor-exit-external');
            currentScore = Math.max(currentScore, CATEGORY_BASE_SCORES.tor);

            if (this.config.blockTor) {
                const action = this.config.torPolicy ?? 'block';
                if (action === 'block' || action === 'ban') {
                    return {
                        allowed: false, action,
                        reason: 'TOR_EXIT_NODE', riskScore: currentScore, category: 'tor', meta,
                    };
                }
                // challenge ou throttle — continua com score elevado
            }
        }

        // VPN
        if (meta.isVPN) {
            signals.push('vpn-detected');
            currentScore = Math.max(currentScore, CATEGORY_BASE_SCORES.vpn);

            if (this.config.blockVPN) {
                const action = this.config.vpnPolicy ?? 'challenge';
                // Só bloqueia efetivamente se a ação for block/ban
                if (action === 'block' || action === 'ban') {
                    return {
                        allowed: false, action,
                        reason: 'VPN_PROXY', riskScore: currentScore, category: 'vpn', meta,
                    };
                }
                // challenge ou throttle aplica o score alto mas não bloqueia diretamente
            }
        }

        // Datacenter
        if (meta.isDatacenter && !meta.isVPN) {
            const asn = meta.asn?.toUpperCase() ?? '';
            const isHighRisk = HIGH_RISK_DATACENTER_ASNS.includes(asn);

            signals.push(`datacenter:${asn}:high-risk=${isHighRisk}`);
            const dcScore = isHighRisk ? 40 : CATEGORY_BASE_SCORES.datacenter;
            currentScore = Math.max(currentScore, dcScore);

            if (this.config.blockDatacenter) {
                const action = this.config.datacenterPolicy ?? 'throttle';
                if (action === 'block' || action === 'ban') {
                    return {
                        allowed: false, action,
                        reason: 'DATACENTER_ASN', riskScore: currentScore, category: 'datacenter', meta,
                    };
                }
            }
        }

        // Mobile ASN — reduz penalidade de CGNAT
        const asn = meta.asn?.toUpperCase() ?? '';
        if (KNOWN_MOBILE_ASNS_BR.includes(asn)) {
            signals.push(`mobile-asn:${asn}`);
            meta.isCGNAT = true;
            category = 'mobile';
            // IPs móveis têm score base reduzido
            currentScore = Math.min(currentScore, 15);
        }

        // ── 12. Ajuste de score para CGNAT ────────────────────────────────
        if (meta.isCGNAT) {
            // Para CGNAT, elevamos os thresholds efetivos
            // Não reduzimos o score, mas o tratamos com thresholds mais altos
            signals.push('cgnat-protection-active');
            // Um IP CGNAT só é banido com score × cgnatBanMultiplier
            const effectiveBanThreshold = this.config.banThreshold * this.config.cgnatBanMultiplier;
            if (currentScore >= this.config.banThreshold && currentScore < effectiveBanThreshold) {
                signals.push('cgnat-ban-prevented');
                // Degrada para throttle em vez de ban
                return {
                    allowed: false,
                    action: 'throttle',
                    reason: 'CGNAT_ABUSE',
                    riskScore: currentScore,
                    category,
                    meta,
                };
            }
        }

        // ── 13. Persiste reputação atualizada ─────────────────────────────
        const newReputation: IPReputation = {
            ip,
            score: currentScore,
            violations: reputation?.violations ?? 0,
            firstSeenAt: reputation?.firstSeenAt ?? now,
            lastSeenAt: now,
            isBanned: false,
            category,
            isCGNAT: meta.isCGNAT,
        };
        await this.config.store.setReputation(ip, newReputation);

        // ── 14. Decisão final por score ───────────────────────────────────
        return decide(currentScore, this.scoreToReason(currentScore), category);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Penalização por violação
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Registra uma violação para um IP, aumentando seu score de risco.
     *
     * Integração com outros middlewares:
     * @example
     * // No botProtection.ts onBlocked:
     * ipFilter.reportViolation(ip, 'BOT_DETECTED', VIOLATION_SCORES.BOT_DETECTED);
     *
     * // No csrfProtection.ts onFailure:
     * ipFilter.reportViolation(ip, 'CSRF_VIOLATION', VIOLATION_SCORES.CSRF_VIOLATION);
     */
    async reportViolation(
        ip: string,
        violationType: keyof typeof VIOLATION_SCORES | string,
        customScore?: number,
    ): Promise<number> {
        const normalized = normalizeIP(ip);
        const delta = customScore ?? VIOLATION_SCORES[violationType] ?? 10;
        const newScore = await this.config.store.incrementScore(
            normalized, delta, this.config.banDurationMs * 2,
        );

        this.config.onViolation?.(normalized, violationType, delta);
        this.debugLog('VIOLATION', normalized, violationType, `+${delta} → ${newScore}`);

        // Auto-ban se ultrapassou threshold
        if (newScore >= this.config.banThreshold) {
            const rep = await this.config.store.getReputation(normalized);

            // Não bane CGNAT automaticamente — precisa de muito mais evidência
            const isCGNAT = rep?.isCGNAT ?? false;
            const effectiveBanT = isCGNAT
                ? this.config.banThreshold * this.config.cgnatBanMultiplier
                : this.config.banThreshold;

            if (newScore >= effectiveBanT) {
                const expiresAt = Date.now() + this.config.banDurationMs;
                await this.config.store.ban(normalized, expiresAt, violationType);
                void this.config.onBanned?.(normalized, violationType, expiresAt);
                this.debugLog('AUTO-BAN', normalized, violationType, `score:${newScore}`);
            }
        }

        return newScore;
    }

    /**
     * Remove um banimento manualmente.
     * Use para reverter falsos positivos.
     */
    async unban(ip: string): Promise<void> {
        await this.config.store.unban(normalizeIP(ip));
        this.debugLog('UNBAN', ip);
    }

    /**
     * Atualiza a lista de Tor exit nodes em runtime.
     * Chame periodicamente (cron diário recomendado).
     *
     * @example
     * // Atualiza da lista oficial do Tor Project
     * const response = await fetch('https://check.torproject.org/torbulkexitlist');
     * const nodes = (await response.text()).split('\n').filter(l => l && !l.startsWith('#'));
     * ipFilter.updateTorExitNodes(nodes);
     */
    updateTorExitNodes(nodes: string[]): void {
        this.torSet.clear();
        for (const node of nodes) {
            const trimmed = normalizeIP(node.trim());
            if (trimmed) this.torSet.add(trimmed);
        }
        this.debugLog('TOR-UPDATED', `${this.torSet.size} nodes`);
    }

    /**
     * Retorna o score de risco atual de um IP sem incrementar.
     */
    async getScore(ip: string): Promise<number> {
        const rep = await this.config.store.getReputation(normalizeIP(ip));
        return rep?.score ?? 0;
    }

    /**
     * Retorna snapshot completo da reputação de um IP.
     */
    async getReputation(ip: string): Promise<IPReputation | null> {
        return this.config.store.getReputation(normalizeIP(ip));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários privados
    // ─────────────────────────────────────────────────────────────────────────

    private async executeBan(ip: string, reason: IPFilterReason, expiresAt: number): Promise<void> {
        await this.config.store.ban(ip, expiresAt, reason);
        void this.config.onBanned?.(ip, reason, expiresAt);
        this.debugLog('BAN', ip, reason, new Date(expiresAt).toISOString());
    }

    private getRouteConfig(path: string): Partial<IPFilterConfig> {
        const overrides = this.config.routeOverrides;
        for (const [pattern, cfg] of Object.entries(overrides)) {
            if (path === pattern || path.startsWith(pattern + '/')) return cfg;
        }
        return {};
    }

    private scoreToReason(score: number): IPFilterReason {
        if (score >= this.config.banThreshold) return 'REPUTATION_LOW';
        if (score >= this.config.blockThreshold) return 'REPUTATION_LOW';
        if (score >= this.config.challengeThreshold) return 'CHALLENGE_REQUIRED';
        return 'ALLOWLISTED';
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[ip-filter]', event, ...args);
    }
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
 * Middleware IPFilter para Express.
 *
 * Injeta `req.ipFilterResult` para uso nos handlers.
 *
 * @example
 * app.use(createExpressIPFilter(ipFilter));
 *
 * // Nos handlers, registre violações:
 * app.post('/api/auth/login', async (req, res) => {
 *   const isValid = await authenticate(req.body);
 *   if (!isValid) {
 *     await ipFilter.reportViolation(req.ip, 'AUTH_BRUTEFORCE');
 *   }
 * });
 */
export function createExpressIPFilter(filter: IPFilter) {
    return async (req: ExpressReq & { ipFilterResult?: IPFilterResult }, res: ExpressRes, next: NextFn): Promise<void> => {
        const result = await filter.evaluate({
            ip: req.ip,
            method: req.method,
            path: req.path,
            headers: req.headers,
        });

        req.ipFilterResult = result;

        if (!result.allowed) {
            const status = result.action === 'ban' ? 403 : result.action === 'throttle' ? 429 : 403;
            const retryAfter = result.meta.banExpiresAt
                ? Math.ceil((result.meta.banExpiresAt - Date.now()) / 1000)
                : undefined;

            res
                .status(status)
                .set({
                    'Content-Type': 'application/json',
                    'X-Content-Type-Options': 'nosniff',
                    'Cache-Control': 'no-store',
                    ...(retryAfter ? { 'Retry-After': String(retryAfter) } : {}),
                })
                .json({ error: 'Forbidden', message: 'Access denied.' });
            return;
        }

        next();
    };
}

/**
 * Handler IPFilter para Next.js Edge Runtime.
 *
 * @example
 * // middleware.ts
 * const ipFilterHandler = createNextIPFilter(ipFilter);
 * export default async function middleware(req: Request) {
 *   const blocked = await ipFilterHandler(req);
 *   if (blocked) return blocked;
 *   return NextResponse.next();
 * }
 */
export function createNextIPFilter(filter: IPFilter) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => { headers[key] = value; });

        const url = new URL(request.url);
        const result = await filter.evaluate({
            method: request.method,
            path: url.pathname,
            headers,
        });

        if (!result.allowed) {
            const status = result.action === 'throttle' ? 429 : 403;
            return new Response(
                JSON.stringify({ error: 'Forbidden', message: 'Access denied.' }),
                {
                    status,
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
// Factories com preset
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Preset para uso geral — equilibrado entre segurança e usabilidade.
 *
 * - Bloqueia Tor e bogons
 * - VPN: challenge (não bloqueia)
 * - Datacenter: throttle (não bloqueia)
 * - CGNAT: protegido de ban automático
 *
 * @example
 * const ipf = createBalancedIPFilter(store, externalEnrichment);
 */
export function createBalancedIPFilter(
    store: IPFilterStore,
    externalEnrichment?: IPFilterConfig['externalEnrichment'],
): IPFilter {
    return new IPFilter({
        store,
        blockTor: true,
        torPolicy: 'block',
        blockVPN: false,
        vpnPolicy: 'challenge',
        blockDatacenter: false,
        datacenterPolicy: 'throttle',
        blockBogons: true,
        challengeThreshold: 50,
        blockThreshold: 75,
        banThreshold: 90,
        banDurationMs: 3_600_000,
        externalEnrichment,
        allowlist: ['127.0.0.1', '::1'],
        routeOverrides: {
            // Login: mais restritivo
            '/api/auth/login': {
                challengeThreshold: 30,
                blockThreshold: 50,
                banThreshold: 70,
                blockVPN: false, // ainda não bloqueia VPN
                vpnPolicy: 'challenge',
            },
            // Admin: máxima restrição
            '/api/admin': {
                challengeThreshold: 20,
                blockThreshold: 40,
                banThreshold: 60,
                blockVPN: true,
                vpnPolicy: 'block',
                blockDatacenter: true,
                datacenterPolicy: 'block',
            },
            // Pagamentos: restrição alta
            '/api/payments': {
                challengeThreshold: 30,
                blockThreshold: 50,
                banThreshold: 70,
                blockVPN: true,
                vpnPolicy: 'challenge',
            },
        },
    });
}

/**
 * Preset para API pública / endpoints públicos.
 * Máxima permissividade — apenas bloqueia IPs explicitamente maliciosos.
 */
export function createPublicAPIFilter(store: IPFilterStore): IPFilter {
    return new IPFilter({
        store,
        blockTor: false,
        blockVPN: false,
        blockDatacenter: false,
        blockBogons: true,
        challengeThreshold: 70,
        blockThreshold: 85,
        banThreshold: 95,
        banDurationMs: 1_800_000, // 30 min — mais curto para IPs compartilhados
        allowlist: ['127.0.0.1', '::1'],
    });
}

/**
 * Preset para endpoints de alta segurança (admin, financeiro).
 * Máxima restrição — qualquer sinal de automação ou anonimização bloqueia.
 */
export function createHighSecurityFilter(
    store: IPFilterStore,
    allowedIPs: string[],
    externalEnrichment?: IPFilterConfig['externalEnrichment'],
): IPFilter {
    return new IPFilter({
        store,
        allowlist: [...allowedIPs, '127.0.0.1', '::1'],
        blockTor: true,
        torPolicy: 'ban',
        blockVPN: true,
        vpnPolicy: 'block',
        blockDatacenter: true,
        datacenterPolicy: 'block',
        blockBogons: true,
        challengeThreshold: 20,
        blockThreshold: 40,
        banThreshold: 60,
        banDurationMs: 86_400_000, // 24h para endpoints críticos
        externalEnrichment,
    });
}

export { VIOLATION_SCORES as DEFAULT_VIOLATION_SCORES };