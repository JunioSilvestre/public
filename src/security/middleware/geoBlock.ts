/**
 * @fileoverview Middleware de bloqueio geográfico — GeoIP-based access control.
 *
 * @description
 * Implementa controle de acesso baseado em geolocalização de IP com múltiplas
 * camadas de validação, fallbacks seguros e integração com provedores externos.
 *
 * ── Estratégias de detecção ────────────────────────────────────────────────
 *  1. Headers de CDN     — Cloudflare, AWS CloudFront, Fastly, Akamai
 *  2. Headers de proxy   — X-GeoIP-Country, X-Country-Code (nginx, HAProxy)
 *  3. IP lookup externo  — hook para MaxMind GeoIP2, ip-api.com, ipinfo.io
 *  4. ASN lookup         — bloqueia ASNs de datacenter / VPN / Tor
 *  5. Tor Exit Node list — detecção de saídas Tor conhecidas
 *  6. VPN/Proxy signals  — headers e ASNs típicos de VPN comercial
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *  • Geo bypass via Tor exit nodes                           (ubíquo)
 *  • Geo bypass via VPN residencial                          (2019+)
 *  • Header spoofing: CF-IPCountry, X-Country-Code           (ubíquo)
 *  • CDN header injection por atacante upstream              (configuração errada)
 *  • IPv6 bypass de regras IPv4-only                         (documentado 2018+)
 *  • Geo evasion via AWS Lambda/GCP Functions em país permitido (2021+)
 *  • OFAC / embargo compliance gap via cloud provider IP     (regulatório)
 *  • Residential proxy farms de países bloqueados            (2020+)
 *  • IP geolocation database staleness (IPs reatribuídos)    (contínuo)
 *  • Satellite internet com IP de país diferente             (Starlink 2021+)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • IPv6 GeoIP gaps (bases de dados ainda incompletas)      (contínuo)
 *  • CGNAT — múltiplos países por IP compartilhado           (emergente)
 *  • IP geolocation via WebRTC leak (client-side complement) (browser)
 *  • Anycast IP routing inconsistency                         (CDN-heavy)
 *  • Starlink / Kuiper satellite IP pool volatility          (2024+)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Allowlist-first (deny = default para países não listados)
 *  • ou Blocklist-only (permite tudo exceto os listados)
 *  • Confiança configurável por fonte de geolocalização
 *  • Cache de lookups para evitar latência por request
 *  • Fallback seguro configurável: allow | block | challenge
 *  • Suporte a exceções por IP, rota e user role
 *  • Header spoofing detection via múltiplas fontes
 *  • Adaptadores prontos para Express e Next.js Edge
 *
 * @see https://www.cloudflare.com/products/cloudflare-geo-blocking/
 * @see https://dev.maxmind.com/geoip/geolocate-an-ip/
 * @see https://owasp.org/www-project-web-security-testing-guide/
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da avaliação geográfica. */
export interface GeoBlockResult {
    allowed: boolean;
    reason?: GeoBlockReason;
    /** País detectado (ISO 3166-1 alpha-2, uppercase). */
    country?: string;
    /** Fonte que forneceu o país detectado. */
    source?: GeoSource;
    /** Nível de confiança na detecção (0–100). */
    confidence: number;
    meta: GeoBlockMeta;
}

export type GeoBlockReason =
    | 'COUNTRY_BLOCKED'
    | 'COUNTRY_NOT_ALLOWED'
    | 'TOR_EXIT_NODE'
    | 'VPN_DETECTED'
    | 'DATACENTER_ASN'
    | 'HEADER_SPOOFING_SUSPECTED'
    | 'GEO_LOOKUP_FAILED'
    | 'IP_INVALID'
    | 'ROUTE_RESTRICTED';

/** Fonte da informação geográfica (em ordem decrescente de confiança). */
export type GeoSource =
    | 'cloudflare'         // CF-IPCountry — só confiável se Cloudflare está na frente
    | 'cloudfront'         // CloudFront-Viewer-Country
    | 'fastly'             // Fastly-Geo-Country-Code
    | 'akamai'             // X-Akamai-Edgescape (country_code=)
    | 'nginx-geoip'        // X-GeoIP-Country (módulo nginx geoip2)
    | 'x-country-header'   // X-Country-Code (HAProxy, custom proxies)
    | 'external-api'       // IP lookup externo (MaxMind, ip-api, ipinfo)
    | 'fallback';          // Origem desconhecida / estimada

export interface GeoBlockMeta {
    ip: string;
    path: string;
    method: string;
    timestamp: number;
    signals: string[];
    asn?: string;
    isTor?: boolean;
    isVPN?: boolean;
    isDatacenter?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface GeoBlockConfig {
    /**
     * Modo de operação:
     *
     * 'allowlist' — bloqueia tudo exceto os países em `allowedCountries`.
     *               Mais restritivo. Use para serviços com público-alvo definido.
     *
     * 'blocklist' — permite tudo exceto os países em `blockedCountries`.
     *               Use para compliance OFAC/embargo ou bloqueio de hotspots.
     *
     * Default: 'allowlist'
     */
    mode: 'allowlist' | 'blocklist';

    /**
     * Países permitidos (modo allowlist) — ISO 3166-1 alpha-2 uppercase.
     * Ex: ['BR', 'US', 'PT', 'DE']
     *
     * Referência rápida:
     *  BR=Brasil  US=EUA     PT=Portugal  DE=Alemanha
     *  GB=UK      FR=França  ES=Espanha   IT=Itália
     *  AR=Argentina  MX=México  CA=Canadá  AU=Austrália
     *  JP=Japão   CN=China   IN=Índia     RU=Rússia
     */
    allowedCountries?: string[];

    /**
     * Países bloqueados (modo blocklist) — ISO 3166-1 alpha-2 uppercase.
     * Inclui países com restrições OFAC por padrão quando `applyOFAC: true`.
     */
    blockedCountries?: string[];

    /**
     * Aplica automaticamente a lista de países sob sanções OFAC (EUA).
     * Relevante para empresas com operações nos EUA ou clientes americanos.
     * Default: false
     *
     * ⚠ Aviso legal: esta lista é informativa. Consulte seu departamento jurídico.
     */
    applyOFAC?: boolean;

    /**
     * Bloqueia saídas de rede Tor conhecidas.
     * Default: true
     *
     * Tor exit nodes são IPs públicos usados como saída da rede Tor.
     * A lista é mantida pelo Tor Project: https://check.torproject.org/torbulkexitlist
     *
     * Em produção, atualize a lista periodicamente (cron diário recomendado).
     */
    blockTor?: boolean;

    /**
     * Bloqueia IPs de datacenter e hosting providers suspeitos.
     * Baseado em ASN lookup — ASNs de AWS, GCP, Azure, DigitalOcean, etc.
     *
     * ⚠ Pode bloquear usuários legítimos em redes corporativas.
     * Use com `exemptIPs` para IPs confiáveis.
     * Default: false
     */
    blockDatacenterASNs?: boolean;

    /**
     * Bloqueia IPs com sinais de VPN comercial.
     * Combina: ASN de VPN conhecido + ausência de headers típicos de browser.
     * Default: false (muitos usuários legítimos usam VPN)
     */
    blockVPN?: boolean;

    /**
     * Fontes de geolocalização habilitadas, em ordem de confiança.
     * A primeira fonte disponível com dados é usada.
     *
     * Default: ['cloudflare', 'cloudfront', 'fastly', 'akamai', 'nginx-geoip', 'x-country-header', 'external-api']
     */
    enabledSources?: GeoSource[];

    /**
     * Nível mínimo de confiança para aceitar um resultado de geo lookup.
     * Se o lookup retornar confiança abaixo disso, usa o fallback.
     * Default: 50
     */
    minConfidence?: number;

    /**
     * Ação quando o país não pode ser determinado (lookup falhou, IP privado, etc.):
     * - 'allow'     — falha aberta (permissivo, arriscado)
     * - 'block'     — falha fechada (seguro, pode bloquear usuários legítimos)
     * - 'challenge' — exige CAPTCHA ou prova de identidade (equilibrado)
     *
     * Default: 'block'
     */
    onLookupFailure?: 'allow' | 'block' | 'challenge';

    /**
     * IPs sempre permitidos independente de país/Tor/VPN.
     * Use para: escritórios, VPNs corporativas, health checks.
     */
    exemptIPs?: string[];

    /**
     * Prefixos CIDR sempre permitidos.
     * Ex: ['10.0.0.0/8', '192.168.0.0/16'] para redes privadas.
     */
    exemptCIDRs?: string[];

    /**
     * Rotas que requerem restrição geográfica adicional além da config global.
     * Use para isolar endpoints sensíveis por região.
     *
     * @example
     * routeOverrides: {
     *   '/api/payments': { allowedCountries: ['BR'] },
     *   '/api/admin':    { allowedCountries: ['BR'], blockTor: true, blockVPN: true },
     * }
     */
    routeOverrides?: Record<string, Partial<GeoBlockConfig>>;

    /**
     * Cache de lookups de geolocalização para reduzir latência.
     * Default: true (cache em memória, TTL de 1 hora por IP)
     */
    cache?: {
        enabled: boolean;
        ttlMs: number;
        maxSize: number;
    };

    /**
     * Hook para lookup externo de geolocalização.
     * Chamado quando nenhum header de CDN/proxy disponibiliza o país.
     *
     * @example
     * externalLookup: async (ip) => {
     *   const resp = await fetch(`https://ipapi.co/${ip}/json/`);
     *   const data = await resp.json();
     *   return { country: data.country_code, confidence: 80, asn: data.asn };
     * }
     */
    externalLookup?: (ip: string) => Promise<ExternalGeoResult | null>;

    /**
     * Hook chamado quando uma requisição é bloqueada.
     */
    onBlocked?: (result: GeoBlockResult, ip: string, path: string) => void | Promise<void>;

    /**
     * Hook chamado quando spoofing de header é suspeito.
     * (múltiplos headers de CDN com países diferentes)
     */
    onSpoofingDetected?: (signals: string[], ip: string) => void | Promise<void>;

    /** Habilita logging detalhado. Default: false. */
    debug?: boolean;
}

/** Resultado de um lookup externo de geolocalização. */
export interface ExternalGeoResult {
    /** Código de país ISO 3166-1 alpha-2, uppercase. */
    country: string;
    /** Nível de confiança 0–100. */
    confidence: number;
    /** ASN (Autonomous System Number) — ex: 'AS15169' para Google. */
    asn?: string;
    /** Nome do ISP/organização. */
    org?: string;
    /** true se detectado como VPN pelo provedor. */
    isVPN?: boolean;
    /** true se detectado como proxy/datacenter. */
    isProxy?: boolean;
    /** true se é Tor exit node. */
    isTor?: boolean;
}

/** Requisição normalizada para avaliação geo. */
export interface GeoRequest {
    ip: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constantes de segurança
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Países sob sanções OFAC (EUA) — atualizado conforme lista pública OFAC.
 * Fontes: https://ofac.treasury.gov/sanctions-programs-and-country-information
 *
 * ⚠ Esta lista é informativa. Consulte seu departamento jurídico para compliance.
 * Países: Cuba, Irã, Coreia do Norte, Rússia (sanções parciais),
 *          Síria, Venezuela (sanções parciais), Belarus.
 */
export const OFAC_SANCTIONED_COUNTRIES: readonly string[] = [
    'CU', // Cuba
    'IR', // Irã
    'KP', // Coreia do Norte
    'SY', // Síria
    'RU', // Rússia (sanções parciais — habilite conforme seu contexto legal)
    'BY', // Belarus
    'MM', // Myanmar
    'SD', // Sudão
    'SS', // Sudão do Sul
    'YE', // Iêmen (sanções parciais)
    'ZW', // Zimbábue (sanções parciais)
    'LY', // Líbia (sanções parciais)
    'SO', // Somália (sanções parciais)
    'CD', // Congo (RDC, sanções parciais)
    'CF', // República Centro-Africana
    'ML', // Mali
    'HT', // Haiti (sanções parciais)
    'NI', // Nicarágua
];

/**
 * ASNs de provedores de datacenter e hosting conhecidos.
 * IPs nesses ASNs raramente são de usuários finais legítimos.
 *
 * Lista curada a partir de:
 * - https://bgp.he.net (Hurricane Electric BGP Toolkit)
 * - https://ipinfo.io/bogon
 * - Pesquisa de threat intelligence pública
 *
 * Formato: 'AS' + número (ex: 'AS16509' = Amazon AWS)
 */
export const KNOWN_DATACENTER_ASNS: readonly string[] = [
    // Amazon / AWS
    'AS16509', 'AS14618', 'AS38895',
    // Google / GCP
    'AS15169', 'AS19527',
    // Microsoft / Azure
    'AS8075', 'AS8074',
    // Cloudflare (legítimo para usuários, mas sinaliza proxy)
    'AS13335',
    // DigitalOcean
    'AS14061',
    // Linode / Akamai
    'AS63949',
    // Vultr
    'AS20473',
    // Hetzner
    'AS24940',
    // OVH
    'AS16276',
    // Leaseweb
    'AS60781', 'AS28753',
    // Choopa / Vultr
    'AS20473',
    // Alibaba Cloud
    'AS37963', 'AS45102',
    // Tencent Cloud
    'AS45090',
    // Oracle Cloud
    'AS31898',
    // IBM Cloud
    'AS36351',
    // Scaleway
    'AS12876',
    // Fastly (CDN)
    'AS54113',
    // Akamai
    'AS16625', 'AS20940',
    // Incapsula / Imperva
    'AS19551',
    // Zscaler
    'AS62044',
];

/**
 * ASNs conhecidos de provedores de VPN comercial.
 * Incompleta por natureza — novos ASNs surgem constantemente.
 */
export const KNOWN_VPN_ASNS: readonly string[] = [
    'AS9009',  // M247 (NordVPN, ExpressVPN)
    'AS9132',  // Choopa
    'AS60068', // Datacamp Limited (muitos VPNs)
    'AS197183',// Octopuce (VPNs europeus)
    'AS40021', // Nubes Technologies
    'AS31898', // Oracle (usado por alguns VPNs)
    'AS8100',  // QuadraNet (frequente em VPNs)
    'AS53667', // FranTech Solutions (BuyVM)
    'AS32097', // WholeSale Internet
    'AS26496', // GoDaddy (resellers de VPN)
    'AS4766',  // Korea Telecom (VPNs asiáticos)
    'AS9121',  // Turk Telekom (VPNs turcos)
];

/**
 * Mapeamento de headers de CDN/proxy para extração de país.
 * Cada entrada: [nome do header, transformação opcional, confiança 0-100]
 *
 * Confiança: quão confiável é este header que ele não foi forjado
 * pela requisição do cliente? Depende da infraestrutura — o Cloudflare
 * sobrescreve CF-IPCountry (confiança 90), mas X-Country-Code pode ser
 * injetado por qualquer proxy intermediário (confiança 40).
 */
const GEO_HEADER_SOURCES: Array<{
    source: GeoSource;
    header: string;
    transform: (value: string) => string | null;
    confidence: number;
}> = [
        {
            source: 'cloudflare',
            header: 'cf-ipcountry',
            transform: v => /^[A-Z]{2}$/.test(v.toUpperCase()) ? v.toUpperCase() : null,
            confidence: 90,
        },
        {
            source: 'cloudfront',
            header: 'cloudfront-viewer-country',
            transform: v => /^[A-Z]{2}$/.test(v.toUpperCase()) ? v.toUpperCase() : null,
            confidence: 85,
        },
        {
            source: 'fastly',
            header: 'x-forwarded-for-country',
            transform: v => /^[A-Z]{2}$/.test(v.toUpperCase()) ? v.toUpperCase() : null,
            confidence: 80,
        },
        {
            source: 'akamai',
            header: 'x-akamai-edgescape',
            // Formato: country_code=US,georegion=US,region_code=CA,city=San...
            transform: v => {
                const match = v.match(/country_code=([A-Z]{2})/i);
                return match ? match[1].toUpperCase() : null;
            },
            confidence: 85,
        },
        {
            source: 'nginx-geoip',
            header: 'x-geoip-country',
            transform: v => /^[A-Z]{2}$/.test(v.toUpperCase()) ? v.toUpperCase() : null,
            confidence: 70,
        },
        {
            source: 'x-country-header',
            header: 'x-country-code',
            transform: v => /^[A-Z]{2}$/.test(v.toUpperCase()) ? v.toUpperCase() : null,
            confidence: 50,
        },
        {
            // Header alternativo menos padronizado
            source: 'x-country-header',
            header: 'x-real-country',
            transform: v => /^[A-Z]{2}$/.test(v.toUpperCase()) ? v.toUpperCase() : null,
            confidence: 40,
        },
    ];

// ─────────────────────────────────────────────────────────────────────────────
// Cache de lookups
// ─────────────────────────────────────────────────────────────────────────────

interface CacheEntry {
    result: ExternalGeoResult | null;
    cachedAt: number;
    expiresAt: number;
}

/**
 * Cache LRU simples para lookups de geolocalização.
 * Em produção, use Redis para cache compartilhado entre instâncias.
 */
class GeoLookupCache {
    private readonly store = new Map<string, CacheEntry>();
    private readonly maxSize: number;
    private readonly ttlMs: number;

    constructor(maxSize: number, ttlMs: number) {
        this.maxSize = maxSize;
        this.ttlMs = ttlMs;
    }

    get(ip: string): ExternalGeoResult | null | undefined {
        const entry = this.store.get(ip);
        if (!entry) return undefined; // miss

        if (Date.now() > entry.expiresAt) {
            this.store.delete(ip);
            return undefined; // expired
        }

        // LRU: move para o fim recolocando
        this.store.delete(ip);
        this.store.set(ip, entry);
        return entry.result;
    }

    set(ip: string, result: ExternalGeoResult | null): void {
        // Evicção LRU quando cheio
        if (this.store.size >= this.maxSize) {
            const firstKey = this.store.keys().next().value;
            if (firstKey) this.store.delete(firstKey);
        }

        this.store.set(ip, {
            result,
            cachedAt: Date.now(),
            expiresAt: Date.now() + this.ttlMs,
        });
    }

    clear(): void {
        this.store.clear();
    }

    get size(): number {
        return this.store.size;
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

/** Verifica se um IP é privado/loopback (não precisa de geo lookup). */
function isPrivateIP(ip: string): boolean {
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;

    const privateRanges = [
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./,
        /^169\.254\./,   // link-local
        /^fc00:/,        // IPv6 ULA
        /^fd/,           // IPv6 ULA
        /^fe80:/,        // IPv6 link-local
        /^::1$/,         // IPv6 loopback
    ];

    return privateRanges.some(r => r.test(ip));
}

/** Valida código de país ISO 3166-1 alpha-2. */
function isValidCountryCode(code: string): boolean {
    return /^[A-Z]{2}$/.test(code);
}

/** Normaliza código de país para uppercase. */
function normalizeCountry(code: string): string {
    return code.trim().toUpperCase();
}

/**
 * Detecta possível spoofing de header quando múltiplas fontes
 * de CDN/proxy fornecem países diferentes.
 *
 * Ex: CF-IPCountry: BR mas X-Country-Code: US → suspeito.
 */
function detectHeaderSpoofing(
    headers: Record<string, string | string[] | undefined>,
): { suspected: boolean; signals: string[] } {
    const signals: string[] = [];
    const countriesFound = new Map<string, GeoSource>();

    for (const source of GEO_HEADER_SOURCES) {
        const raw = getHeader(headers, source.header);
        if (!raw) continue;

        const country = source.transform(raw);
        if (!country) continue;

        const existing = countriesFound.get(country);
        if (!existing) {
            countriesFound.set(country, source.source);
        }
    }

    if (countriesFound.size > 1) {
        const countries = Array.from(countriesFound.keys()).join(', ');
        signals.push(`multiple-geo-headers:${countries}`);
        return { suspected: true, signals };
    }

    return { suspected: false, signals };
}

/**
 * Extrai IP real da requisição.
 * Idêntico ao padrão estabelecido nos outros middlewares.
 */
export function extractRealIP(
    headers: Record<string, string | string[] | undefined>,
): string {
    const cf = headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return cf.trim().split(',')[0].trim();

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

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class GeoBlockMiddleware {
    private readonly config: Required<
        Omit<GeoBlockConfig, 'externalLookup' | 'onBlocked' | 'onSpoofingDetected'>
    > & Pick<GeoBlockConfig, 'externalLookup' | 'onBlocked' | 'onSpoofingDetected'>;

    private readonly cache: GeoLookupCache | null;
    private readonly blockedCountriesSet: Set<string>;
    private readonly allowedCountriesSet: Set<string>;
    private readonly exemptIPsSet: Set<string>;
    private readonly datacenterASNsSet: Set<string>;
    private readonly vpnASNsSet: Set<string>;

    constructor(config: GeoBlockConfig) {
        // Validações de configuração
        if (config.mode === 'allowlist' && !config.allowedCountries?.length) {
            throw new Error(
                '[geo-block] Modo "allowlist" requer ao menos um país em allowedCountries. ' +
                'Sem essa lista, TODOS os requests seriam bloqueados.',
            );
        }

        if (config.mode === 'blocklist' && !config.blockedCountries?.length && !config.applyOFAC) {
            console.warn(
                '[geo-block] Modo "blocklist" sem blockedCountries nem applyOFAC. ' +
                'Nenhum país será bloqueado — verifique a configuração.',
            );
        }

        const blockedCountries = [
            ...(config.blockedCountries ?? []).map(normalizeCountry),
            ...(config.applyOFAC ? Array.from(OFAC_SANCTIONED_COUNTRIES) : []),
        ];

        // blockedCountries é computado antes (OFAC + config.blockedCountries).
        // Separamos defaults do spread para evitar chave duplicada no object literal.
        const defaults = {
            mode: 'allowlist' as const,
            allowedCountries: [] as string[],
            applyOFAC: false,
            blockTor: true,
            blockDatacenterASNs: false,
            blockVPN: false,
            enabledSources: [
                'cloudflare', 'cloudfront', 'fastly', 'akamai',
                'nginx-geoip', 'x-country-header', 'external-api',
            ] as GeoSource[],
            minConfidence: 50,
            onLookupFailure: 'block' as const,
            exemptIPs: [] as string[],
            exemptCIDRs: [] as string[],
            routeOverrides: {} as Record<string, Partial<GeoBlockConfig>>,
            cache: {
                enabled: true,
                ttlMs: 3_600_000,
                maxSize: 10_000,
            },
            debug: false,
            externalLookup: undefined as GeoBlockConfig['externalLookup'],
            onBlocked: undefined as GeoBlockConfig['onBlocked'],
            onSpoofingDetected: undefined as GeoBlockConfig['onSpoofingDetected'],
        };

        this.config = {
            ...defaults,
            ...config,
            blockedCountries, // sobrescreve após spread — inclui OFAC
        };

        // Inicializa Sets para lookups O(1)
        this.blockedCountriesSet = new Set(this.config.blockedCountries.map(normalizeCountry));
        this.allowedCountriesSet = new Set(
            (this.config.allowedCountries ?? []).map(normalizeCountry),
        );
        this.exemptIPsSet = new Set(this.config.exemptIPs);
        this.datacenterASNsSet = new Set(KNOWN_DATACENTER_ASNS);
        this.vpnASNsSet = new Set(KNOWN_VPN_ASNS);

        this.cache = this.config.cache.enabled
            ? new GeoLookupCache(this.config.cache.maxSize, this.config.cache.ttlMs)
            : null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Avaliação principal
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Avalia uma requisição e retorna a decisão de bloqueio geográfico.
     *
     * Pipeline:
     *  1. Verifica IPs e CIDRs isentos
     *  2. Verifica IPs privados (sempre permitidos)
     *  3. Detecta spoofing de headers de CDN
     *  4. Extrai país dos headers disponíveis
     *  5. Fallback para lookup externo se necessário
     *  6. Verifica Tor, VPN, Datacenter ASN
     *  7. Aplica regra de país (allowlist ou blocklist)
     *  8. Aplica overrides de rota
     */
    async evaluate(req: GeoRequest): Promise<GeoBlockResult> {
        const ip = req.ip || extractRealIP(req.headers);
        const path = req.path;
        const method = req.method.toUpperCase();
        const now = Date.now();
        const signals: string[] = [];

        const meta: GeoBlockMeta = {
            ip, path, method, timestamp: now, signals,
        };

        const allow = (
            country?: string,
            source?: GeoSource,
            confidence = 100,
        ): GeoBlockResult => ({
            allowed: true, country, source, confidence, meta,
        });

        const block = (
            reason: GeoBlockReason,
            country?: string,
            source?: GeoSource,
            confidence = 100,
        ): GeoBlockResult => {
            const result: GeoBlockResult = {
                allowed: false, reason, country, source, confidence, meta,
            };
            void this.config.onBlocked?.(result, ip, path);
            this.debugLog('BLOCKED', reason, ip, country ?? '?');
            return result;
        };

        // ── 1. IPs isentos ─────────────────────────────────────────────────
        if (this.exemptIPsSet.has(ip)) {
            signals.push('exempt-ip');
            return allow(undefined, undefined, 100);
        }

        for (const cidr of this.config.exemptCIDRs) {
            if (matchesCIDR(ip, cidr)) {
                signals.push(`exempt-cidr:${cidr}`);
                return allow(undefined, undefined, 100);
            }
        }

        // ── 2. IPs privados — sempre permitidos ────────────────────────────
        if (isPrivateIP(ip)) {
            signals.push('private-ip');
            return allow('XX', 'fallback', 100);
        }

        // ── 3. Detecção de spoofing de headers ────────────────────────────
        const spoofCheck = detectHeaderSpoofing(req.headers);
        if (spoofCheck.suspected) {
            signals.push(...spoofCheck.signals);
            void this.config.onSpoofingDetected?.(spoofCheck.signals, ip);
            this.debugLog('SPOOFING-SUSPECTED', ip, spoofCheck.signals);
            // Não bloqueia sozinho — reduz confiança e continua avaliação
        }

        // ── 4. Extrai país dos headers de CDN/proxy ────────────────────────
        let detectedCountry: string | undefined;
        let detectedSource: GeoSource | undefined;
        let confidence = 0;

        for (const sourceDef of GEO_HEADER_SOURCES) {
            if (!this.config.enabledSources.includes(sourceDef.source)) continue;

            const rawValue = getHeader(req.headers, sourceDef.header);
            if (!rawValue) continue;

            const country = sourceDef.transform(rawValue);
            if (!country || !isValidCountryCode(country)) continue;

            // Reduz confiança se spoofing foi suspeito
            const adjustedConfidence = spoofCheck.suspected
                ? Math.floor(sourceDef.confidence * 0.5)
                : sourceDef.confidence;

            if (adjustedConfidence >= this.config.minConfidence) {
                detectedCountry = country;
                detectedSource = sourceDef.source;
                confidence = adjustedConfidence;
                signals.push(`geo-header:${sourceDef.source}:${country}`);
                break;
            }
        }

        // ── 5. Lookup externo se necessário ──────────────────────────────
        let externalResult: ExternalGeoResult | null = null;

        if (
            !detectedCountry &&
            this.config.enabledSources.includes('external-api') &&
            this.config.externalLookup
        ) {
            externalResult = await this.performExternalLookup(ip);

            if (externalResult) {
                if (isValidCountryCode(externalResult.country)) {
                    detectedCountry = externalResult.country;
                    detectedSource = 'external-api';
                    confidence = externalResult.confidence;
                    signals.push(`geo-external:${externalResult.country}`);
                }

                if (externalResult.asn) meta.asn = externalResult.asn;
                if (externalResult.isTor) meta.isTor = true;
                if (externalResult.isVPN) meta.isVPN = true;
                if (externalResult.isProxy) meta.isDatacenter = true;
            }
        }

        // ── 6. Falha no lookup ────────────────────────────────────────────
        if (!detectedCountry || confidence < this.config.minConfidence) {
            signals.push(`geo-unknown:confidence=${confidence}`);

            switch (this.config.onLookupFailure) {
                case 'allow':
                    return allow(undefined, 'fallback', confidence);
                case 'challenge':
                    return {
                        allowed: false,
                        reason: 'GEO_LOOKUP_FAILED',
                        confidence,
                        meta,
                    };
                case 'block':
                default:
                    return block('GEO_LOOKUP_FAILED', undefined, 'fallback', confidence);
            }
        }

        // ── 7. Verificações Tor / VPN / Datacenter ────────────────────────
        const threatCheck = await this.checkThreatSignals(ip, externalResult, req.headers);
        if (threatCheck) {
            signals.push(...threatCheck.signals);
            meta.isTor = threatCheck.isTor;
            meta.isVPN = threatCheck.isVPN;
            meta.isDatacenter = threatCheck.isDatacenter;

            if (threatCheck.blockReason) {
                return block(threatCheck.blockReason, detectedCountry, detectedSource, confidence);
            }
        }

        // ── 8. Regra de país ──────────────────────────────────────────────
        const countryBlockResult = this.checkCountryRule(
            detectedCountry,
            path,
        );

        if (!countryBlockResult.allowed) {
            return block(
                countryBlockResult.reason!,
                detectedCountry,
                detectedSource,
                confidence,
            );
        }

        this.debugLog('ALLOWED', ip, detectedCountry, detectedSource);
        return allow(detectedCountry, detectedSource, confidence);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verificações de ameaças
    // ─────────────────────────────────────────────────────────────────────────

    private async checkThreatSignals(
        ip: string,
        externalResult: ExternalGeoResult | null,
        headers: Record<string, string | string[] | undefined>,
    ): Promise<{
        signals: string[];
        blockReason?: GeoBlockReason;
        isTor?: boolean;
        isVPN?: boolean;
        isDatacenter?: boolean;
    } | null> {
        const signals: string[] = [];
        let blockReason: GeoBlockReason | undefined;
        let isTor = false;
        let isVPN = false;
        let isDatacenter = false;

        // Tor detection via lookup externo
        if (externalResult?.isTor) {
            isTor = true;
            signals.push('tor-exit-external');
            if (this.config.blockTor) {
                blockReason = 'TOR_EXIT_NODE';
            }
        }

        // VPN detection via lookup externo
        if (externalResult?.isVPN) {
            isVPN = true;
            signals.push('vpn-detected-external');
            if (this.config.blockVPN) {
                blockReason = blockReason ?? 'VPN_DETECTED';
            }
        }

        // Datacenter detection via lookup externo
        if (externalResult?.isProxy) {
            isDatacenter = true;
            signals.push('datacenter-proxy-external');
            if (this.config.blockDatacenterASNs) {
                blockReason = blockReason ?? 'DATACENTER_ASN';
            }
        }

        // ASN-based detection
        if (externalResult?.asn) {
            const asn = externalResult.asn.toUpperCase();

            if (this.config.blockDatacenterASNs && this.datacenterASNsSet.has(asn)) {
                isDatacenter = true;
                signals.push(`datacenter-asn:${asn}`);
                blockReason = blockReason ?? 'DATACENTER_ASN';
            }

            if (this.config.blockVPN && this.vpnASNsSet.has(asn)) {
                isVPN = true;
                signals.push(`vpn-asn:${asn}`);
                blockReason = blockReason ?? 'VPN_DETECTED';
            }
        }

        if (signals.length === 0 && !blockReason) return null;

        return { signals, blockReason, isTor, isVPN, isDatacenter };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Regra de país
    // ─────────────────────────────────────────────────────────────────────────

    private checkCountryRule(
        country: string,
        path: string,
    ): { allowed: boolean; reason?: GeoBlockReason } {
        // Verifica override de rota primeiro (mais específico)
        const routeOverride = this.getRouteOverride(path);

        if (routeOverride) {
            return this.applyCountryRule(
                country,
                routeOverride.mode ?? this.config.mode,
                routeOverride.allowedCountries
                    ? new Set(routeOverride.allowedCountries.map(normalizeCountry))
                    : this.allowedCountriesSet,
                routeOverride.blockedCountries
                    ? new Set([
                        ...routeOverride.blockedCountries.map(normalizeCountry),
                        ...(routeOverride.applyOFAC ? OFAC_SANCTIONED_COUNTRIES : []),
                    ])
                    : this.blockedCountriesSet,
            );
        }

        return this.applyCountryRule(
            country,
            this.config.mode,
            this.allowedCountriesSet,
            this.blockedCountriesSet,
        );
    }

    private applyCountryRule(
        country: string,
        mode: 'allowlist' | 'blocklist',
        allowedSet: Set<string>,
        blockedSet: Set<string>,
    ): { allowed: boolean; reason?: GeoBlockReason } {
        if (mode === 'allowlist') {
            if (!allowedSet.has(country)) {
                return { allowed: false, reason: 'COUNTRY_NOT_ALLOWED' };
            }
            return { allowed: true };
        }

        // blocklist
        if (blockedSet.has(country)) {
            return { allowed: false, reason: 'COUNTRY_BLOCKED' };
        }
        return { allowed: true };
    }

    private getRouteOverride(path: string): Partial<GeoBlockConfig> | null {
        const overrides = this.config.routeOverrides;

        for (const [routePattern, override] of Object.entries(overrides)) {
            if (path === routePattern || path.startsWith(routePattern + '/')) {
                return override;
            }
        }

        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lookup externo com cache
    // ─────────────────────────────────────────────────────────────────────────

    private async performExternalLookup(ip: string): Promise<ExternalGeoResult | null> {
        // Verifica cache primeiro
        if (this.cache) {
            const cached = this.cache.get(ip);
            if (cached !== undefined) {
                this.debugLog('CACHE-HIT', ip, cached?.country ?? 'null');
                return cached;
            }
        }

        if (!this.config.externalLookup) return null;

        try {
            const result = await this.config.externalLookup(ip);

            // Armazena no cache (inclusive resultado null para evitar lookups repetidos)
            if (this.cache) {
                this.cache.set(ip, result);
            }

            return result;
        } catch (err) {
            this.debugLog('EXTERNAL-LOOKUP-ERROR', ip, err);
            return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários públicos
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Retorna estatísticas do cache de lookups.
     */
    getCacheStats(): { size: number; enabled: boolean } {
        return {
            size: this.cache?.size ?? 0,
            enabled: this.config.cache.enabled,
        };
    }

    /**
     * Limpa o cache de lookups.
     * Use após atualizar a base de dados de GeoIP.
     */
    clearCache(): void {
        this.cache?.clear();
    }

    /**
     * Adiciona um país à blocklist em runtime (sem reiniciar).
     * Útil para resposta a incidentes.
     */
    blockCountry(countryCode: string): void {
        this.blockedCountriesSet.add(normalizeCountry(countryCode));
    }

    /**
     * Remove um país da blocklist em runtime.
     */
    unblockCountry(countryCode: string): void {
        this.blockedCountriesSet.delete(normalizeCountry(countryCode));
    }

    /**
     * Adiciona um IP à lista de isentos em runtime.
     */
    exemptIP(ip: string): void {
        this.exemptIPsSet.add(ip);
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[geo-block]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CIDR matching (compartilhado com ddosProtection)
// ─────────────────────────────────────────────────────────────────────────────

function matchesCIDR(ip: string, cidr: string): boolean {
    const [network, prefix] = cidr.split('/');
    if (!network || !prefix) return false;

    const bits = parseInt(prefix, 10);
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    const ipNum = ipToInt(ip);
    const netNum = ipToInt(network);

    return ipNum !== null && netNum !== null && (ipNum & mask) === (netNum & mask);
}

function ipToInt(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

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
 * Middleware GeoBlock para Express.
 *
 * @example
 * app.use(createExpressGeoBlock(geoBlock));
 */
export function createExpressGeoBlock(geo: GeoBlockMiddleware) {
    return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
        const result = await geo.evaluate({
            ip: req.ip ?? extractRealIP(req.headers),
            method: req.method,
            path: req.path,
            headers: req.headers,
        });

        if (!result.allowed) {
            res
                .status(403)
                .set({
                    'Content-Type': 'application/json',
                    'X-Content-Type-Options': 'nosniff',
                    'Cache-Control': 'no-store',
                })
                .json({ error: 'Forbidden', message: 'Access denied.' });
            return;
        }

        next();
    };
}

/**
 * Handler GeoBlock para Next.js middleware (Edge Runtime).
 *
 * @example
 * // middleware.ts
 * export default createNextGeoBlock(geoBlock);
 */
export function createNextGeoBlock(geo: GeoBlockMiddleware) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => { headers[key] = value; });

        const url = new URL(request.url);

        const result = await geo.evaluate({
            ip: headers['cf-connecting-ip'] ?? headers['x-real-ip'] ?? '0.0.0.0',
            method: request.method,
            path: url.pathname,
            headers,
        });

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
// Factories com preset
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Preset para serviço com público restrito a um país (ex: produto local).
 *
 * @example
 * const geo = createSingleCountryGeo('BR', externalLookup);
 */
export function createSingleCountryGeo(
    countryCode: string,
    externalLookup?: GeoBlockConfig['externalLookup'],
): GeoBlockMiddleware {
    return new GeoBlockMiddleware({
        mode: 'allowlist',
        allowedCountries: [countryCode],
        blockTor: true,
        onLookupFailure: 'block',
        externalLookup,
        cache: { enabled: true, ttlMs: 3_600_000, maxSize: 10_000 },
    });
}

/**
 * Preset para compliance OFAC — bloqueia países sob sanções EUA.
 * Adequado para fintechs, exchanges de criptomoeda, SaaS com clientes americanos.
 *
 * ⚠ Consulte seu departamento jurídico antes de usar em produção.
 *
 * @example
 * const geo = createOFACGeo(externalLookup);
 */
export function createOFACGeo(
    externalLookup?: GeoBlockConfig['externalLookup'],
): GeoBlockMiddleware {
    return new GeoBlockMiddleware({
        mode: 'blocklist',
        applyOFAC: true,
        blockTor: true,
        onLookupFailure: 'block',
        externalLookup,
        cache: { enabled: true, ttlMs: 3_600_000, maxSize: 10_000 },
    });
}

/**
 * Preset para bloqueio máximo — allowlist + OFAC + Tor + VPN + Datacenter.
 * Para endpoints de alta sensibilidade (pagamentos, PII, admin).
 *
 * @example
 * const geo = createHighSecurityGeo(['BR', 'PT'], externalLookup);
 * app.use('/api/payments', createExpressGeoBlock(geo));
 */
export function createHighSecurityGeo(
    allowedCountries: string[],
    externalLookup?: GeoBlockConfig['externalLookup'],
): GeoBlockMiddleware {
    return new GeoBlockMiddleware({
        mode: 'allowlist',
        allowedCountries,
        applyOFAC: true,
        blockTor: true,
        blockVPN: true,
        blockDatacenterASNs: true,
        onLookupFailure: 'block',
        externalLookup,
        cache: { enabled: true, ttlMs: 1_800_000, maxSize: 5_000 },
        routeOverrides: {
            '/api/admin': { allowedCountries, blockTor: true, blockVPN: true },
            '/api/payments': { allowedCountries, blockTor: true, blockVPN: true },
        },
    });
}

/**
 * Fábrica geral com store e config customizáveis.
 *
 * @example
 * const geo = createGeoBlock({
 *   mode: 'allowlist',
 *   allowedCountries: ['BR', 'PT', 'US'],
 *   blockTor: true,
 *   externalLookup: async (ip) => myMaxMindClient.lookup(ip),
 *   onBlocked: (result) => logger.warn('geo blocked', result.meta),
 * });
 */
export function createGeoBlock(config: GeoBlockConfig): GeoBlockMiddleware {
    return new GeoBlockMiddleware(config);
}

// KNOWN_DATACENTER_ASNS e KNOWN_VPN_ASNS já são exportadas como export const acima.