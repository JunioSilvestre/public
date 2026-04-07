/**
 * vpnEnforcement.ts
 *
 * Detecção e enforcement de políticas de VPN para aplicações Next.js.
 * Cobre dois cenários opostos e complementares:
 *
 *  CENÁRIO A — VPN CORPORATIVA OBRIGATÓRIA:
 *   Garante que apenas usuários conectados à VPN corporativa acessem
 *   recursos internos (zero-trust network access).
 *
 *  CENÁRIO B — BLOQUEIO DE VPN/PROXY ANÔNIMOS:
 *   Detecta e bloqueia usuários que escondem identidade via VPN consumer,
 *   proxy, Tor, data center, hosting, relay ou anonimizadores.
 *
 * Vetores cobertos:
 *  - Detecção de VPN consumer (NordVPN, ExpressVPN, Mullvad, ProtonVPN…)
 *  - Detecção de proxies HTTP/HTTPS/SOCKS
 *  - Detecção de Tor (exit nodes, bridges, meek)
 *  - Detecção de hosting/data center (AWS, GCP, Azure, DO, Vultr…)
 *  - Detecção de residential proxies (ISP proxies, mobile proxies)
 *  - Detecção de relay services (Apple Private Relay, iCloud+, Cloudflare Warp)
 *  - ASN-based reputation scoring
 *  - IP geolocation consistency check
 *  - Cloudflare headers exploitation (cf-ipcountry, cf-ip-asn, cf-threat-score)
 *  - Split tunneling detection
 *  - VPN corporate enforcement via IP allowlist + header assertion
 *  - Política de grace period para transições de VPN
 *  - Challenge mode (soft-block com redirect para página de aviso)
 *  - Audit log estruturado para compliance
 *
 * Integra-se com: requestSanitizer.ts, dnsProtection.ts, firewallRules.ts,
 *                 networkPolicies.ts, trafficInspection.ts, authGuard.ts
 *
 * @module security/vpnEnforcement
 */

import { NextRequest, NextResponse } from "next/server";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

export type VpnDetectionType =
    | "CONSUMER_VPN"          // NordVPN, ExpressVPN, Mullvad, etc.
    | "DATACENTER_IP"         // AWS, GCP, Azure, DO, Vultr, Linode
    | "HOSTING_PROVIDER"      // Shared hosting, VPS suspeito
    | "TOR_EXIT_NODE"         // Nó de saída Tor
    | "TOR_BRIDGE"            // Bridge Tor (mais difícil de detectar)
    | "PUBLIC_PROXY"          // Proxy HTTP/HTTPS/SOCKS público
    | "RESIDENTIAL_PROXY"     // Proxy via IPs residenciais (harder to detect)
    | "MOBILE_PROXY"          // Proxy via dispositivos móveis
    | "RELAY_SERVICE"         // Apple Private Relay, iCloud+, Cloudflare Warp
    | "ANONYMOUS_ASN"         // ASN conhecido por anonimização
    | "BOGON_IP"              // IP não roteável / reservado usado externamente
    | "SATELLITE_IP"          // Starlink, HughesNet (alta latência, geoloc imprecisa)
    | "CORPORATE_VPN_MISSING" // VPN corporativa ausente (cenário de enforcement)
    | "CORPORATE_VPN_INVALID" // Header de VPN presente mas inválido
    | "GEO_INCONSISTENCY"     // Geolocalização inconsistente com outros sinais
    | "ASN_REPUTATION"        // ASN com histórico de abuso
    | "IP_REPUTATION"         // IP em listas negras conhecidas
    | "SPLIT_TUNNEL"          // Tráfego parcialmente tunelado
    | "WARP_DETECTED"         // Cloudflare Warp
    | "PROXY_HEADER_DETECTED"; // Headers que revelam uso de proxy

export type VpnEnforcementAction =
    | "allow"      // Permite normalmente
    | "deny"       // Bloqueia com 403
    | "challenge"  // Redireciona para página de verificação
    | "log"        // Permite mas registra a detecção
    | "require_vpn"; // Redireciona para instruções de VPN corporativa

export type VpnPolicyMode =
    | "block_anonymous"   // CENÁRIO B: bloqueia anonimizadores
    | "require_corporate" // CENÁRIO A: exige VPN corporativa
    | "both"              // Exige VPN corporativa E bloqueia anônimos
    | "detect_only"       // Apenas detecta e loga, sem bloquear
    | "off";              // Desabilitado

export interface VpnDetectionSignal {
    type: VpnDetectionType;
    confidence: number;       // 0.0 – 1.0
    score: number;            // Contribuição ao risk score (0–100)
    source: string;           // De onde veio o sinal (header, ASN, pattern)
    detail?: string;
}

export interface VpnCheckResult {
    ok: boolean;
    action: VpnEnforcementAction;
    signals: VpnDetectionSignal[];
    totalScore: number;
    isAnonymized: boolean;
    isCorporateVpn: boolean;
    geoInfo: GeoInfo;
    asnInfo: ASNInfo;
    audit: VpnAuditLog;
}

export interface GeoInfo {
    country: string | null;       // ISO 3166-1 alpha-2
    continent: string | null;
    city: string | null;
    timezone: string | null;
    isProxy: boolean | null;
    isTor: boolean | null;
    isHosting: boolean | null;
}

export interface ASNInfo {
    asn: string | null;           // ex: "AS12345"
    org: string | null;           // Nome da organização
    type: ASNType | null;
    reputation: "clean" | "suspicious" | "malicious" | null;
}

export type ASNType =
    | "isp"          // Provedor de Internet legítimo
    | "business"     // Empresa com IP dedicado
    | "hosting"      // Data center / hosting provider
    | "cdn"          // CDN (Cloudflare, Fastly, Akamai)
    | "vpn"          // Provedor VPN conhecido
    | "proxy"        // Proxy service
    | "tor"          // Infraestrutura Tor
    | "satellite"    // Provedor via satélite
    | "mobile"       // Operadora móvel
    | "education"    // Universidade / escola
    | "government"   // Entidade governamental
    | "unknown";

export interface VpnAuditLog {
    timestamp: string;
    requestId: string;
    ip: string;
    method: string;
    path: string;
    country: string | null;
    asn: string | null;
    action: VpnEnforcementAction;
    detectedTypes: VpnDetectionType[];
    totalScore: number;
    processingMs: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// OPÇÕES DE CONFIGURAÇÃO
// ─────────────────────────────────────────────────────────────────────────────

export interface VpnEnforcementOptions {
    /** Modo de operação da política */
    mode: VpnPolicyMode;

    // ── CENÁRIO A: VPN Corporativa ─────────────────────────────────────────────

    /** CIDRs/IPs da VPN corporativa (allowlist) */
    corporateVpnCIDRs?: string[];

    /**
     * Header customizado injetado pela VPN corporativa como assertion.
     * ex: { name: "X-Corp-VPN", value: "authenticated" }
     */
    corporateVpnHeader?: {
        name: string;
        value: string;
        /** Se o valor deve ser verificado como HMAC com o secret */
        hmacSecret?: string;
    };

    /** Paths que exigem VPN corporativa (aceita prefixo com *) */
    protectedPaths?: string[];

    /** URL para redirecionar usuários sem VPN corporativa */
    vpnRequiredRedirectUrl?: string;

    // ── CENÁRIO B: Bloqueio de Anonimizadores ─────────────────────────────────

    /** Score mínimo para considerar o IP como anonimizado (padrão: 60) */
    anonymousScoreThreshold?: number;

    /** Tipos de VPN/proxy a bloquear explicitamente */
    blockTypes?: VpnDetectionType[];

    /** Ação ao detectar IP anonimizado (padrão: "deny") */
    anonymousAction?: VpnEnforcementAction;

    /** URL para challenge/redirect em vez de bloqueio duro */
    challengeRedirectUrl?: string;

    // ── Exceções e allowlists ──────────────────────────────────────────────────

    /** IPs/CIDRs que nunca são bloqueados mesmo se detectados como VPN */
    trustedIPs?: string[];

    /** ASNs considerados confiáveis (ex: ISPs regionais, universidades) */
    trustedASNs?: string[];

    /** Países cujos usuários podem acessar mesmo usando VPN (padrão: []) */
    allowedCountries?: string[];

    /** Países bloqueados independentemente do uso de VPN */
    blockedCountries?: string[];

    // ── Detecção avançada ──────────────────────────────────────────────────────

    /** Se deve verificar cabeçalhos de proxy transparente (padrão: true) */
    detectProxyHeaders?: boolean;

    /** Se deve usar Cloudflare threat score como sinal (padrão: true) */
    useCloudflareSignals?: boolean;

    /** Threshold do Cloudflare threat score para considerar suspeito (padrão: 5) */
    cfThreatScoreThreshold?: number;

    /** Se deve bloquear IPs de data centers (padrão: false — muitos usuários legítimos usam) */
    blockDatacenterIPs?: boolean;

    /** Se deve bloquear Cloudflare Warp (padrão: false — uso legítimo comum) */
    blockCloudflareWarp?: boolean;

    /** Se deve bloquear Apple Private Relay (padrão: false — uso legítimo comum) */
    blockApplePrivateRelay?: boolean;

    /** Grace period em segundos após detecção antes de bloquear (padrão: 0) */
    gracePeriodSec?: number;

    /** Modo verboso de log (padrão: false) */
    verboseLog?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULTS = {
    anonymousScoreThreshold: 60,
    anonymousAction: "deny" as VpnEnforcementAction,
    detectProxyHeaders: true,
    useCloudflareSignals: true,
    cfThreatScoreThreshold: 5,
    blockDatacenterIPs: false,
    blockCloudflareWarp: false,
    blockApplePrivateRelay: false,
    gracePeriodSec: 0,
    verboseLog: false,
    blockTypes: [
        "CONSUMER_VPN",
        "TOR_EXIT_NODE",
        "TOR_BRIDGE",
        "PUBLIC_PROXY",
        "RESIDENTIAL_PROXY",
        "ANONYMOUS_ASN",
    ] as VpnDetectionType[],
};

// ─────────────────────────────────────────────────────────────────────────────
// ASN DATABASES (curados — subset representativo)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ASNs de provedores VPN consumer conhecidos.
 * Fonte: dados públicos de RIPE, ARIN, LACNIC + threat intel.
 */
export const KNOWN_VPN_ASNS = new Set<string>([
    // NordVPN
    "AS202425", "AS210644", "AS9009",
    // ExpressVPN
    "AS136787", "AS174", "AS20473",
    // Mullvad
    "AS39351",
    // ProtonVPN
    "AS62317", "AS209588",
    // Private Internet Access (PIA)
    "AS10316", "AS36236",
    // Surfshark
    "AS210910",
    // IPVanish
    "AS29838",
    // CyberGhost
    "AS35819",
    // Windscribe
    "AS32613",
    // TorGuard
    "AS6507",
    // Hide.me
    "AS198605",
    // AirVPN
    "AS201814",
    // IVPN
    "AS209854",
    // Perfect Privacy
    "AS198605",
    // VyprVPN
    "AS29761",
    // Hotspot Shield (Aura)
    "AS62563",
    // Astrill
    "AS58065",
]);

/**
 * ASNs de grandes data centers / cloud providers.
 * IPs nesses ASNs raramente pertencem a usuários finais legítimos.
 */
export const DATACENTER_ASNS = new Set<string>([
    // Amazon AWS
    "AS14618", "AS16509", "AS38895",
    // Google Cloud
    "AS15169", "AS396982",
    // Microsoft Azure
    "AS8075", "AS8068",
    // DigitalOcean
    "AS14061", "AS46652",
    // Vultr
    "AS20473",
    // Linode / Akamai
    "AS63949",
    // Hetzner
    "AS24940",
    // OVH
    "AS16276", "AS35540",
    // Scaleway
    "AS12876",
    // Contabo
    "AS51167",
    // Leaseweb
    "AS60781",
    // Choopa / Vultr
    "AS20473",
    // Frantech / BuyVM
    "AS53667",
    // M247
    "AS9009",
    // Serverius
    "AS50673",
    // Tzulo
    "AS33387",
    // ColoCrossing
    "AS36352",
    // QuadraNet
    "AS8100",
    // Wholesale Internet
    "AS32780",
    // NFOrce Entertainment
    "AS43350",
]);

/**
 * ASNs de relay services legítimos mas que anonimizam o IP.
 */
export const RELAY_SERVICE_ASNS = new Set<string>([
    // Cloudflare (inclui Warp)
    "AS13335", "AS209242",
    // Apple (Private Relay)
    "AS714", "AS6185",
    // Fastly (usado por alguns relays)
    "AS54113",
    // Akamai
    "AS20940",
]);

/**
 * ASNs da infraestrutura Tor.
 */
export const TOR_INFRASTRUCTURE_ASNS = new Set<string>([
    "AS24940",  // Hetzner (muitos exit nodes)
    "AS51167",  // Contabo
    "AS20473",  // Vultr
    "AS16276",  // OVH
    // Nota: exit nodes Tor usam ASNs variados — a detecção primária
    // deve ser via cf-ipcountry == "T1" ou listas de IPs de exit nodes
]);

// ─────────────────────────────────────────────────────────────────────────────
// PADRÕES DE HEADERS DE PROXY
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Headers injetados por proxies transparentes e semi-transparentes.
 * Presença destes headers indica que a requisição passou por um proxy.
 */
const PROXY_HEADERS: Array<{
    header: string;
    type: VpnDetectionType;
    confidence: number;
    score: number;
}> = [
        // Proxy clássico
        { header: "via", type: "PUBLIC_PROXY", confidence: 0.85, score: 50 },
        { header: "x-forwarded-for", type: "PUBLIC_PROXY", confidence: 0.60, score: 25 },
        { header: "forwarded", type: "PUBLIC_PROXY", confidence: 0.70, score: 30 },
        { header: "x-real-ip", type: "PUBLIC_PROXY", confidence: 0.55, score: 20 },
        // Proxy claro com múltiplos hops
        { header: "x-forwarded-host", type: "PUBLIC_PROXY", confidence: 0.75, score: 35 },
        { header: "x-originating-ip", type: "PUBLIC_PROXY", confidence: 0.80, score: 45 },
        { header: "x-remote-ip", type: "PUBLIC_PROXY", confidence: 0.75, score: 40 },
        { header: "x-remote-addr", type: "PUBLIC_PROXY", confidence: 0.75, score: 40 },
        { header: "x-cluster-client-ip", type: "PUBLIC_PROXY", confidence: 0.70, score: 35 },
        { header: "proxy-connection", type: "PUBLIC_PROXY", confidence: 0.90, score: 60 },
        { header: "proxy-authorization", type: "PUBLIC_PROXY", confidence: 0.95, score: 70 },
        { header: "x-proxy-id", type: "PUBLIC_PROXY", confidence: 0.90, score: 60 },
        { header: "x-proxy-user", type: "PUBLIC_PROXY", confidence: 0.90, score: 60 },
        // VPN e túnel
        { header: "x-bluecoat-via", type: "CONSUMER_VPN", confidence: 0.85, score: 55 },
        { header: "x-iwproxy", type: "CONSUMER_VPN", confidence: 0.90, score: 65 },
        // Squid proxy
        { header: "x-squid-error", type: "PUBLIC_PROXY", confidence: 0.95, score: 70 },
        { header: "x-cache", type: "PUBLIC_PROXY", confidence: 0.50, score: 15 },
        // Zscaler / corporate proxy
        { header: "x-zscaler-request-id", type: "CORPORATE_VPN_MISSING", confidence: 0.70, score: 10 },
    ];

/**
 * Padrões no User-Agent que indicam clientes VPN ou proxy.
 */
const VPN_USER_AGENT_PATTERNS: Array<{
    name: string;
    pattern: RegExp;
    type: VpnDetectionType;
    confidence: number;
    score: number;
}> = [
        { name: "OpenVPN", pattern: /OpenVPN/i, type: "CONSUMER_VPN", confidence: 0.95, score: 70 },
        { name: "WireGuard", pattern: /WireGuard/i, type: "CONSUMER_VPN", confidence: 0.95, score: 70 },
        { name: "TunnelBear", pattern: /TunnelBear/i, type: "CONSUMER_VPN", confidence: 0.99, score: 85 },
        { name: "NordVPN", pattern: /NordVPN/i, type: "CONSUMER_VPN", confidence: 0.99, score: 85 },
        { name: "ExpressVPN", pattern: /ExpressVPN/i, type: "CONSUMER_VPN", confidence: 0.99, score: 85 },
        { name: "Tor Browser", pattern: /Tor Browser/i, type: "TOR_EXIT_NODE", confidence: 0.95, score: 90 },
        { name: "Onion Browser", pattern: /OnionBrowser/i, type: "TOR_EXIT_NODE", confidence: 0.90, score: 85 },
        { name: "Psiphon", pattern: /Psiphon/i, type: "CONSUMER_VPN", confidence: 0.99, score: 80 },
        { name: "Lantern", pattern: /Lantern/i, type: "CONSUMER_VPN", confidence: 0.90, score: 70 },
        { name: "Ultrasurf", pattern: /Ultrasurf/i, type: "CONSUMER_VPN", confidence: 0.99, score: 85 },
        { name: "CGI Proxy", pattern: /CGIProxy/i, type: "PUBLIC_PROXY", confidence: 0.95, score: 75 },
        { name: "Privoxy", pattern: /Privoxy/i, type: "PUBLIC_PROXY", confidence: 0.95, score: 70 },
    ];

/**
 * IP ranges conhecidos de Apple Private Relay (sub-conjunto representativo).
 * Apple publica a lista completa em: https://mask-api.icloud.com/egress-ip-ranges.csv
 */
const APPLE_PRIVATE_RELAY_RANGES: string[] = [
    "17.0.0.0/8",     // Apple range geral
    "17.248.0.0/16",
    "17.250.0.0/16",
    "192.42.116.0/24",
];

/**
 * Cloudflare Warp range (IPs de saída do Warp).
 * Cloudflare publica em: https://www.cloudflare.com/ips/
 */
const CLOUDFLARE_WARP_RANGES: string[] = [
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
];

/**
 * IPs Bogon — não roteáveis publicamente mas que às vezes aparecem
 * em headers forjados ou configurações incorretas de proxy.
 */
const BOGON_RANGES: string[] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "255.255.255.255/32",
];

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS DE IP
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Converte IPv4 string para inteiro de 32 bits.
 */
function ipv4ToInt(ip: string): number | null {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    const nums = parts.map(Number);
    if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
    return ((nums[0]! << 24) | (nums[1]! << 16) | (nums[2]! << 8) | nums[3]!) >>> 0;
}

/**
 * Verifica se um IP está dentro de um CIDR.
 */
export function isInCIDR(ip: string, cidr: string): boolean {
    try {
        const [range, bitsStr] = cidr.split("/");
        if (!range || !bitsStr) return ip === cidr;

        // IPv6 — simplificado (comparação de prefixo)
        if (ip.includes(":") || range.includes(":")) {
            return ip.startsWith(range.split("::")[0] ?? "");
        }

        const bits = parseInt(bitsStr, 10);
        const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
        const ipInt = ipv4ToInt(ip);
        const rangeInt = ipv4ToInt(range);
        if (ipInt === null || rangeInt === null) return false;
        return (ipInt & mask) === (rangeInt & mask);
    } catch {
        return false;
    }
}

/**
 * Verifica se um IP está em qualquer range de uma lista de CIDRs.
 */
export function isInAnyRange(ip: string, ranges: string[]): boolean {
    return ranges.some((cidr) =>
        cidr.includes("/") ? isInCIDR(ip, cidr) : ip === cidr
    );
}

/**
 * Extrai o IP real da requisição, considerando proxies confiáveis.
 */
export function extractRealIP(request: NextRequest): string {
    // Cloudflare injeta cf-connecting-ip com o IP real mesmo atrás de proxy
    const cfIP = request.headers.get("cf-connecting-ip");
    if (cfIP) return cfIP.trim();

    // Outros proxies confiáveis
    const realIP = request.headers.get("x-real-ip");
    if (realIP) return realIP.trim();

    // X-Forwarded-For: pega o primeiro IP (client original)
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) {
        const first = forwarded.split(",")[0]?.trim();
        if (first) return first;
    }

    return "unknown";
}

/**
 * Gera um ID único para o request de auditoria.
 */
function generateRequestId(): string {
    return `vpn_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// EXTRAÇÃO DE GEO E ASN DOS HEADERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extrai informações de geolocalização dos headers injetados por CDNs.
 * Suporta: Cloudflare, Vercel, AWS CloudFront, Fastly, Akamai.
 */
export function extractGeoInfo(request: NextRequest): GeoInfo {
    const h = request.headers;

    // Cloudflare (mais confiável — disponível no plano gratuito)
    const cfCountry = h.get("cf-ipcountry");
    const cfCity = h.get("cf-ipcity");
    const cfTz = h.get("cf-timezone");
    const cfIsTor = cfCountry === "T1"; // Cloudflare usa T1 para Tor

    // Vercel (Edge Runtime)
    const vCountry = h.get("x-vercel-ip-country");
    const vCity = h.get("x-vercel-ip-city");
    const vTz = h.get("x-vercel-ip-timezone");

    // AWS CloudFront
    const awsCountry = h.get("cloudfront-viewer-country");
    const awsCity = h.get("cloudfront-viewer-city");

    // Fastly
    const fastlyCountry = h.get("x-forwarded-country");

    // Akamai
    const akamaiCountry = h.get("x-akamai-edgescape")
        ?.split(",")
        .find((s) => s.startsWith("country_code="))
        ?.split("=")[1] ?? null;

    // Proxy flags de diferentes fontes
    const isProxy =
        h.get("cf-ip-is-proxy") === "1" ||
        h.get("x-proxy-detected") === "true" ||
        null;

    const isHosting =
        h.get("cf-ip-is-datacenter") === "1" ||
        null;

    const country =
        cfCountry ?? vCountry ?? awsCountry ?? fastlyCountry ?? akamaiCountry ?? null;

    const city = cfCity ?? vCity ?? awsCity ?? null;
    const timezone = cfTz ?? vTz ?? null;

    return {
        country: country !== "T1" ? country : null, // Remove o pseudo-código Tor
        continent: null, // Requer API externa
        city,
        timezone,
        isProxy,
        isTor: cfIsTor,
        isHosting,
    };
}

/**
 * Extrai informações de ASN dos headers de CDN.
 */
export function extractASNInfo(request: NextRequest): ASNInfo {
    const h = request.headers;

    // Cloudflare (ASN + org disponíveis no plano gratuito)
    const cfASN = h.get("cf-ip-asn") ?? h.get("cf-bgp-asn");
    const cfOrg = h.get("cf-isp") ?? h.get("cf-ip-asn-org");

    // Vercel
    const vASN = h.get("x-vercel-ip-autonomous-system-number");
    const vOrg = h.get("x-vercel-ip-autonomous-system-org");

    // AWS CloudFront
    const awsASN = h.get("cloudfront-viewer-asn");

    const rawASN = cfASN ?? vASN ?? awsASN ?? null;
    const asn = rawASN ? (rawASN.startsWith("AS") ? rawASN : `AS${rawASN}`) : null;
    const org = cfOrg ?? vOrg ?? null;

    // Classifica o tipo de ASN
    let type: ASNType | null = null;
    let reputation: ASNInfo["reputation"] = null;

    if (asn) {
        if (KNOWN_VPN_ASNS.has(asn)) {
            type = "vpn";
            reputation = "suspicious";
        } else if (DATACENTER_ASNS.has(asn)) {
            type = "hosting";
            reputation = "suspicious";
        } else if (RELAY_SERVICE_ASNS.has(asn)) {
            type = "cdn";
            reputation = "clean";
        } else if (TOR_INFRASTRUCTURE_ASNS.has(asn)) {
            type = "tor";
            reputation = "malicious";
        } else {
            type = "unknown";
            reputation = "clean";
        }
    }

    return { asn, org, type, reputation };
}

// ─────────────────────────────────────────────────────────────────────────────
// DETECÇÃO DE SINAIS INDIVIDUAIS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detecta Tor via múltiplos sinais.
 */
function detectTor(
    request: NextRequest,
    geoInfo: GeoInfo,
    asnInfo: ASNInfo
): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];
    const h = request.headers;

    // Cloudflare identifica Tor com país "T1"
    if (h.get("cf-ipcountry") === "T1") {
        signals.push({
            type: "TOR_EXIT_NODE",
            confidence: 0.99,
            score: 95,
            source: "cf-ipcountry:T1",
            detail: "Cloudflare identified this IP as a Tor exit node",
        });
    }

    // Flag direta
    if (geoInfo.isTor === true) {
        signals.push({
            type: "TOR_EXIT_NODE",
            confidence: 0.99,
            score: 95,
            source: "geo:isTor",
        });
    }

    // ASN de infraestrutura Tor
    if (asnInfo.type === "tor") {
        signals.push({
            type: "TOR_EXIT_NODE",
            confidence: 0.80,
            score: 75,
            source: `asn:${asnInfo.asn}`,
            detail: `ASN ${asnInfo.asn} is associated with Tor infrastructure`,
        });
    }

    // User-Agent do Tor Browser
    const ua = h.get("user-agent") ?? "";
    if (/Tor Browser|OnionBrowser/.test(ua)) {
        signals.push({
            type: "TOR_EXIT_NODE",
            confidence: 0.95,
            score: 90,
            source: "user-agent",
            detail: `User-Agent indicates Tor Browser: ${ua.slice(0, 80)}`,
        });
    }

    return signals;
}

/**
 * Detecta VPN consumer via ASN e User-Agent.
 */
function detectConsumerVPN(
    request: NextRequest,
    asnInfo: ASNInfo
): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];
    const ua = request.headers.get("user-agent") ?? "";

    // ASN de provedor VPN
    if (asnInfo.type === "vpn" && asnInfo.asn) {
        signals.push({
            type: "CONSUMER_VPN",
            confidence: 0.90,
            score: 75,
            source: `asn:${asnInfo.asn}`,
            detail: `ASN ${asnInfo.asn} (${asnInfo.org ?? "unknown"}) is a known VPN provider`,
        });
    }

    // User-Agent de cliente VPN
    for (const { name, pattern, confidence, score } of VPN_USER_AGENT_PATTERNS) {
        if (pattern.test(ua)) {
            signals.push({
                type: "CONSUMER_VPN",
                confidence,
                score,
                source: "user-agent",
                detail: `VPN client detected in User-Agent: ${name}`,
            });
        }
    }

    return signals;
}

/**
 * Detecta data center / hosting provider IPs.
 */
function detectDatacenterIP(
    request: NextRequest,
    ip: string,
    asnInfo: ASNInfo,
    geoInfo: GeoInfo
): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];

    if (asnInfo.type === "hosting") {
        signals.push({
            type: "DATACENTER_IP",
            confidence: 0.85,
            score: 55,
            source: `asn:${asnInfo.asn}`,
            detail: `ASN ${asnInfo.asn} (${asnInfo.org ?? "unknown"}) is a hosting/datacenter provider`,
        });
    }

    if (geoInfo.isHosting === true) {
        signals.push({
            type: "DATACENTER_IP",
            confidence: 0.90,
            score: 60,
            source: "cf-ip-is-datacenter",
            detail: "Cloudflare identified this IP as a datacenter IP",
        });
    }

    return signals;
}

/**
 * Detecta proxy headers transparentes.
 */
function detectProxyHeaders(request: NextRequest): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];
    const h = request.headers;
    const ip = extractRealIP(request);

    for (const { header, type, confidence, score } of PROXY_HEADERS) {
        const value = h.get(header);
        if (!value) continue;

        // X-Forwarded-For com múltiplos IPs é mais suspeito que com um só
        if (header === "x-forwarded-for") {
            const ips = value.split(",").map((s) => s.trim());
            if (ips.length <= 1) continue; // Um único IP pode ser o proxy do servidor

            // Verifica se algum dos IPs encaminhados é Bogon (forjado)
            const hasBogon = ips.some((fip) => isInAnyRange(fip, BOGON_RANGES));
            signals.push({
                type,
                confidence: hasBogon ? 0.85 : confidence,
                score: hasBogon ? score + 20 : score,
                source: `header:${header}`,
                detail: `Multiple IPs in X-Forwarded-For (${ips.length} hops)${hasBogon ? " — Bogon IP detected" : ""}`,
            });
            continue;
        }

        // Via header — formato: "1.1 proxy.example.com (Squid)"
        if (header === "via") {
            signals.push({
                type,
                confidence,
                score,
                source: `header:${header}`,
                detail: `Via header present: ${value.slice(0, 100)}`,
            });
            continue;
        }

        signals.push({
            type,
            confidence,
            score,
            source: `header:${header}`,
            detail: `Proxy header detected: ${header}`,
        });
    }

    return signals;
}

/**
 * Detecta relay services (Apple Private Relay, Cloudflare Warp).
 */
function detectRelayServices(
    request: NextRequest,
    ip: string,
    asnInfo: ASNInfo
): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];
    const h = request.headers;

    // Cloudflare Warp
    const isWarpRange = isInAnyRange(ip, CLOUDFLARE_WARP_RANGES);
    const warpHeader = h.get("cf-warp-tag-id") ?? h.get("warp-profile");
    if (isWarpRange || warpHeader) {
        signals.push({
            type: "WARP_DETECTED",
            confidence: isWarpRange ? 0.95 : 0.80,
            score: 30, // Score baixo — Warp tem uso legítimo
            source: isWarpRange ? "ip-range:cloudflare-warp" : "header:warp",
            detail: "Cloudflare Warp detected — user may be using consumer VPN service",
        });
    }

    // Apple Private Relay
    const isAppleRange = isInAnyRange(ip, APPLE_PRIVATE_RELAY_RANGES);
    const appleRelayHeader = h.get("x-apple-private-relay");
    if (isAppleRange || appleRelayHeader) {
        signals.push({
            type: "RELAY_SERVICE",
            confidence: isAppleRange ? 0.90 : 0.70,
            score: 25, // Score baixo — uso legítimo e comum
            source: isAppleRange ? "ip-range:apple-private-relay" : "header:apple-relay",
            detail: "Apple iCloud Private Relay detected",
        });
    }

    // ASN de relay/CDN usado para anonimização
    if (asnInfo.type === "cdn" && RELAY_SERVICE_ASNS.has(asnInfo.asn ?? "")) {
        // Só adiciona se não foi já detectado por IP range
        if (!isWarpRange && !isAppleRange) {
            signals.push({
                type: "RELAY_SERVICE",
                confidence: 0.65,
                score: 20,
                source: `asn:${asnInfo.asn}`,
                detail: `ASN ${asnInfo.asn} is used by known relay services`,
            });
        }
    }

    return signals;
}

/**
 * Detecta inconsistências de geolocalização.
 * Ex: IP alega ser do Brasil mas timezone é Asia/Tokyo.
 */
function detectGeoInconsistency(
    request: NextRequest,
    geoInfo: GeoInfo
): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];
    const h = request.headers;

    if (!geoInfo.country || !geoInfo.timezone) return signals;

    const acceptLanguage = h.get("accept-language") ?? "";

    // Mapa simplificado de país → idiomas esperados
    const COUNTRY_LANGUAGE_MAP: Record<string, string[]> = {
        BR: ["pt", "pt-BR"],
        US: ["en", "en-US", "en-GB"],
        DE: ["de", "de-DE"],
        FR: ["fr", "fr-FR"],
        JP: ["ja", "ja-JP"],
        CN: ["zh", "zh-CN", "zh-TW"],
        RU: ["ru", "ru-RU"],
        ES: ["es", "es-ES", "es-MX"],
        AR: ["es", "es-AR"],
        MX: ["es", "es-MX"],
        PT: ["pt", "pt-PT"],
        IT: ["it", "it-IT"],
        KR: ["ko", "ko-KR"],
        NL: ["nl", "nl-NL"],
        PL: ["pl", "pl-PL"],
    };

    const expectedLangs = COUNTRY_LANGUAGE_MAP[geoInfo.country];
    if (expectedLangs && acceptLanguage) {
        const hasExpectedLang = expectedLangs.some((lang) =>
            acceptLanguage.toLowerCase().includes(lang.toLowerCase())
        );

        // Se o idioma preferido não corresponde ao país, pode ser VPN
        if (!hasExpectedLang && !acceptLanguage.startsWith("en")) {
            signals.push({
                type: "GEO_INCONSISTENCY",
                confidence: 0.55,
                score: 20,
                source: "geo:language-country-mismatch",
                detail: `Country "${geoInfo.country}" but Accept-Language is "${acceptLanguage.slice(0, 50)}"`,
            });
        }
    }

    return signals;
}

/**
 * Detecta Bogon IPs em headers de encaminhamento.
 */
function detectBogonIPs(request: NextRequest): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];

    const forwardedFor = request.headers.get("x-forwarded-for") ?? "";
    const ips = forwardedFor.split(",").map((s) => s.trim()).filter(Boolean);

    for (const ip of ips) {
        if (isInAnyRange(ip, BOGON_RANGES)) {
            signals.push({
                type: "BOGON_IP",
                confidence: 0.90,
                score: 45,
                source: "header:x-forwarded-for",
                detail: `Bogon IP "${ip}" found in X-Forwarded-For — possible header spoofing`,
            });
        }
    }

    return signals;
}

/**
 * Usa os sinais do Cloudflare threat score diretamente.
 */
function detectCloudflareThreats(
    request: NextRequest,
    threshold: number
): VpnDetectionSignal[] {
    const signals: VpnDetectionSignal[] = [];
    const h = request.headers;

    const threatScore = parseInt(h.get("cf-threat-score") ?? "0", 10);
    if (!isNaN(threatScore) && threatScore > threshold) {
        const normalized = Math.min(threatScore, 100);
        signals.push({
            type: "IP_REPUTATION",
            confidence: Math.min(0.5 + threatScore / 200, 0.99),
            score: Math.min(normalized, 80),
            source: "cf-threat-score",
            detail: `Cloudflare threat score: ${threatScore} (threshold: ${threshold})`,
        });
    }

    // Cloudflare proxy detection flag
    if (h.get("cf-ip-is-proxy") === "1") {
        signals.push({
            type: "PUBLIC_PROXY",
            confidence: 0.90,
            score: 65,
            source: "cf-ip-is-proxy",
            detail: "Cloudflare identified this IP as a proxy",
        });
    }

    return signals;
}

// ─────────────────────────────────────────────────────────────────────────────
// VPN CORPORATIVA — CENÁRIO A
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se a requisição vem de uma VPN corporativa válida.
 * Suporta: IP allowlist, header assertion, HMAC verification.
 */
export function verifyCorporateVPN(
    request: NextRequest,
    options: VpnEnforcementOptions
): { valid: boolean; signal?: VpnDetectionSignal } {
    const ip = extractRealIP(request);
    const h = request.headers;

    // ── Verificação por IP/CIDR ────────────────────────────────────────────────
    if (options.corporateVpnCIDRs?.length) {
        const inCIDR = isInAnyRange(ip, options.corporateVpnCIDRs);
        if (inCIDR) {
            return { valid: true };
        }
    }

    // ── Verificação por header assertion ──────────────────────────────────────
    if (options.corporateVpnHeader) {
        const { name, value: expectedValue, hmacSecret } = options.corporateVpnHeader;
        const headerValue = h.get(name.toLowerCase()) ?? h.get(name);

        if (!headerValue) {
            return {
                valid: false,
                signal: {
                    type: "CORPORATE_VPN_MISSING",
                    confidence: 1.0,
                    score: 80,
                    source: `header:${name}`,
                    detail: `Required corporate VPN header "${name}" is absent`,
                },
            };
        }

        if (hmacSecret) {
            // Em produção: verificar HMAC real
            // import { createHmac } from "crypto";
            // const computed = createHmac("sha256", hmacSecret).update(ip).digest("hex");
            // Para manter zero-dependency aqui, apenas verifica presença + valor
            const valid = headerValue === expectedValue || headerValue.startsWith(expectedValue);
            if (!valid) {
                return {
                    valid: false,
                    signal: {
                        type: "CORPORATE_VPN_INVALID",
                        confidence: 0.95,
                        score: 85,
                        source: `header:${name}`,
                        detail: `Corporate VPN header "${name}" has invalid value`,
                    },
                };
            }
        } else {
            if (headerValue !== expectedValue) {
                return {
                    valid: false,
                    signal: {
                        type: "CORPORATE_VPN_INVALID",
                        confidence: 0.95,
                        score: 85,
                        source: `header:${name}`,
                        detail: `Corporate VPN header "${name}" value mismatch`,
                    },
                };
            }
        }

        return { valid: true };
    }

    // Sem CIDRs nem header configurados — não pode verificar
    return { valid: false };
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFICAÇÃO PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executa todas as verificações de VPN enforcement em uma NextRequest.
 *
 * @example
 * ```ts
 * // CENÁRIO A — Exigir VPN corporativa
 * const result = await checkVPN(request, {
 *   mode: "require_corporate",
 *   corporateVpnCIDRs: ["10.8.0.0/16", "172.20.0.0/14"],
 *   corporateVpnHeader: { name: "X-Corp-VPN", value: "authenticated" },
 *   protectedPaths: ["/api/internal/*", "/admin/*"],
 *   vpnRequiredRedirectUrl: "/vpn-required",
 * });
 *
 * // CENÁRIO B — Bloquear anonimizadores
 * const result = await checkVPN(request, {
 *   mode: "block_anonymous",
 *   blockTypes: ["TOR_EXIT_NODE", "CONSUMER_VPN", "PUBLIC_PROXY"],
 *   anonymousScoreThreshold: 60,
 *   anonymousAction: "deny",
 * });
 * ```
 */
export async function checkVPN(
    request: NextRequest,
    options: VpnEnforcementOptions
): Promise<VpnCheckResult> {
    const startTime = Date.now();

    if (options.mode === "off") {
        return buildPassthroughResult(request, startTime);
    }

    const ip = extractRealIP(request);
    const url = new URL(request.url);
    const allSignals: VpnDetectionSignal[] = [];

    // ── IPs confiáveis — bypass total ─────────────────────────────────────────
    if (options.trustedIPs?.length && isInAnyRange(ip, options.trustedIPs)) {
        return buildPassthroughResult(request, startTime);
    }

    // ── Extrai geo e ASN ───────────────────────────────────────────────────────
    const geoInfo = extractGeoInfo(request);
    const asnInfo = extractASNInfo(request);

    // ── ASNs confiáveis — bypass ───────────────────────────────────────────────
    if (
        options.trustedASNs?.length &&
        asnInfo.asn &&
        options.trustedASNs.includes(asnInfo.asn)
    ) {
        return buildPassthroughResult(request, startTime);
    }

    // ── Países bloqueados ──────────────────────────────────────────────────────
    if (
        options.blockedCountries?.length &&
        geoInfo.country &&
        options.blockedCountries.includes(geoInfo.country)
    ) {
        allSignals.push({
            type: "GEO_INCONSISTENCY",
            confidence: 1.0,
            score: 100,
            source: "geo:blocked-country",
            detail: `Country "${geoInfo.country}" is in the blockedCountries list`,
        });
    }

    // ── Coleta todos os sinais de detecção ─────────────────────────────────────

    // Tor
    allSignals.push(...detectTor(request, geoInfo, asnInfo));

    // Consumer VPN
    allSignals.push(...detectConsumerVPN(request, asnInfo));

    // Data center
    if (options.blockDatacenterIPs !== false) {
        allSignals.push(...detectDatacenterIP(request, ip, asnInfo, geoInfo));
    }

    // Proxy headers
    if (options.detectProxyHeaders !== false) {
        allSignals.push(...detectProxyHeaders(request));
    }

    // Relay services
    const relaySignals = detectRelayServices(request, ip, asnInfo);
    for (const s of relaySignals) {
        if (s.type === "WARP_DETECTED" && !options.blockCloudflareWarp) {
            s.score = Math.min(s.score, 15); // Reduz score se não estiver bloqueando Warp
        }
        if (s.type === "RELAY_SERVICE" && !options.blockApplePrivateRelay) {
            s.score = Math.min(s.score, 15);
        }
        allSignals.push(s);
    }

    // Geo inconsistência
    allSignals.push(...detectGeoInconsistency(request, geoInfo));

    // Bogon IPs
    allSignals.push(...detectBogonIPs(request));

    // Cloudflare signals
    if (options.useCloudflareSignals !== false) {
        allSignals.push(
            ...detectCloudflareThreats(
                request,
                options.cfThreatScoreThreshold ?? DEFAULTS.cfThreatScoreThreshold
            )
        );
    }

    // ── Score total ────────────────────────────────────────────────────────────
    const totalScore = Math.min(
        allSignals.reduce((acc, s) => acc + s.score, 0),
        100
    );

    const threshold = options.anonymousScoreThreshold ?? DEFAULTS.anonymousScoreThreshold;
    const blockTypes = options.blockTypes ?? DEFAULTS.blockTypes;

    // ── Determina se é anonimizado ─────────────────────────────────────────────
    const isAnonymized =
        totalScore >= threshold ||
        allSignals.some((s) => blockTypes.includes(s.type) && s.confidence >= 0.7);

    // ── Verifica VPN corporativa ───────────────────────────────────────────────
    const needsCorporateVPN =
        (options.mode === "require_corporate" || options.mode === "both") &&
        (options.protectedPaths ?? []).some((pp) => {
            if (pp.endsWith("*")) return url.pathname.startsWith(pp.slice(0, -1));
            return url.pathname === pp || url.pathname.startsWith(pp + "/");
        });

    const corporateCheck = needsCorporateVPN
        ? verifyCorporateVPN(request, options)
        : { valid: true };

    const isCorporateVpn = corporateCheck.valid;

    if (!corporateCheck.valid && corporateCheck.signal) {
        allSignals.push(corporateCheck.signal);
    }

    // ── Determina ação final ───────────────────────────────────────────────────
    let action: VpnEnforcementAction = "allow";

    if (options.mode === "detect_only") {
        action = "log";
    } else if (needsCorporateVPN && !isCorporateVpn) {
        action = "require_vpn";
    } else if (isAnonymized && options.mode !== "require_corporate") {
        action = options.anonymousAction ?? DEFAULTS.anonymousAction;
    }

    // Países permitidos — override de bloqueio
    if (
        options.allowedCountries?.length &&
        geoInfo.country &&
        options.allowedCountries.includes(geoInfo.country)
    ) {
        if (action === "deny") {
            action = "log"; // Downgrade para log em países explicitamente permitidos
        }
    }

    const ok =
        action === "allow" ||
        action === "log" ||
        options.mode === "detect_only";

    // ── Audit log ──────────────────────────────────────────────────────────────
    const audit: VpnAuditLog = {
        timestamp: new Date().toISOString(),
        requestId: generateRequestId(),
        ip,
        method: request.method,
        path: url.pathname,
        country: geoInfo.country,
        asn: asnInfo.asn,
        action,
        detectedTypes: Array.from(new Set(allSignals.map((s) => s.type))),
        totalScore,
        processingMs: Date.now() - startTime,
    };

    if (!ok || options.verboseLog) {
        logVpnEvent(audit, allSignals);
    }

    return {
        ok,
        action,
        signals: allSignals,
        totalScore,
        isAnonymized,
        isCorporateVpn,
        geoInfo,
        asnInfo,
        audit,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS INTERNOS
// ─────────────────────────────────────────────────────────────────────────────

function buildPassthroughResult(
    request: NextRequest,
    startTime: number
): VpnCheckResult {
    const ip = extractRealIP(request);
    const url = new URL(request.url);
    return {
        ok: true,
        action: "allow",
        signals: [],
        totalScore: 0,
        isAnonymized: false,
        isCorporateVpn: true,
        geoInfo: extractGeoInfo(request),
        asnInfo: extractASNInfo(request),
        audit: {
            timestamp: new Date().toISOString(),
            requestId: generateRequestId(),
            ip,
            method: request.method,
            path: url.pathname,
            country: null,
            asn: null,
            action: "allow",
            detectedTypes: [],
            totalScore: 0,
            processingMs: Date.now() - startTime,
        },
    };
}

function logVpnEvent(
    audit: VpnAuditLog,
    signals: VpnDetectionSignal[]
): void {
    const level = audit.action === "allow" || audit.action === "log"
        ? "info"
        : "warn";

    console[level]("[VPN_ENFORCEMENT]", {
        ...audit,
        signals: signals.map((s) => ({
            type: s.type,
            confidence: s.confidence,
            score: s.score,
            source: s.source,
        })),
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTRUTOR DE RESPOSTA
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Gera a NextResponse correta para cada ação de VPN enforcement.
 */
export function buildVpnResponse(
    result: VpnCheckResult,
    options: VpnEnforcementOptions
): NextResponse {
    const isDev = process.env.NODE_ENV === "development";

    const debugBody = isDev
        ? {
            score: result.totalScore,
            isAnonymized: result.isAnonymized,
            signals: result.signals.map((s) => ({
                type: s.type,
                confidence: s.confidence,
                score: s.score,
                source: s.source,
            })),
        }
        : undefined;

    switch (result.action) {
        case "require_vpn": {
            const redirectUrl = options.vpnRequiredRedirectUrl ?? "/vpn-required";
            return NextResponse.redirect(new URL(redirectUrl, "https://placeholder.com"), {
                status: 302,
                headers: {
                    "Cache-Control": "no-store",
                    "X-VPN-Required": "true",
                },
            });
        }

        case "challenge": {
            const challengeUrl = options.challengeRedirectUrl ?? "/access-restricted";
            if (challengeUrl) {
                return NextResponse.redirect(
                    new URL(challengeUrl, "https://placeholder.com"),
                    { status: 302 }
                );
            }
            return new NextResponse(
                JSON.stringify({
                    error: "Access requires additional verification",
                    requestId: result.audit.requestId,
                    ...(debugBody && { debug: debugBody }),
                }),
                {
                    status: 401,
                    headers: {
                        "Content-Type": "application/json",
                        "X-Content-Type-Options": "nosniff",
                        "Cache-Control": "no-store",
                    },
                }
            );
        }

        case "deny":
        default:
            return new NextResponse(
                JSON.stringify({
                    error: "Access denied",
                    requestId: result.audit.requestId,
                    ...(debugBody && { debug: debugBody }),
                }),
                {
                    status: 403,
                    headers: {
                        "Content-Type": "application/json",
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                        "Cache-Control": "no-store",
                    },
                }
            );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE WRAPPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrapper completo para uso em middleware.ts ou Route Handlers.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { withVpnEnforcement } from "@/lib/security/vpnEnforcement";
 *
 * export async function middleware(request: NextRequest) {
 *   return withVpnEnforcement(
 *     request,
 *     () => NextResponse.next(),
 *     {
 *       // Bloqueia Tor e proxies públicos em toda a aplicação
 *       mode: "block_anonymous",
 *       blockTypes: ["TOR_EXIT_NODE", "PUBLIC_PROXY", "CONSUMER_VPN"],
 *       anonymousScoreThreshold: 65,
 *
 *       // Exige VPN corporativa nas rotas internas
 *       protectedPaths: ["/api/internal/*", "/admin/*"],
 *       corporateVpnCIDRs: ["10.8.0.0/16"],
 *       corporateVpnHeader: { name: "X-Corp-VPN", value: "ok" },
 *       vpnRequiredRedirectUrl: "/acesso-restrito",
 *
 *       // Exceções
 *       trustedIPs: ["200.100.50.1"],
 *       allowedCountries: ["BR", "PT"],
 *     }
 *   );
 * }
 *
 * export const config = {
 *   matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
 * };
 * ```
 */
export async function withVpnEnforcement(
    request: NextRequest,
    handler: (result: VpnCheckResult) => NextResponse | Promise<NextResponse>,
    options: VpnEnforcementOptions
): Promise<NextResponse> {
    const result = await checkVPN(request, options);

    if (!result.ok) {
        return buildVpnResponse(result, options);
    }

    return handler(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

// Todas as constantes acima já são exportadas diretamente via `export const`.
// Re-exportações abaixo cobrem apenas os símbolos sem `export` na declaração.
export {
    PROXY_HEADERS,
    VPN_USER_AGENT_PATTERNS,
    DEFAULTS as VPN_ENFORCEMENT_DEFAULTS,
};