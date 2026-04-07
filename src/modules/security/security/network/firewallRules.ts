/**
 * @arquivo     src/security/network/firewallRules.ts
 * @módulo      Security / Network / Regras de Firewall (WAF)
 * @descrição   Firewall de aplicação (WAF) para Next.js com engine de regras declarativas.
 *              Responsabilidades: filtragem por IP/CIDR/ASN/país, proteção contra bots,
 *              detecção de scanners, bloqueio de paths sensíveis, method tampering,
 *              rate limiting estrutural, detecção de enumeração, bloqueio de Tor nodes,
 *              score de risco acumulativo e suporte a regras customizadas.
 *
 * @como-usar
 *              const firewall = new ApplicationFirewall({ mode: 'enforce', blockedIPs: [...] });
 *              const result = await firewall.evaluate(request);
 *              if (!result.ok) return buildFirewallResponse(result);
 *              // Middleware completo:
 *              const response = await firewallMiddleware(request, options);
 *              if (response) return response;
 *
 * @dependências next/server, requestSanitizer.ts, dnsProtection.ts, rateLimiter.ts
 * @notas       O modo 'audit' registra violações sem bloquear.
 *              Use 'enforce' em produção.
 *
 * @módulo security/firewallRules
 */

import { NextRequest, NextResponse } from "next/server";

// ─────────────────────────────────────────────────────────────────────────────
// TIPOS E INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

/** Ação que uma regra pode tomar ao ser ativada. */
export type FirewallAction =
    | "allow"     // Permite e interrompe o pipeline (whitelist explícita)
    | "deny"      // Bloqueia imediatamente com 403
    | "block"     // Bloqueia com 400/403 e adiciona ao blocklist temporário
    | "challenge" // Retorna 401/429 — usado para CAPTCHA ou step-up auth
    | "log"       // Apenas registra — não bloqueia (modo audit)
    | "score";    // Adiciona ao score de risco sem ação imediata

/** Fase do pipeline onde a regra é avaliada. */
export type FirewallPhase =
    | "connection" // Avaliada primeiro: IP, geo, ASN
    | "request"    // Headers, método, path, query
    | "body"       // Conteúdo do body (requer leitura)
    | "response";  // Inspeciona a resposta antes de enviar (future-proof)

export type FirewallViolationType =
    | "IP_BLOCKED"
    | "IP_BLOCKLIST"
    | "CIDR_BLOCKED"
    | "TOR_EXIT_NODE"
    | "ANONYMOUS_PROXY"
    | "GEO_BLOCKED"
    | "ASN_BLOCKED"
    | "BOT_DETECTED"
    | "SCANNER_DETECTED"
    | "CRAWLER_BLOCKED"
    | "USER_AGENT_BLOCKED"
    | "USER_AGENT_MISSING"
    | "METHOD_NOT_ALLOWED"
    | "PATH_BLOCKED"
    | "PATH_TRAVERSAL"
    | "SENSITIVE_PATH"
    | "ADMIN_PATH_UNAUTHORIZED"
    | "RATE_LIMIT_EXCEEDED"
    | "ENUMERATION_DETECTED"
    | "CUSTOM_RULE_TRIGGERED"
    | "RISK_SCORE_EXCEEDED"
    | "REFERER_INVALID"
    | "REQUEST_SMUGGLING"
    | "HTTP_VERSION_MISMATCH"
    | "OVERSIZED_HEADER"
    | "TOO_MANY_HEADERS"
    | "MALFORMED_REQUEST";

export interface FirewallViolation {
    type: FirewallViolationType;
    ruleId: string;
    message: string;
    action: FirewallAction;
    score: number;
    detail?: string;
    meta?: Record<string, unknown>;
}

export interface FirewallResult {
    ok: boolean;
    action: FirewallAction;
    violations: FirewallViolation[];
    totalScore: number;
    /** ID da primeira regra que causou bloqueio */
    blockedByRule?: string;
    /** Metadados de auditoria — não expor ao cliente */
    audit: {
        ip: string;
        method: string;
        path: string;
        userAgent: string;
        timestamp: string;
        processingTimeMs?: number;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// DEFINIÇÃO DE REGRAS
// ─────────────────────────────────────────────────────────────────────────────

export interface FirewallRule {
    /** Identificador único da regra (ex: "WAF-001") */
    id: string;
    /** Descrição legível da regra */
    description: string;
    /** Fase de avaliação */
    phase: FirewallPhase;
    /** Prioridade: menor número = avaliado primeiro (0–1000) */
    priority: number;
    /** Ação a executar quando a regra é ativada */
    action: FirewallAction;
    /** Score de risco adicionado ao total quando ativada (0–100) */
    score: number;
    /** Se true, interrompe o pipeline imediatamente ao ser ativada */
    terminal?: boolean;
    /** Se false, a regra está desabilitada */
    enabled?: boolean;
    /** Função de match — retorna true se a regra se aplica à requisição */
    match: (context: FirewallContext) => boolean | Promise<boolean>;
}

export interface FirewallContext {
    request: NextRequest;
    ip: string;
    method: string;
    path: string;
    pathname: string;
    query: URLSearchParams;
    headers: Headers;
    userAgent: string;
    referer: string | null;
    contentType: string | null;
    contentLength: number;
    /** Score acumulado até o momento no pipeline */
    currentScore: number;
    /** Violations já registradas */
    violations: FirewallViolation[];
}

export interface FirewallOptions {
    /** Score máximo antes de bloquear automaticamente (padrão: 75) */
    maxRiskScore?: number;
    /** IPs explicitamente permitidos (bypass total) */
    trustedIPs?: string[];
    /** IPs/CIDRs bloqueados */
    blockedIPs?: string[];
    /** Países bloqueados (ISO 3166-1 alpha-2, ex: ["CN", "RU"]) */
    blockedCountries?: string[];
    /** ASNs bloqueados (ex: ["AS12345"]) */
    blockedASNs?: string[];
    /** Paths que requerem autenticação adicional */
    adminPaths?: string[];
    /** Paths completamente bloqueados */
    blockedPaths?: string[];
    /** Métodos HTTP permitidos */
    allowedMethods?: string[];
    /** Se deve bloquear User-Agents ausentes (padrão: true) */
    blockMissingUserAgent?: boolean;
    /** Se deve bloquear Tor exit nodes (padrão: true) */
    blockTor?: boolean;
    /** Regras customizadas adicionais */
    customRules?: FirewallRule[];
    /** Modo de operação (padrão: "enforce") */
    mode?: "enforce" | "audit" | "off";
    /** Se deve logar todas as requisições, mesmo as permitidas */
    verboseLog?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTES DE SEGURANÇA
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULTS: Required<Omit<FirewallOptions, "trustedIPs" | "blockedIPs" | "blockedCountries" | "blockedASNs" | "adminPaths" | "blockedPaths" | "customRules">> = {
    maxRiskScore: 75,
    allowedMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    blockMissingUserAgent: true,
    blockTor: true,
    mode: "enforce",
    verboseLog: false,
};

/**
 * User-Agents de ferramentas de scan e ataque conhecidas.
 * Cada entrada tem um nome descritivo para auditoria.
 */
const SCANNER_USER_AGENTS: Array<{ name: string; pattern: RegExp }> = [
    { name: "Nikto", pattern: /nikto/i },
    { name: "sqlmap", pattern: /sqlmap/i },
    { name: "Nmap", pattern: /nmap/i },
    { name: "Masscan", pattern: /masscan/i },
    { name: "Burp Suite", pattern: /burp/i },
    { name: "OWASP ZAP", pattern: /zaproxy|owasp/i },
    { name: "Nuclei", pattern: /nuclei/i },
    { name: "Acunetix", pattern: /acunetix/i },
    { name: "Nessus", pattern: /nessus/i },
    { name: "OpenVAS", pattern: /openvas/i },
    { name: "Metasploit", pattern: /metasploit/i },
    { name: "w3af", pattern: /w3af/i },
    { name: "Wfuzz", pattern: /wfuzz/i },
    { name: "ffuf", pattern: /ffuf/i },
    { name: "Gobuster", pattern: /gobuster/i },
    { name: "dirbuster", pattern: /dirbuster/i },
    { name: "WPScan", pattern: /wpscan/i },
    { name: "Shodan", pattern: /shodan/i },
    { name: "Censys", pattern: /censys/i },
    { name: "Jorgee", pattern: /jorgee/i },
    { name: "Havij", pattern: /havij/i },
    { name: "libwww-perl", pattern: /libwww-perl/i },
    { name: "python-requests", pattern: /python-requests\/[0-9]/i },
    { name: "Go HTTP client", pattern: /^go-http-client\//i },
    { name: "curl (suspicious)", pattern: /^curl\/[0-9]/ },
    { name: "Java HttpClient", pattern: /^java\//i },
    { name: "Wget", pattern: /^wget\//i },
    { name: "MJ12bot", pattern: /mj12bot/i },
    { name: "DotBot", pattern: /dotbot/i },
    { name: "AhrefsBot", pattern: /ahrefsbot/i },
    { name: "SemrushBot", pattern: /semrushbot/i },
    { name: "MajesticSEO", pattern: /magestic|majestic/i },
    { name: "DataForSeo", pattern: /dataforseo/i },
    { name: "PetalBot", pattern: /petalbot/i },
    { name: "BLEXBot", pattern: /blexbot/i },
    { name: "Scrapy", pattern: /scrapy/i },
    { name: "HTTrack", pattern: /httrack/i },
];

/**
 * Bots legítimos cujo User-Agent deve ser verificado mas não bloqueado
 * automaticamente (precisam de validação de IP reverso para ser confiáveis).
 */
const LEGITIMATE_BOTS: RegExp[] = [
    /googlebot/i,
    /bingbot/i,
    /slurp/i,         // Yahoo
    /duckduckbot/i,
    /baiduspider/i,
    /yandexbot/i,
    /facebookexternalhit/i,
    /twitterbot/i,
    /linkedinbot/i,
    /whatsapp/i,
    /applebot/i,
    /ia_archiver/i,   // Wayback Machine
];

/**
 * Paths sensíveis que nunca devem ser expostos publicamente.
 * Inclui arquivos de configuração, CI/CD, secrets e frameworks comuns.
 */
const SENSITIVE_PATHS: RegExp[] = [
    // Configuração de ambiente e secrets
    /\/\.env(\.|$)/i,
    /\/\.env\.(local|production|development|test|staging)/i,
    /\/\.secret/i,
    /\/secrets?\//i,
    /\/config\/.*\.(json|yaml|yml|toml|ini|conf)$/i,

    // Git e controle de versão
    /\/\.git\//i,
    /\/\.gitignore$/i,
    /\/\.gitconfig$/i,
    /\/\.svn\//i,
    /\/\.hg\//i,

    // CI/CD e DevOps
    /\/\.github\//i,
    /\/\.gitlab-ci\.yml$/i,
    /\/\.travis\.yml$/i,
    /\/Jenkinsfile$/i,
    /\/docker-compose.*\.yml$/i,
    /\/Dockerfile/i,
    /\/\.dockerignore$/i,
    /\/\.k8s\//i,
    /\/terraform\//i,
    /\/\.terraform\//i,

    // Dependências e lock files
    /\/package\.json$/i,
    /\/package-lock\.json$/i,
    /\/yarn\.lock$/i,
    /\/pnpm-lock\.yaml$/i,
    /\/Gemfile(\.lock)?$/i,
    /\/composer\.(json|lock)$/i,
    /\/requirements\.txt$/i,
    /\/Pipfile(\.lock)?$/i,

    // Backups e dumps
    /\.(bak|backup|old|orig|save|swp|tmp)$/i,
    /\/dump\.(sql|gz|zip|tar)$/i,
    /\/backup\//i,

    // Logs
    /\/logs?\//i,
    /\.(log|logs)$/i,
    /\/access\.log/i,
    /\/error\.log/i,

    // Frameworks e CMS específicos
    /\/wp-config\.php$/i,
    /\/wp-admin\//i,
    /\/xmlrpc\.php$/i,
    /\/phpinfo\.php$/i,
    /\/\.htaccess$/i,
    /\/\.htpasswd$/i,
    /\/web\.config$/i,
    /\/web\.xml$/i,
    /\/WEB-INF\//i,
    /\/META-INF\//i,

    // Next.js internos (nunca devem ser acessados diretamente)
    /\/\.next\/server\//i,
    /\/\.next\/cache\//i,

    // Chaves e certificados
    /\.(pem|key|crt|cer|p12|pfx|csr)$/i,
    /\/id_rsa/i,
    /\/authorized_keys$/i,
    /\/known_hosts$/i,

    // Banco de dados
    /\.(sqlite|sqlite3|db|mdb)$/i,
    /\/database\.yml$/i,

    // AWS e cloud credentials
    /\/\.aws\/credentials/i,
    /\/credentials\.json$/i,
    /\/service-account\.json$/i,
];

/**
 * Paths de ferramentas de scan tentando descobrir endpoints conhecidos.
 * Indicam varredura automatizada — alta certeza de ataque.
 */
const SCAN_PATH_PATTERNS: RegExp[] = [
    /\/cgi-bin\//i,
    /\/phpmyadmin/i,
    /\/adminer/i,
    /\/manager\/html/i,         // Tomcat Manager
    /\/solr\/admin/i,
    /\/actuator(\/|$)/i,        // Spring Boot Actuator
    /\/metrics(\/|$)/i,
    /\/health(\/|$)/i,          // Se não for sua rota
    /\/_profiler/i,              // Symfony
    /\/telescope/i,              // Laravel Telescope
    /\/horizon/i,                // Laravel Horizon
    /\/debug\/default\/view/i,   // Yii
    /\/__clockwork/i,
    /\/jmx-console/i,
    /\/web-console/i,
    /\/status\.php/i,
    /\/server-status/i,          // Apache
    /\/server-info/i,
    /\/nginx_status/i,
    /\/\.well-known\/security\.txt/i,
    /\/crossdomain\.xml$/i,
    /\/clientaccesspolicy\.xml$/i,
    /\/favicon\.ico$/i,          // Scanners verificam favicon para fingerprint
    /\/robots\.txt$/i,           // Pode ser legítimo — apenas loga
    /\/sitemap.*\.xml$/i,
];

/**
 * Padrões de path traversal além dos cobertos pelo requestSanitizer.
 */
const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
    /\.\.\//,
    /\.\.%2[fF]/,
    /\.\.%5[cC]/,
    /%2[eE]%2[eE]%2[fF]/,
    /%252[eE]%252[eE]/,   // Double URL encoding
    /\.\.\\/,
    /\/etc\/passwd/i,
    /\/etc\/shadow/i,
    /\/proc\/self/i,
    /\/windows\/system32/i,
    /\/boot\.ini/i,
    /win\.ini/i,
];

/**
 * Padrões de HTTP Request Smuggling nos headers.
 * Ataques que exploram discrepâncias entre frontend proxy e backend.
 */
const REQUEST_SMUGGLING_PATTERNS: RegExp[] = [
    /transfer-encoding:\s*chunked[\s\S]*content-length:/i,
    /content-length:[\s\S]*transfer-encoding:\s*chunked/i,
];

// ─────────────────────────────────────────────────────────────────────────────
// UTILITÁRIOS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extrai o IP real da requisição considerando proxies confiáveis.
 * Ordem de prioridade: CF-Connecting-IP > X-Real-IP > X-Forwarded-For > socket
 */
export function extractClientIP(request: NextRequest): string {
    const cfIP = request.headers.get("cf-connecting-ip");
    if (cfIP) return cfIP.trim();

    const realIP = request.headers.get("x-real-ip");
    if (realIP) return realIP.trim();

    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) {
        // Pega o IP mais à esquerda (cliente original)
        const first = forwarded.split(",")[0];
        if (first) return first.trim();
    }

    // Fallback para o IP da conexão (Next.js Edge Runtime)
    try {
        return new URL(request.url).hostname;
    } catch {
        return "unknown";
    }
}

/**
 * Converte notação CIDR para verificação de IP.
 * Suporta apenas IPv4 por ora.
 */
export function ipMatchesCIDR(ip: string, cidr: string): boolean {
    try {
        const [range, bits] = cidr.split("/");
        if (!range || !bits) return ip === cidr;

        const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1) >>> 0;
        const ipInt = ipToInt(ip);
        const rangeInt = ipToInt(range);

        if (ipInt === null || rangeInt === null) return false;
        return (ipInt & mask) === (rangeInt & mask);
    } catch {
        return false;
    }
}

function ipToInt(ip: string): number | null {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    const nums = parts.map(Number);
    if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
    return ((nums[0]! << 24) | (nums[1]! << 16) | (nums[2]! << 8) | nums[3]!) >>> 0;
}

/**
 * Verifica se um IP está em qualquer CIDR ou lista exata.
 */
export function ipMatchesList(ip: string, list: string[]): boolean {
    return list.some((entry) =>
        entry.includes("/") ? ipMatchesCIDR(ip, entry) : ip === entry
    );
}

/**
 * Detecta scanner pelo User-Agent. Retorna o nome da ferramenta ou null.
 */
export function detectScanner(userAgent: string): string | null {
    for (const { name, pattern } of SCANNER_USER_AGENTS) {
        if (pattern.test(userAgent)) return name;
    }
    return null;
}

/**
 * Verifica se o User-Agent parece ser de bot legítimo.
 */
export function isLegitimateBot(userAgent: string): boolean {
    return LEGITIMATE_BOTS.some((pattern) => pattern.test(userAgent));
}

/**
 * Detecta se o path acessa recurso sensível.
 */
export function detectSensitivePath(pathname: string): RegExp | null {
    for (const pattern of SENSITIVE_PATHS) {
        if (pattern.test(pathname)) return pattern;
    }
    return null;
}

/**
 * Detecta padrão de scan no path.
 */
export function detectScanPath(pathname: string): RegExp | null {
    for (const pattern of SCAN_PATH_PATTERNS) {
        if (pattern.test(pathname)) return pattern;
    }
    return null;
}

/**
 * Detecta tentativa de path traversal no URL.
 */
export function detectPathTraversal(input: string): boolean {
    return PATH_TRAVERSAL_PATTERNS.some((p) => p.test(input));
}

/**
 * Verifica Request Smuggling via análise dos headers raw.
 */
export function detectRequestSmuggling(headers: Headers): boolean {
    const te = headers.get("transfer-encoding") ?? "";
    const cl = headers.get("content-length") ?? "";
    if (te && cl) return true; // TE + CL presentes juntos é suspeito
    const raw = `${te} ${cl}`;
    return REQUEST_SMUGGLING_PATTERNS.some((p) => p.test(raw));
}

/**
 * Conta o número de headers da requisição.
 */
export function countHeaders(headers: Headers): number {
    let count = 0;
    headers.forEach(() => { count++; });
    return count;
}

/**
 * Soma o tamanho total dos valores dos headers.
 */
export function totalHeaderSize(headers: Headers): number {
    let size = 0;
    headers.forEach((value, key) => {
        size += key.length + value.length + 4; // ": " + "\r\n"
    });
    return size;
}

// ─────────────────────────────────────────────────────────────────────────────
// REGRAS BUILT-IN
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Gera o conjunto completo de regras built-in com base nas opções configuradas.
 */
function buildBuiltInRules(options: FirewallOptions): FirewallRule[] {
    const opts = { ...DEFAULTS, ...options };

    const rules: FirewallRule[] = [

        // ── FASE: CONNECTION ───────────────────────────────────────────────────

        {
            id: "WAF-001",
            description: "Bloqueia IPs na lista de bloqueio explícita",
            phase: "connection",
            priority: 1,
            action: "block",
            score: 100,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                if (!opts.blockedIPs?.length) return false;
                return ipMatchesList(ctx.ip, opts.blockedIPs);
            },
        },

        {
            id: "WAF-002",
            description: "Bloqueia requisições sem IP identificável",
            phase: "connection",
            priority: 2,
            action: "block",
            score: 80,
            terminal: true,
            enabled: true,
            match: (ctx) => !ctx.ip || ctx.ip === "unknown",
        },

        {
            id: "WAF-003",
            description: "Bloqueia países na geo-blocklist",
            phase: "connection",
            priority: 5,
            action: "deny",
            score: 100,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                if (!opts.blockedCountries?.length) return false;
                // CF-IPCountry é injetado pelo Cloudflare
                const country = ctx.headers.get("cf-ipcountry") ??
                    ctx.headers.get("x-country-code") ?? "";
                return opts.blockedCountries.includes(country.toUpperCase());
            },
        },

        {
            id: "WAF-004",
            description: "Bloqueia ASNs conhecidos por abuso",
            phase: "connection",
            priority: 6,
            action: "deny",
            score: 90,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                if (!opts.blockedASNs?.length) return false;
                const asn = ctx.headers.get("cf-ip-asn") ??
                    ctx.headers.get("x-asn") ?? "";
                return opts.blockedASNs.some((a) =>
                    asn.toUpperCase().includes(a.toUpperCase())
                );
            },
        },

        {
            id: "WAF-005",
            description: "Detecta Tor exit nodes via header Cloudflare",
            phase: "connection",
            priority: 7,
            action: opts.blockTor ? "block" : "log",
            score: 85,
            terminal: opts.blockTor,
            enabled: true,
            match: (ctx) => {
                // Cloudflare injeta este header para Tor exit nodes
                const isTor = ctx.headers.get("cf-ipcountry") === "T1";
                if (isTor) return true;
                // Fallback: verifica header customizado de proxy detection
                const proxy = ctx.headers.get("x-proxy-type") ?? "";
                return /tor/i.test(proxy);
            },
        },

        {
            id: "WAF-006",
            description: "Detecta proxies anônimos e VPNs de alto risco",
            phase: "connection",
            priority: 8,
            action: "score",
            score: 40,
            enabled: true,
            match: (ctx) => {
                const threat = ctx.headers.get("cf-threat-score");
                if (threat && parseInt(threat, 10) > 20) return true;
                const proxy = ctx.headers.get("x-proxy-type") ?? "";
                return /anonymous|elite|high-anonymity|vpn/i.test(proxy);
            },
        },

        // ── FASE: REQUEST — MÉTODO ─────────────────────────────────────────────

        {
            id: "WAF-010",
            description: "Rejeita métodos HTTP não permitidos",
            phase: "request",
            priority: 10,
            action: "deny",
            score: 70,
            terminal: true,
            enabled: true,
            match: (ctx) => !opts.allowedMethods.includes(ctx.method),
        },

        {
            id: "WAF-011",
            description: "Detecta method tampering via _method override",
            phase: "request",
            priority: 11,
            action: "deny",
            score: 60,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                // Alguns frameworks aceitam _method no body/query para tunneling de método
                const methodOverride = ctx.headers.get("x-http-method-override") ??
                    ctx.headers.get("x-method-override") ??
                    ctx.query.get("_method") ?? "";
                if (!methodOverride) return false;
                const normalized = methodOverride.toUpperCase();
                return !opts.allowedMethods.includes(normalized);
            },
        },

        // ── FASE: REQUEST — USER AGENT ─────────────────────────────────────────

        {
            id: "WAF-020",
            description: "Bloqueia User-Agent ausente",
            phase: "request",
            priority: 20,
            action: opts.blockMissingUserAgent ? "block" : "score",
            score: 50,
            terminal: opts.blockMissingUserAgent,
            enabled: true,
            match: (ctx) => !ctx.userAgent || ctx.userAgent.trim() === "",
        },

        {
            id: "WAF-021",
            description: "Detecta ferramentas de scan e ataque por User-Agent",
            phase: "request",
            priority: 21,
            action: "block",
            score: 100,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                if (!ctx.userAgent) return false;
                return detectScanner(ctx.userAgent) !== null;
            },
        },

        {
            id: "WAF-022",
            description: "Detecta User-Agents suspeitos (muito curtos, genéricos, binários)",
            phase: "request",
            priority: 22,
            action: "score",
            score: 35,
            enabled: true,
            match: (ctx) => {
                const ua = ctx.userAgent;
                if (!ua) return false;
                // Muito curto (< 10 chars) sem ser um bot legítimo
                if (ua.length < 10 && !isLegitimateBot(ua)) return true;
                // Contém caracteres de controle
                // eslint-disable-next-line no-control-regex
                if (/[\x00-\x08\x0B-\x1F]/.test(ua)) return true;
                // User-agent "teste" ou placeholder
                if (/^(test|null|none|undefined|-|0)$/i.test(ua.trim())) return true;
                return false;
            },
        },

        {
            id: "WAF-023",
            description: "Detecta bots legítimos sem verificação de IP reverso (score apenas)",
            phase: "request",
            priority: 23,
            action: "log",
            score: 10,
            enabled: true,
            match: (ctx) => isLegitimateBot(ctx.userAgent),
        },

        // ── FASE: REQUEST — PATH ───────────────────────────────────────────────

        {
            id: "WAF-030",
            description: "Detecta path traversal no URL",
            phase: "request",
            priority: 30,
            action: "block",
            score: 100,
            terminal: true,
            enabled: true,
            match: (ctx) =>
                detectPathTraversal(ctx.path) || detectPathTraversal(ctx.pathname),
        },

        {
            id: "WAF-031",
            description: "Bloqueia acesso a paths sensíveis (secrets, configs, git…)",
            phase: "request",
            priority: 31,
            action: "deny",
            score: 90,
            terminal: true,
            enabled: true,
            match: (ctx) => detectSensitivePath(ctx.pathname) !== null,
        },

        {
            id: "WAF-032",
            description: "Detecta padrões de varredura automática de endpoints",
            phase: "request",
            priority: 32,
            action: "block",
            score: 80,
            terminal: true,
            enabled: true,
            match: (ctx) => detectScanPath(ctx.pathname) !== null,
        },

        {
            id: "WAF-033",
            description: "Bloqueia paths explicitamente configurados",
            phase: "request",
            priority: 33,
            action: "deny",
            score: 100,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                if (!opts.blockedPaths?.length) return false;
                return opts.blockedPaths.some((blocked) => {
                    if (blocked.endsWith("*")) {
                        return ctx.pathname.startsWith(blocked.slice(0, -1));
                    }
                    return ctx.pathname === blocked;
                });
            },
        },

        {
            id: "WAF-034",
            description: "Protege rotas administrativas — exige header de autorização",
            phase: "request",
            priority: 34,
            action: "challenge",
            score: 60,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                if (!opts.adminPaths?.length) return false;
                const isAdmin = opts.adminPaths.some((ap) =>
                    ctx.pathname.startsWith(ap)
                );
                if (!isAdmin) return false;
                // Permite se tiver Authorization header
                const auth = ctx.headers.get("authorization");
                return !auth || auth.trim() === "";
            },
        },

        {
            id: "WAF-035",
            description: "Detecta tentativas de acessar extensões de arquivo incomuns",
            phase: "request",
            priority: 35,
            action: "score",
            score: 25,
            enabled: true,
            match: (ctx) => {
                const suspiciousExts = /\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh|bat|exe|dll|so|dylib)$/i;
                return suspiciousExts.test(ctx.pathname);
            },
        },

        {
            id: "WAF-036",
            description: "Detecta URLs excessivamente longas (potencial buffer overflow / fuzzing)",
            phase: "request",
            priority: 36,
            action: "deny",
            score: 60,
            terminal: true,
            enabled: true,
            match: (ctx) => ctx.path.length > 2048,
        },

        // ── FASE: REQUEST — HEADERS ────────────────────────────────────────────

        {
            id: "WAF-040",
            description: "Detecta Request Smuggling via Content-Length + Transfer-Encoding",
            phase: "request",
            priority: 40,
            action: "block",
            score: 100,
            terminal: true,
            enabled: true,
            match: (ctx) => detectRequestSmuggling(ctx.headers),
        },

        {
            id: "WAF-041",
            description: "Bloqueia headers em excesso (DoS / fuzzing)",
            phase: "request",
            priority: 41,
            action: "deny",
            score: 60,
            terminal: true,
            enabled: true,
            match: (ctx) => countHeaders(ctx.headers) > 100,
        },

        {
            id: "WAF-042",
            description: "Bloqueia payload de headers muito grande (> 32KB total)",
            phase: "request",
            priority: 42,
            action: "deny",
            score: 70,
            terminal: true,
            enabled: true,
            match: (ctx) => totalHeaderSize(ctx.headers) > 32 * 1024,
        },

        {
            id: "WAF-043",
            description: "Detecta Content-Length inválido ou negativo",
            phase: "request",
            priority: 43,
            action: "deny",
            score: 50,
            terminal: true,
            enabled: true,
            match: (ctx) => {
                const cl = ctx.headers.get("content-length");
                if (!cl) return false;
                const parsed = parseInt(cl, 10);
                return isNaN(parsed) || parsed < 0;
            },
        },

        {
            id: "WAF-044",
            description: "Detecta Referer suspeito ou inválido",
            phase: "request",
            priority: 44,
            action: "score",
            score: 20,
            enabled: true,
            match: (ctx) => {
                if (!ctx.referer) return false;
                try {
                    new URL(ctx.referer);
                    return false;
                } catch {
                    return true; // Referer malformado
                }
            },
        },

        {
            id: "WAF-045",
            description: "Detecta Accept-Language inválido ou excessivamente longo",
            phase: "request",
            priority: 45,
            action: "score",
            score: 15,
            enabled: true,
            match: (ctx) => {
                const lang = ctx.headers.get("accept-language") ?? "";
                return lang.length > 512;
            },
        },

        // ── FASE: REQUEST — QUERY STRING ───────────────────────────────────────

        {
            id: "WAF-050",
            description: "Detecta query string excessivamente longa (> 4KB)",
            phase: "request",
            priority: 50,
            action: "deny",
            score: 50,
            terminal: true,
            enabled: true,
            match: (ctx) => ctx.query.toString().length > 4096,
        },

        {
            id: "WAF-051",
            description: "Detecta excesso de parâmetros de query (> 100)",
            phase: "request",
            priority: 51,
            action: "deny",
            score: 45,
            terminal: true,
            enabled: true,
            match: (ctx) => Array.from(ctx.query.keys()).length > 100,
        },

        // ── SCORE ACUMULATIVO ──────────────────────────────────────────────────

        {
            id: "WAF-090",
            description: "Bloqueia requisição quando score de risco acumulado excede o limite",
            phase: "request",
            priority: 90,
            action: "block",
            score: 0,
            terminal: true,
            enabled: true,
            match: (ctx) => ctx.currentScore >= opts.maxRiskScore,
        },
    ];

    return rules.filter((r) => r.enabled !== false);
}

// ─────────────────────────────────────────────────────────────────────────────
// ENGINE DO FIREWALL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executa o pipeline de regras do firewall sobre uma requisição.
 * As regras são ordenadas por prioridade e executadas em sequência.
 * Regras `terminal` interrompem o pipeline imediatamente.
 *
 * @example
 * ```ts
 * const result = await evaluateFirewall(request, {
 *   allowedMethods: ["GET", "POST"],
 *   blockedCountries: ["KP"],
 *   adminPaths: ["/api/admin"],
 *   blockedPaths: ["/api/internal/*"],
 * });
 * if (!result.ok) {
 *   return buildFirewallResponse(result);
 * }
 * ```
 */
export async function evaluateFirewall(
    request: NextRequest,
    options: FirewallOptions = {}
): Promise<FirewallResult> {
    const startTime = Date.now();

    // Modo off — bypass total
    if (options.mode === "off") {
        return {
            ok: true,
            action: "allow",
            violations: [],
            totalScore: 0,
            audit: buildAuditLog(request, "unknown", Date.now() - startTime),
        };
    }

    const ip = extractClientIP(request);

    // IPs confiáveis — bypass total do firewall
    if (options.trustedIPs?.length && ipMatchesList(ip, options.trustedIPs)) {
        return {
            ok: true,
            action: "allow",
            violations: [],
            totalScore: 0,
            audit: buildAuditLog(request, ip, Date.now() - startTime),
        };
    }

    // Monta o contexto
    const url = new URL(request.url);
    const ctx: FirewallContext = {
        request,
        ip,
        method: request.method.toUpperCase(),
        path: request.url,
        pathname: url.pathname,
        query: url.searchParams,
        headers: request.headers,
        userAgent: request.headers.get("user-agent") ?? "",
        referer: request.headers.get("referer"),
        contentType: request.headers.get("content-type"),
        contentLength: parseInt(request.headers.get("content-length") ?? "0", 10),
        currentScore: 0,
        violations: [],
    };

    // Combina regras built-in + customizadas, ordenadas por prioridade
    const allRules = [
        ...buildBuiltInRules(options),
        ...(options.customRules ?? []),
    ].sort((a, b) => a.priority - b.priority);

    const violations: FirewallViolation[] = [];
    let totalScore = 0;
    let finalAction: FirewallAction = "allow";
    let blockedByRule: string | undefined;

    for (const rule of allRules) {
        // Atualiza o score atual no contexto antes de cada avaliação
        ctx.currentScore = totalScore;
        ctx.violations = violations;

        let matched: boolean;
        try {
            matched = await rule.match(ctx);
        } catch (err) {
            // Regras que lançam exceção são tratadas como não-match
            // para evitar que bugs em regras customizadas derrubem o firewall
            console.error(`[FIREWALL] Error evaluating rule ${rule.id}:`, err);
            matched = false;
        }

        if (!matched) continue;

        const violation: FirewallViolation = {
            type: ruleActionToViolationType(rule),
            ruleId: rule.id,
            message: rule.description,
            action: rule.action,
            score: rule.score,
        };

        violations.push(violation);
        totalScore += rule.score;

        // Em modo audit, as ações de bloqueio são rebaixadas para "log"
        const effectiveAction = options.mode === "audit" ? "log" : rule.action;

        if (["deny", "block", "challenge"].includes(effectiveAction)) {
            finalAction = effectiveAction as FirewallAction;
            blockedByRule = rule.id;

            if (rule.terminal) break;
        }

        if (effectiveAction === "allow" && rule.terminal) {
            finalAction = "allow";
            break;
        }
    }

    // Score acumulado pode bloquear mesmo sem regra terminal
    if (finalAction === "allow" && totalScore >= (options.maxRiskScore ?? DEFAULTS.maxRiskScore)) {
        finalAction = "block";
        violations.push({
            type: "RISK_SCORE_EXCEEDED",
            ruleId: "WAF-090",
            message: `Accumulated risk score ${totalScore} exceeds maximum of ${options.maxRiskScore ?? DEFAULTS.maxRiskScore}`,
            action: "block",
            score: 0,
        });
        blockedByRule = "WAF-090";
    }

    const ok = finalAction === "allow" || finalAction === "log" || options.mode === "audit";

    const result: FirewallResult = {
        ok,
        action: finalAction,
        violations,
        totalScore,
        blockedByRule,
        audit: buildAuditLog(request, ip, Date.now() - startTime),
    };

    if (options.verboseLog || !ok) {
        logFirewallEvent(result);
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS INTERNOS
// ─────────────────────────────────────────────────────────────────────────────

function ruleActionToViolationType(rule: FirewallRule): FirewallViolationType {
    // Tenta inferir o tipo de violação pelo ID e action da regra
    const map: Record<string, FirewallViolationType> = {
        "WAF-001": "IP_BLOCKLIST",
        "WAF-002": "IP_BLOCKED",
        "WAF-003": "GEO_BLOCKED",
        "WAF-004": "ASN_BLOCKED",
        "WAF-005": "TOR_EXIT_NODE",
        "WAF-006": "ANONYMOUS_PROXY",
        "WAF-010": "METHOD_NOT_ALLOWED",
        "WAF-011": "METHOD_NOT_ALLOWED",
        "WAF-020": "USER_AGENT_MISSING",
        "WAF-021": "SCANNER_DETECTED",
        "WAF-022": "USER_AGENT_BLOCKED",
        "WAF-023": "CRAWLER_BLOCKED",
        "WAF-030": "PATH_TRAVERSAL",
        "WAF-031": "SENSITIVE_PATH",
        "WAF-032": "SCANNER_DETECTED",
        "WAF-033": "PATH_BLOCKED",
        "WAF-034": "ADMIN_PATH_UNAUTHORIZED",
        "WAF-035": "PATH_BLOCKED",
        "WAF-036": "MALFORMED_REQUEST",
        "WAF-040": "REQUEST_SMUGGLING",
        "WAF-041": "OVERSIZED_HEADER",
        "WAF-042": "OVERSIZED_HEADER",
        "WAF-043": "MALFORMED_REQUEST",
        "WAF-044": "REFERER_INVALID",
        "WAF-045": "MALFORMED_REQUEST",
        "WAF-050": "MALFORMED_REQUEST",
        "WAF-051": "MALFORMED_REQUEST",
        "WAF-090": "RISK_SCORE_EXCEEDED",
    };
    return map[rule.id] ?? "CUSTOM_RULE_TRIGGERED";
}

function buildAuditLog(
    request: NextRequest,
    ip: string,
    processingTimeMs: number
): FirewallResult["audit"] {
    const url = new URL(request.url);
    return {
        ip,
        method: request.method,
        path: url.pathname,
        userAgent: request.headers.get("user-agent") ?? "",
        timestamp: new Date().toISOString(),
        processingTimeMs,
    };
}

function logFirewallEvent(result: FirewallResult): void {
    const level = result.ok ? "info" : "warn";
    console[level]("[FIREWALL]", {
        ok: result.ok,
        action: result.action,
        score: result.totalScore,
        blockedByRule: result.blockedByRule,
        violations: result.violations.map((v) => ({
            rule: v.ruleId,
            type: v.type,
            score: v.score,
        })),
        audit: result.audit,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSTRUTOR DE RESPOSTA HTTP
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Converte um FirewallResult em uma NextResponse de erro apropriada.
 *
 * @example
 * ```ts
 * const result = await evaluateFirewall(request, firewallConfig);
 * if (!result.ok) return buildFirewallResponse(result);
 * ```
 */
export function buildFirewallResponse(result: FirewallResult): NextResponse {
    const isDev = process.env.NODE_ENV === "development";

    const statusMap: Record<FirewallAction, number> = {
        deny: 403,
        block: 403,
        challenge: 401,
        log: 200,
        score: 200,
        allow: 200,
    };

    const status = statusMap[result.action] ?? 403;

    const body = {
        error: status === 401 ? "Unauthorized" : "Forbidden",
        requestId: result.audit.timestamp,
        ...(isDev && {
            debug: {
                blockedByRule: result.blockedByRule,
                totalScore: result.totalScore,
                violations: result.violations.map((v) => ({
                    rule: v.ruleId,
                    type: v.type,
                    message: v.message,
                    score: v.score,
                })),
            },
        }),
    };

    return new NextResponse(JSON.stringify(body), {
        status,
        headers: {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            // Não vaza informação sobre o motivo do bloqueio em produção
            ...(isDev && { "X-Firewall-Rule": result.blockedByRule ?? "unknown" }),
        },
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE WRAPPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrapper completo para uso em Route Handlers e Middleware do Next.js.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { withFirewall } from "@/lib/security/firewallRules";
 *
 * export async function middleware(request: NextRequest) {
 *   return withFirewall(request, () => NextResponse.next(), {
 *     blockedCountries: ["KP", "IR"],
 *     adminPaths: ["/api/admin", "/dashboard/admin"],
 *     blockedPaths: ["/api/internal/*"],
 *     trustedIPs: ["10.0.0.1"],
 *     mode: "enforce",
 *   });
 * }
 *
 * export const config = {
 *   matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
 * };
 * ```
 */
export async function withFirewall(
    request: NextRequest,
    handler: (result: FirewallResult) => NextResponse | Promise<NextResponse>,
    options: FirewallOptions = {}
): Promise<NextResponse> {
    const result = await evaluateFirewall(request, options);

    if (!result.ok) {
        return buildFirewallResponse(result);
    }

    return handler(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// FÁBRICA DE REGRAS CUSTOMIZADAS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Helper tipado para criar regras customizadas com defaults seguros.
 *
 * @example
 * ```ts
 * const myRule = createRule({
 *   id: "CUSTOM-001",
 *   description: "Bloqueia usuários sem plano ativo na API premium",
 *   phase: "request",
 *   priority: 50,
 *   action: "challenge",
 *   score: 50,
 *   match: async (ctx) => {
 *     if (!ctx.pathname.startsWith("/api/premium")) return false;
 *     const token = ctx.headers.get("authorization");
 *     return !token || !(await validatePremiumToken(token));
 *   },
 * });
 * ```
 */
export function createRule(
    rule: Omit<FirewallRule, "enabled"> & { enabled?: boolean }
): FirewallRule {
    return {
        terminal: false,
        enabled: true,
        ...rule,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

export {
    SCANNER_USER_AGENTS,
    LEGITIMATE_BOTS,
    SENSITIVE_PATHS,
    SCAN_PATH_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    REQUEST_SMUGGLING_PATTERNS,
    DEFAULTS as FIREWALL_DEFAULTS,
};