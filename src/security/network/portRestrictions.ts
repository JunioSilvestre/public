/**
 * @fileoverview Middleware de restrição de portas — controle de acesso por porta TCP/HTTP.
 *
 * @description
 * Controla quais portas são permitidas para diferentes tipos de tráfego,
 * detecta tentativas de acesso a portas não autorizadas, e protege contra
 * ataques que exploram serviços expostos em portas inesperadas.
 *
 * ── Responsabilidades ─────────────────────────────────────────────────────
 *  1. Allowlist de portas     — apenas portas explicitamente permitidas
 *  2. Blocklist de portas     — portas proibidas independentemente de origem
 *  3. Portas por ambiente     — dev/staging/prod têm conjuntos diferentes
 *  4. Portas por tipo de IP   — internos vs externos têm acesso diferente
 *  5. Detecção de port scan   — múltiplas portas acessadas pelo mesmo IP
 *  6. Redirecionamento        — porta não-padrão → porta canônica
 *  7. Headers Host/Port       — validação de consistência
 *  8. SSRF via porta          — impede que URLs internas usem portas arbitrárias
 *
 * ── Por que isso importa ──────────────────────────────────────────────────
 *
 *  Na maioria das aplicações, a porta é controlada pelo load balancer /
 *  proxy reverso. Mas em alguns cenários o middleware precisa verificar:
 *
 *  • Apps que rodam em múltiplas portas (admin em :8080, API em :3000)
 *  • Validação do header Host para prevenir host header injection
 *  • Proteção de URLs internas em endpoints de proxy / webhook caller
 *  • Detectar port scanning via padrões de acesso multi-porta
 *  • Ambientes de desenvolvimento que expõem portas extras indevidamente
 *
 * ── Vetores cobertos ──────────────────────────────────────────────────────
 *  • Host header injection via porta              (OWASP 2017 A7)
 *  • SSRF para portas internas via parâmetros URL  (OWASP A10:2021)
 *  • Port scanning via HTTP                        (reconhecimento)
 *  • Acesso a serviços internos via porta exposta  (lateral movement)
 *  • HTTP → HTTPS downgrade via porta 80           (mixed content)
 *  • Acesso a debug ports em produção (:9229 Node) (CVE múltiplos)
 *  • Service fingerprinting via porta default      (reconhecimento)
 *  • Admin interface em porta padrão sem proteção  (Spring Actuator, etc.)
 *  • Bypass de firewall via portas permitidas       (tunneling)
 *  • DNS rebinding combinado com porta interna      (2020+)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • HTTP/3 QUIC (UDP) port validation             (RFC 9000)
 *  • ALPN-based port negotiation                   (TLS 1.3+)
 *  • SNI-based virtual hosting port rules          (emergente)
 *
 * @see https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
 * @see https://portswigger.net/web-security/host-header
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da verificação de porta. */
export interface PortCheckResult {
    allowed: boolean;
    reason?: PortBlockReason;
    /** Porta detectada na requisição. */
    port: number | null;
    /** Porta canônica para redirect (quando reason = 'REDIRECT'). */
    redirectTo?: number;
    /** Protocolo detectado. */
    protocol: 'http' | 'https' | 'unknown';
    meta: PortCheckMeta;
}

export type PortBlockReason =
    | 'PORT_BLOCKED'           // Porta explicitamente bloqueada
    | 'PORT_NOT_ALLOWED'       // Porta não está na allowlist
    | 'PORT_FORBIDDEN_ENV'     // Porta proibida neste ambiente (prod)
    | 'HOST_PORT_MISMATCH'     // Host header tem porta diferente da real
    | 'SSRF_PORT_DETECTED'     // Porta interna detectada em parâmetro URL
    | 'PORT_SCAN_DETECTED'     // Padrão de port scanning detectado
    | 'DEBUG_PORT_BLOCKED'     // Porta de debug bloqueada em produção
    | 'ADMIN_PORT_EXTERNAL'    // Porta admin acessada de IP externo
    | 'HTTP_ON_HTTPS_PORT'     // HTTP em porta HTTPS (ou vice-versa)
    | 'REDIRECT';              // Deve redirecionar para porta canônica

export interface PortCheckMeta {
    ip: string;
    path: string;
    method: string;
    host: string;
    timestamp: number;
    signals: string[];
    environment: Environment;
}

export type Environment = 'development' | 'staging' | 'production' | 'test';

// ─────────────────────────────────────────────────────────────────────────────
// Constantes de porta
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Portas bem conhecidas e suas associações de serviço.
 * Usadas para validação semântica e bloqueio contextual.
 */
export const WELL_KNOWN_PORTS: Record<number, string> = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    143: 'imap',
    389: 'ldap',
    443: 'https',
    445: 'smb',
    465: 'smtps',
    587: 'smtp-submission',
    636: 'ldaps',
    993: 'imaps',
    995: 'pop3s',
    1080: 'socks',
    1433: 'mssql',
    1521: 'oracle',
    2375: 'docker-unencrypted',
    2376: 'docker-tls',
    3000: 'node-default',
    3306: 'mysql',
    3389: 'rdp',
    4200: 'angular-dev',
    4443: 'https-alt',
    5000: 'flask-default',
    5432: 'postgresql',
    5601: 'kibana',
    5672: 'amqp',
    5900: 'vnc',
    6379: 'redis',
    6380: 'redis-tls',
    7474: 'neo4j',
    8000: 'http-alt',
    8008: 'http-alt-2',
    8080: 'http-proxy',
    8081: 'http-proxy-alt',
    8082: 'http-dev',
    8083: 'http-dev-2',
    8084: 'http-dev-3',
    8085: 'http-dev-4',
    8086: 'influxdb',
    8088: 'http-alt-3',
    8090: 'http-alt-4',
    8091: 'couchbase',
    8092: 'couchbase-api',
    8125: 'statsd',
    8161: 'activemq-console',
    8181: 'glassfish',
    8443: 'https-alt',
    8444: 'https-alt-2',
    8500: 'consul',
    8600: 'consul-dns',
    8888: 'jupyter',
    8983: 'solr',
    9000: 'sonarqube',
    9090: 'prometheus',
    9091: 'prometheus-alt',
    9092: 'kafka',
    9200: 'elasticsearch',
    9229: 'node-inspector',  // Node.js debug — NUNCA expor em produção
    9300: 'elasticsearch-transport',
    9418: 'git',
    9999: 'dev-server',
    11211: 'memcached',
    15672: 'rabbitmq-management',
    27017: 'mongodb',
    27018: 'mongodb-shard',
    27019: 'mongodb-config',
    50000: 'jenkins',
};

/**
 * Portas que NUNCA devem ser acessíveis externamente.
 * Acesso a estas portas via Host header é um sinal forte de ataque.
 */
export const ALWAYS_BLOCKED_PORTS: readonly number[] = [
    21,    // FTP — não use em aplicações web
    22,    // SSH — não deve ser acessível via HTTP
    23,    // Telnet — protocolo inseguro
    25,    // SMTP — relay abuse
    53,    // DNS — amplification attacks
    110,   // POP3
    143,   // IMAP
    389,   // LDAP — sem criptografia
    445,   // SMB — ransomware vector
    1433,  // MSSQL
    1521,  // Oracle
    2375,  // Docker API sem TLS — RCE trivial
    3306,  // MySQL
    3389,  // RDP
    4444,  // Metasploit default
    5432,  // PostgreSQL
    5900,  // VNC
    6379,  // Redis (sem auth por padrão)
    9229,  // Node.js inspector — RCE remoto
    11211, // Memcached — amplification
    27017, // MongoDB (sem auth por padrão)
];

/**
 * Portas de debug/desenvolvimento nunca permitidas em produção.
 */
export const DEBUG_PORTS: readonly number[] = [
    9229,  // Node.js --inspect
    9230,  // Node.js --inspect (alternativo)
    5858,  // Node.js legacy debug
    4321,  // Astro dev
    4200,  // Angular CLI
    3001,  // Create React App HMR
    8080,  // Webpack dev server padrão
    8081,  // Expo dev tools
    8082,  // Dev server
    8888,  // Jupyter Notebook
    9000,  // SonarQube / PHP-FPM
    9090,  // Prometheus (não expor externamente)
    9091,  // Prometheus pushgateway
    9200,  // Elasticsearch HTTP
    9300,  // Elasticsearch transport
    5601,  // Kibana
    8161,  // ActiveMQ web console
    15672, // RabbitMQ management
    50000, // Jenkins
];

/**
 * Portas de administração que só devem ser acessíveis internamente.
 */
export const ADMIN_PORTS: readonly number[] = [
    8080,  // Spring Boot Actuator / Tomcat
    8081,  // Admin alt
    8082,  // Admin alt 2
    8443,  // HTTPS admin
    8500,  // Consul UI
    9090,  // Prometheus UI
    9200,  // Elasticsearch
    15672, // RabbitMQ management
];

/**
 * Parâmetros de URL que tipicamente carregam URLs — vetores de SSRF.
 */
export const SSRF_URL_PARAMS: readonly string[] = [
    'url', 'uri', 'target', 'dest', 'destination', 'redirect',
    'redirect_uri', 'redirect_url', 'callback', 'callback_url',
    'return', 'returnTo', 'return_url', 'next', 'to', 'goto',
    'link', 'src', 'source', 'image', 'img', 'icon', 'resource',
    'feed', 'fetch', 'load', 'open', 'file', 'path', 'webhook',
    'notify', 'ping', 'proxy', 'forward', 'host',
];

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface PortConfig {
    /** Porta HTTP padrão. Default: 80 */
    http?: number;
    /** Porta HTTPS padrão. Default: 443 */
    https?: number;
}

export interface PortRestrictionRule {
    /** Portas permitidas. Se vazio, usa ALLOWED_PORTS_BY_ENV. */
    allowedPorts?: number[];
    /** Portas explicitamente bloqueadas (além das ALWAYS_BLOCKED). */
    blockedPorts?: number[];
    /**
     * Porta canônica — requisições em outras portas são redirecionadas aqui.
     * Quando definido, responde com 301 para a porta canônica.
     */
    canonicalPort?: number;
    /** Bloqueia portas de debug em produção. Default: true */
    blockDebugPorts?: boolean;
    /** Portas de administração só acessíveis por IPs internos. Default: [] */
    adminPorts?: number[];
    /** Ranges de IP considerados internos. Default: RFC1918 */
    internalRanges?: string[];
}

export interface PortScanConfig {
    /** Habilita detecção de port scan. Default: true */
    enabled?: boolean;
    /**
     * Número de portas diferentes acessadas por um IP em windowMs
     * para considerar port scan. Default: 5
     */
    threshold?: number;
    /** Janela de tempo em ms. Default: 60_000 */
    windowMs?: number;
}

export interface SSRFPortConfig {
    /** Habilita detecção de SSRF via porta em parâmetros de URL. Default: true */
    enabled?: boolean;
    /**
     * Portas bloqueadas quando encontradas em parâmetros de URL.
     * Default: ALWAYS_BLOCKED_PORTS
     */
    blockedPorts?: number[];
    /** Parâmetros de URL a inspecionar. Default: SSRF_URL_PARAMS */
    urlParams?: string[];
}

export interface PortRestrictionsConfig {
    /**
     * Ambiente atual.
     * Controla qual conjunto de portas é permitido.
     * Default: process.env.NODE_ENV ?? 'development'
     */
    environment?: Environment;

    /** Configuração de portas padrão. */
    ports?: PortConfig;

    /** Regras por ambiente. */
    rules?: Partial<Record<Environment, PortRestrictionRule>>;

    /** Regra padrão (aplicada quando ambiente não tem regra). */
    defaultRule?: PortRestrictionRule;

    /** Configuração de detecção de port scan. */
    portScan?: PortScanConfig;

    /** Configuração de proteção SSRF por porta. */
    ssrf?: SSRFPortConfig;

    /**
     * Validação do header Host.
     * Rejeita requisições onde o Host header contém uma porta não permitida.
     * Default: true
     */
    validateHostHeader?: boolean;

    /**
     * Forçar HTTPS redirecionando portas HTTP para HTTPS.
     * Default: false
     */
    forceHTTPS?: boolean;

    /**
     * IPs que ignoram restrições de porta admin.
     */
    internalIPs?: string[];

    /**
     * Modo dry-run — registra mas não bloqueia.
     * Default: false
     */
    dryRun?: boolean;

    /**
     * Hook chamado quando acesso a porta bloqueada é tentado.
     */
    onBlocked?: (result: PortCheckResult) => void | Promise<void>;

    /**
     * Hook chamado quando port scan é detectado.
     */
    onPortScan?: (ip: string, ports: number[], timestamp: number) => void | Promise<void>;

    /** Store para detecção de port scan (opcional). */
    store?: PortScanStore;

    /** Habilita logging detalhado. Default: false */
    debug?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store para detecção de port scan
// ─────────────────────────────────────────────────────────────────────────────

export interface PortScanStore {
    /** Registra acesso a uma porta por um IP. Retorna o conjunto de portas únicas no período. */
    recordPortAccess(ip: string, port: number, windowMs: number): Promise<number[]>;
}

export class MemoryPortScanStore implements PortScanStore {
    private readonly records = new Map<string, { ports: Set<number>; expiresAt: number }>();
    private readonly interval: ReturnType<typeof setInterval>;

    constructor(cleanupMs = 60_000) {
        this.interval = setInterval(() => {
            const now = Date.now();
            for (const [k, v] of Array.from(this.records.entries())) {
                if (v.expiresAt < now) this.records.delete(k);
            }
        }, cleanupMs);
        if (typeof this.interval.unref === 'function') this.interval.unref();
    }

    async recordPortAccess(ip: string, port: number, windowMs: number): Promise<number[]> {
        const now = Date.now();
        const entry = this.records.get(ip);

        if (!entry || entry.expiresAt < now) {
            this.records.set(ip, { ports: new Set([port]), expiresAt: now + windowMs });
            return [port];
        }

        entry.ports.add(port);
        return Array.from(entry.ports);
    }

    destroy(): void {
        clearInterval(this.interval);
        this.records.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Portas permitidas por ambiente
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_ALLOWED_PORTS: Record<Environment, number[]> = {
    production: [80, 443],
    staging: [80, 443, 8080, 8443],
    test: [80, 443, 3000, 8080],
    development: [
        80, 443, 3000, 3001, 3002, 4000, 4200, 4321,
        5000, 5173, 7000, 8000, 8080, 8081, 8443,
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários internos
// ─────────────────────────────────────────────────────────────────────────────

/** Extrai porta do header Host (host:porta). */
function extractPortFromHost(host: string): number | null {
    const match = host.match(/:(\d+)$/);
    if (!match) return null;
    const port = parseInt(match[1], 10);
    return isNaN(port) ? null : port;
}

/** Extrai porta de uma URL string. */
export function extractPortFromURL(url: string): number | null {
    try {
        const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
        if (parsed.port) return parseInt(parsed.port, 10);
        return parsed.protocol === 'https:' ? 443 : 80;
    } catch {
        // Tenta regex simples
        const match = url.match(/:(\d{1,5})(?:\/|$|\?)/);
        if (!match) return null;
        const port = parseInt(match[1], 10);
        return port > 0 && port <= 65535 ? port : null;
    }
}

/** Verifica se um IP está em um range CIDR. */
function isInternalIP(ip: string, internalRanges: string[]): boolean {
    const defaultRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1'];

    const ranges = internalRanges.length ? internalRanges : defaultRanges;

    for (const range of ranges) {
        if (range === ip) return true;
        if (range === '::1' && ip === '::1') return true;
        if (range.includes('/') && matchesCIDRSimple(ip, range)) return true;
    }
    return false;
}

function matchesCIDRSimple(ip: string, cidr: string): boolean {
    try {
        const [network, prefix] = cidr.split('/');
        const bits = parseInt(prefix, 10);
        const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
        const ipInt = ipToInt(ip);
        const netInt = ipToInt(network);
        return ipInt !== null && netInt !== null && (ipInt & mask) === (netInt & mask);
    } catch {
        return false;
    }
}

function ipToInt(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

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
    if (fwd) { const r = Array.isArray(fwd) ? fwd[0] : fwd; return r.split(',')[0].trim(); }
    return '0.0.0.0';
}

/** Detecta porta na query string ou body para SSRF. */
function detectSSRFPort(
    path: string,
    searchParams?: URLSearchParams,
    body?: unknown,
    urlParams?: readonly string[],
): number | null {
    const params = urlParams ?? SSRF_URL_PARAMS;

    // Verifica query string
    if (searchParams) {
        for (const param of params) {
            const value = searchParams.get(param);
            if (value) {
                const port = extractPortFromURL(value);
                if (port !== null) return port;
            }
        }
    }

    // Verifica body (objeto plano)
    if (body && typeof body === 'object' && !Array.isArray(body)) {
        const obj = body as Record<string, unknown>;
        for (const param of params) {
            const value = obj[param];
            if (typeof value === 'string') {
                const port = extractPortFromURL(value);
                if (port !== null) return port;
            }
        }
    }

    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

/** Requisição normalizada. */
export interface PortCheckRequest {
    ip?: string;
    method: string;
    path: string;
    /** Query string como string ou URLSearchParams. */
    query?: string | URLSearchParams;
    headers: Record<string, string | string[] | undefined>;
    parsedBody?: unknown;
    /** Porta em que o servidor recebeu a requisição (quando disponível). */
    serverPort?: number;
    /** true se a conexão foi recebida via TLS. */
    secure?: boolean;
}

export class PortRestrictions {
    private readonly config: Required<
        Omit<PortRestrictionsConfig, 'onBlocked' | 'onPortScan' | 'store'>
    > & Pick<PortRestrictionsConfig, 'onBlocked' | 'onPortScan' | 'store'>;

    private readonly env: Environment;
    private readonly effectiveRule: PortRestrictionRule;
    private readonly allowedSet: Set<number>;
    private readonly blockedSet: Set<number>;

    constructor(config: PortRestrictionsConfig = {}) {
        const environment = (config.environment
            ?? (process.env['NODE_ENV'] as Environment)
            ?? 'development') as Environment;

        // Monta defaults separados para evitar chave duplicada no object literal.
        const defaults = {
            environment,
            rules: {} as Required<PortRestrictionsConfig>['rules'],
            defaultRule: {} as PortRestrictionRule,
            validateHostHeader: true,
            forceHTTPS: false,
            internalIPs: [] as string[],
            dryRun: false,
            debug: false,
            onBlocked: undefined as PortRestrictionsConfig['onBlocked'],
            onPortScan: undefined as PortRestrictionsConfig['onPortScan'],
            store: undefined as PortRestrictionsConfig['store'],
        };

        this.config = {
            ...defaults,
            ...config,
            // Merge profundo das subconfigs — sempre após o spread para garantir precedência
            ports: { http: 80, https: 443, ...(config.ports ?? {}) },
            portScan: { enabled: true, threshold: 5, windowMs: 60_000, ...(config.portScan ?? {}) },
            ssrf: { enabled: true, ...(config.ssrf ?? {}) },
        };

        this.env = environment;

        // Monta a regra efetiva: defaultRule + regra do ambiente
        const envRule = this.config.rules?.[environment] ?? {};
        const baseRule = this.config.defaultRule ?? {};

        this.effectiveRule = {
            allowedPorts: envRule.allowedPorts ?? baseRule.allowedPorts ?? DEFAULT_ALLOWED_PORTS[environment],
            blockedPorts: envRule.blockedPorts ?? baseRule.blockedPorts ?? [],
            canonicalPort: envRule.canonicalPort ?? baseRule.canonicalPort,
            blockDebugPorts: envRule.blockDebugPorts ?? baseRule.blockDebugPorts ?? (environment === 'production'),
            adminPorts: envRule.adminPorts ?? baseRule.adminPorts ?? [],
            internalRanges: envRule.internalRanges ?? baseRule.internalRanges ?? [],
        };

        // Pre-compila Sets para lookup O(1)
        this.allowedSet = new Set(this.effectiveRule.allowedPorts ?? []);
        this.blockedSet = new Set([
            ...Array.from(ALWAYS_BLOCKED_PORTS),
            ...(this.effectiveRule.blockedPorts ?? []),
            ...(this.effectiveRule.blockDebugPorts ? Array.from(DEBUG_PORTS) : []),
        ]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verificação principal
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica se a porta da requisição é permitida.
     */
    async check(req: PortCheckRequest): Promise<PortCheckResult> {
        const ip = req.ip ?? extractIP(req.headers);
        const path = req.path;
        const method = req.method.toUpperCase();
        const now = Date.now();
        const signals: string[] = [];

        // Detecta protocolo
        const proto = this.detectProtocol(req);

        // Detecta porta
        const port = this.detectPort(req);

        const meta: PortCheckMeta = {
            ip, path, method, timestamp: now, signals,
            host: getHeader(req.headers, 'host') ?? '',
            environment: this.env,
        };

        const block = (reason: PortBlockReason, redirectTo?: number): PortCheckResult => {
            const result: PortCheckResult = {
                allowed: this.config.dryRun,
                reason,
                port,
                redirectTo,
                protocol: proto,
                meta,
            };
            void this.config.onBlocked?.(result);
            this.debugLog(this.config.dryRun ? 'DRY-RUN' : 'BLOCKED', reason, port, ip, path);
            return result;
        };

        // ── 1. Forçar HTTPS ───────────────────────────────────────────────
        if (this.config.forceHTTPS && proto === 'http' && port === this.config.ports.http) {
            signals.push('http-to-https-redirect');
            return block('REDIRECT', this.config.ports.https);
        }

        // ── 2. Porta na blocklist imediata ────────────────────────────────
        if (port !== null && this.blockedSet.has(port)) {
            signals.push(`blocked-port:${port}`);

            const isDebug = Array.from(DEBUG_PORTS).includes(port);
            const reason = isDebug ? 'DEBUG_PORT_BLOCKED' : 'PORT_BLOCKED';

            return block(reason);
        }

        // ── 3. Porta de admin acessada externamente ────────────────────────
        if (port !== null && this.effectiveRule.adminPorts?.includes(port)) {
            const isInternal = isInternalIP(ip, [
                ...this.config.internalIPs,
                ...(this.effectiveRule.internalRanges ?? []),
            ]);

            if (!isInternal) {
                signals.push(`admin-port-external:${port}`);
                return block('ADMIN_PORT_EXTERNAL');
            }
        }

        // ── 4. Verificação de allowlist ───────────────────────────────────
        if (port !== null && this.allowedSet.size > 0 && !this.allowedSet.has(port)) {
            signals.push(`port-not-allowed:${port}`);
            const reason = this.env === 'production' ? 'PORT_FORBIDDEN_ENV' : 'PORT_NOT_ALLOWED';

            // Redireciona para porta canônica se configurado
            if (this.effectiveRule.canonicalPort) {
                return block('REDIRECT', this.effectiveRule.canonicalPort);
            }

            return block(reason);
        }

        // ── 5. Validação do header Host ────────────────────────────────────
        if (this.config.validateHostHeader) {
            const hostResult = this.validateHostHeader(req.headers, port, proto);
            if (hostResult) {
                signals.push(`host-port-mismatch:${hostResult}`);
                return block('HOST_PORT_MISMATCH');
            }
        }

        // ── 6. Detecção de SSRF via parâmetros de URL ─────────────────────
        if (this.config.ssrf?.enabled) {
            const ssrfResult = this.checkSSRF(path, req.query, req.parsedBody);
            if (ssrfResult !== null) {
                signals.push(`ssrf-port:${ssrfResult}`);
                return block('SSRF_PORT_DETECTED');
            }
        }

        // ── 7. Detecção de port scan ──────────────────────────────────────
        if (this.config.portScan?.enabled && port !== null && this.config.store) {
            const scanResult = await this.detectPortScan(ip, port);
            if (scanResult) {
                signals.push(`port-scan:${scanResult.join(',')}`);
                void this.config.onPortScan?.(ip, scanResult, now);
                return block('PORT_SCAN_DETECTED');
            }
        }

        return {
            allowed: true,
            port,
            protocol: proto,
            meta,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilitários privados
    // ─────────────────────────────────────────────────────────────────────────

    private detectProtocol(req: PortCheckRequest): 'http' | 'https' | 'unknown' {
        if (req.secure === true) return 'https';
        if (req.secure === false) return 'http';

        const fwdProto = getHeader(req.headers, 'x-forwarded-proto');
        if (fwdProto === 'https') return 'https';
        if (fwdProto === 'http') return 'http';

        const cfVisitor = getHeader(req.headers, 'cf-visitor');
        if (cfVisitor) {
            try {
                const parsed = JSON.parse(cfVisitor) as { scheme?: string };
                if (parsed.scheme === 'https') return 'https';
                if (parsed.scheme === 'http') return 'http';
            } catch { /* ignora */ }
        }

        const port = this.detectPort(req);
        if (port === 443 || port === 8443) return 'https';
        if (port === 80) return 'http';

        return 'unknown';
    }

    private detectPort(req: PortCheckRequest): number | null {
        // Porta explícita da conexão (mais confiável)
        if (req.serverPort !== undefined) return req.serverPort;

        // Porta no header Host
        const host = getHeader(req.headers, 'host') ?? '';
        const hostPort = extractPortFromHost(host);
        if (hostPort !== null) return hostPort;

        // Porta no header X-Forwarded-Port
        const fwdPort = getHeader(req.headers, 'x-forwarded-port');
        if (fwdPort) {
            const p = parseInt(fwdPort, 10);
            if (!isNaN(p) && p > 0 && p <= 65535) return p;
        }

        // Inferida pelo protocolo
        const proto = this.detectProtocol(req);
        if (proto === 'https') return 443;
        if (proto === 'http') return 80;

        return null;
    }

    private validateHostHeader(
        headers: Record<string, string | string[] | undefined>,
        detectedPort: number | null,
        proto: 'http' | 'https' | 'unknown',
    ): string | null {
        const host = getHeader(headers, 'host');
        if (!host) return null;

        const hostPort = extractPortFromHost(host);

        // Se o host tem porta explícita, ela deve coincidir com a porta detectada
        if (hostPort !== null && detectedPort !== null && hostPort !== detectedPort) {
            return `host=${hostPort} != detected=${detectedPort}`;
        }

        // Porta HTTPS em conexão HTTP (ou vice-versa)
        if (proto === 'http' && hostPort === 443) return 'http-on-https-port';
        if (proto === 'https' && hostPort === 80) return 'https-on-http-port';

        // Porta na blocklist detectada via Host header (SSRF / Host Injection)
        if (hostPort !== null && this.blockedSet.has(hostPort)) {
            return `blocked-port-in-host:${hostPort}`;
        }

        return null;
    }

    private checkSSRF(
        path: string,
        query?: string | URLSearchParams,
        body?: unknown,
    ): number | null {
        const blockedPorts = this.config.ssrf?.blockedPorts ?? Array.from(ALWAYS_BLOCKED_PORTS);
        const urlParams = this.config.ssrf?.urlParams ?? SSRF_URL_PARAMS;

        let searchParams: URLSearchParams | undefined;
        if (query instanceof URLSearchParams) {
            searchParams = query;
        } else if (typeof query === 'string') {
            try { searchParams = new URLSearchParams(query); } catch { /* ignora */ }
        } else {
            // Extrai query string do path
            const qIdx = path.indexOf('?');
            if (qIdx !== -1) {
                try { searchParams = new URLSearchParams(path.slice(qIdx + 1)); } catch { /* ignora */ }
            }
        }

        const port = detectSSRFPort(path, searchParams, body, urlParams);
        if (port === null) return null;
        if (blockedPorts.includes(port)) return port;

        // Também verifica portas de serviços internos não listadas na blocklist
        if (this.blockedSet.has(port)) return port;

        return null;
    }

    private async detectPortScan(
        ip: string,
        port: number,
    ): Promise<number[] | null> {
        if (!this.config.store || !this.config.portScan?.enabled) return null;

        const { threshold = 5, windowMs = 60_000 } = this.config.portScan;
        const ports = await this.config.store.recordPortAccess(ip, port, windowMs);

        if (ports.length >= threshold) {
            this.debugLog('PORT-SCAN', ip, ports);
            return ports;
        }

        return null;
    }

    /**
     * Verifica se uma URL em parâmetro é segura (sem porta bloqueada).
     * Use para validar parâmetros de URL antes de fazer fetch.
     *
     * @example
     * const webhookURL = req.body.webhook_url;
     * if (!portRestrictions.isSafeURL(webhookURL)) {
     *   return res.status(400).json({ error: 'Unsafe URL port' });
     * }
     */
    isSafeURL(url: string): boolean {
        const port = extractPortFromURL(url);
        if (port === null) return true;
        return !this.blockedSet.has(port);
    }

    /**
     * Retorna o conjunto de portas permitidas para o ambiente atual.
     */
    getAllowedPorts(): number[] {
        return Array.from(this.allowedSet);
    }

    /**
     * Retorna o conjunto de portas bloqueadas (incluindo debug/sistema).
     */
    getBlockedPorts(): number[] {
        return Array.from(this.blockedSet);
    }

    /**
     * Retorna a descrição de serviço para uma porta.
     */
    getPortService(port: number): string {
        return WELL_KNOWN_PORTS[port] ?? 'unknown';
    }

    private debugLog(event: string, ...args: unknown[]): void {
        if (!this.config.debug) return;
        console.debug('[port-restrictions]', event, ...args);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

type ExpressReq = {
    ip?: string; method: string; path: string; query: Record<string, unknown>;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown; socket?: { localPort?: number; encrypted?: boolean };
};
type ExpressRes = {
    status(n: number): ExpressRes;
    set(h: Record<string, string>): ExpressRes;
    redirect(code: number, url: string): void;
    json(d: unknown): void;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware de restrição de portas para Express.
 *
 * @example
 * const restrictions = createPortRestrictions();
 * app.use(createExpressPortRestrictions(restrictions));
 */
export function createExpressPortRestrictions(pr: PortRestrictions) {
    return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
        const result = await pr.check({
            ip: req.ip,
            method: req.method,
            path: req.path,
            headers: req.headers,
            parsedBody: req.body,
            serverPort: req.socket?.localPort,
            secure: req.socket?.encrypted,
        });

        if (!result.allowed) {
            if (result.reason === 'REDIRECT' && result.redirectTo) {
                const host = (getHeader(req.headers, 'host') ?? '').split(':')[0];
                const proto = result.protocol === 'https' ? 'https' : 'http';
                res.redirect(301, `${proto}://${host}:${result.redirectTo}${req.path}`);
                return;
            }

            res.status(403).set({
                'Content-Type': 'application/json',
                'X-Content-Type-Options': 'nosniff',
                'Cache-Control': 'no-store',
            }).json({ error: 'Forbidden', message: 'Port access denied.' });
            return;
        }

        next();
    };
}

/**
 * Handler de restrição de portas para Next.js Edge Runtime.
 */
export function createNextPortRestrictions(pr: PortRestrictions) {
    return async (request: Request): Promise<Response | null> => {
        const headers: Record<string, string> = {};
        request.headers.forEach((v, k) => { headers[k] = v; });

        const url = new URL(request.url);
        const result = await pr.check({
            method: request.method,
            path: url.pathname,
            query: url.searchParams,
            headers,
            secure: url.protocol === 'https:',
            serverPort: url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80),
        });

        if (!result.allowed) {
            if (result.reason === 'REDIRECT' && result.redirectTo) {
                const redirectURL = `${url.protocol}//${url.hostname}:${result.redirectTo}${url.pathname}${url.search}`;
                return Response.redirect(redirectURL, 301);
            }

            return new Response(
                JSON.stringify({ error: 'Forbidden', message: 'Port access denied.' }),
                { status: 403, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } },
            );
        }

        return null;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factories
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria instância com configuração padrão baseada no NODE_ENV.
 *
 * @example
 * const pr = createPortRestrictions();
 * app.use(createExpressPortRestrictions(pr));
 */
export function createPortRestrictions(
    overrides: Partial<PortRestrictionsConfig> = {},
): PortRestrictions {
    return new PortRestrictions(overrides);
}

/**
 * Configuração estrita para produção:
 * - Apenas 80 e 443
 * - Debug ports bloqueadas
 * - SSRF habilitado
 * - Forçar HTTPS
 *
 * @example
 * const pr = createProductionPortRestrictions({ forceHTTPS: true });
 */
export function createProductionPortRestrictions(
    overrides: Partial<PortRestrictionsConfig> = {},
): PortRestrictions {
    return new PortRestrictions({
        environment: 'production',
        forceHTTPS: true,
        validateHostHeader: true,
        defaultRule: {
            allowedPorts: [80, 443],
            blockDebugPorts: true,
            adminPorts: Array.from(ADMIN_PORTS),
        },
        portScan: { enabled: true, threshold: 3, windowMs: 60_000 },
        ssrf: { enabled: true },
        store: new MemoryPortScanStore(),
        ...overrides,
    });
}

/**
 * Configuração permissiva para desenvolvimento local.
 *
 * @example
 * const pr = createDevelopmentPortRestrictions();
 */
export function createDevelopmentPortRestrictions(): PortRestrictions {
    return new PortRestrictions({
        environment: 'development',
        forceHTTPS: false,
        validateHostHeader: false,
        defaultRule: {
            allowedPorts: DEFAULT_ALLOWED_PORTS.development,
            blockDebugPorts: false,
        },
        portScan: { enabled: false },
        ssrf: { enabled: true },
        debug: true,
    });
}

/**
 * Validador de URL para uso em endpoints que aceitam URLs externas.
 * Retorna true se a URL não contém porta bloqueada.
 *
 * @example
 * const validator = createURLPortValidator();
 * if (!validator('https://evil.com:22/shell')) {
 *   return res.status(400).json({ error: 'URL inválida' });
 * }
 */
export function createURLPortValidator(
    blockedPorts: readonly number[] = ALWAYS_BLOCKED_PORTS,
): (url: string) => boolean {
    const blockedSet = new Set(blockedPorts);
    return (url: string): boolean => {
        const port = extractPortFromURL(url);
        if (port === null) return true;
        return !blockedSet.has(port);
    };
}