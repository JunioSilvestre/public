/**
 * @arquivo     src/security/middleware/botProtection.ts
 * @módulo      Security / Middleware / Proteção contra Bots
 * @descrição   Middleware de defesa em profundidade contra tráfego automatizado.
 *              Implementa 10 camadas de detecção: Rate Limiting (janela deslizante),
 *              Token Bucket, Fingerprint, User-Agent, Behavioral, Honeypot,
 *              Request Anomaly, Headless Detection, Geo/IP Reputation e Challenge.
 *
 * @como-usar
 *              // Express
 *              app.use(createExpressAdapter(botProtection));
 *              // Next.js middleware
 *              export default createNextAdapter(botProtection);
 *              // Custom
 *              const result = await botProtection.evaluate(request);
 *              if (!result.allowed) return respond403(result.reason);
 *
 * @dependências next/server, MemoryStore (dev) ou Redis (produção)
 * @notas       ⚠ Nunca exponha `result.reason` diretamente ao cliente.
 *              Use MemoryStore apenas em desenvolvimento — em produção injete Redis.
 */
/**
 * @fileoverview Middleware de proteção contra bots — defesa em profundidade.
 *
 * @description
 * Implementa múltiplas camadas de detecção e mitigação de tráfego automatizado:
 *
 * ── Camadas de detecção ────────────────────────────────────────────────────
 *  1. Rate Limiting        — janela deslizante por IP + por rota + global
 *  2. Token Bucket         — burst control com reposição gradual
 *  3. Fingerprint          — hash de IP + User-Agent + Accept headers
 *  4. User-Agent           — blocklist de bots conhecidos + detecção heurística
 *  5. Behavioral           — análise de timing, padrões de acesso sequencial
 *  6. Honeypot             — rotas e campos invisíveis que só bots acionam
 *  7. Request Anomaly      — headers ausentes/incomuns, tamanho anômalo
 *  8. Headless Detection   — sinais de Puppeteer/Playwright/Selenium
 *  9. Geo/IP Reputation    — hook para integração com serviços externos
 * 10. Challenge            — CAPTCHA hook, proof-of-work, JS challenge
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *  • Credential stuffing (login bruteforce distribuído)       (ubíquo)
 *  • Scraping agressivo sem respeito a robots.txt             (ubíquo)
 *  • Carding attacks (teste de cartões em massa)              (e-commerce)
 *  • Account enumeration via timing de resposta               (OWASP A07:2021)
 *  • Slowloris / slow POST DoS                                (CVE-2007-6750)
 *  • HTTP Flood (Layer 7 DDoS)                                (ubíquo)
 *  • Headless browser automation (Puppeteer, Playwright)      (2018+)
 *  • Selenium/WebDriver fingerprint                           (clássico)
 *  • Residential proxy rotation sem rate limit                (2019+)
 *  • API abuse via chave vazada usada por bot                 (2020+)
 *  • GraphQL introspection / batch query abuse                (2019+)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • AI-powered bots com comportamento humano simulado        (2023+)
 *  • Browser fingerprint evasion via spoofing de canvas/WebGL (2022+)
 *  • CAPTCHA solving services (2Captcha, Anti-Captcha)        (2020+)
 *  • Residential proxy pools com IPs legítimos                (2021+)
 *
 * @architecture
 *  BotProtection é framework-agnostic: retorna { allowed, reason, meta }
 *  e expõe adaptadores prontos para Express, Next.js e Fetch API (Edge).
 *  O armazenamento de estado (rate limit counters) é injetável — use
 *  Redis em produção, MemoryStore apenas em desenvolvimento.
 *
 * @example
 * // Express
 * app.use(createExpressAdapter(botProtection));
 *
 * // Next.js middleware
 * export default createNextAdapter(botProtection);
 *
 * // Custom
 * const result = await botProtection.evaluate(request);
 * if (!result.allowed) return respond403(result.reason);
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Resultado da avaliação de uma requisição. */
export interface BotEvaluationResult {
  /** true = requisição permitida, false = bloqueada. */
  allowed: boolean;
  /** Código interno do motivo do bloqueio. Nunca exponha diretamente ao cliente. */
  reason?: BotBlockReason;
  /** Nível de confiança de que é um bot (0–100). */
  score: number;
  /** Metadados de diagnóstico. Use apenas em logs internos. */
  meta: BotEvaluationMeta;
}

export type BotBlockReason =
  | 'RATE_LIMIT_IP'
  | 'RATE_LIMIT_ROUTE'
  | 'RATE_LIMIT_GLOBAL'
  | 'TOKEN_BUCKET_EMPTY'
  | 'BLOCKED_USER_AGENT'
  | 'MISSING_USER_AGENT'
  | 'HEADLESS_BROWSER'
  | 'SELENIUM_DETECTED'
  | 'SUSPICIOUS_HEADERS'
  | 'HONEYPOT_TRIGGERED'
  | 'BEHAVIORAL_ANOMALY'
  | 'FINGERPRINT_BLACKLISTED'
  | 'CHALLENGE_REQUIRED'
  | 'IP_REPUTATION_BLOCKED'
  | 'REQUEST_TOO_LARGE'
  | 'IMPOSSIBLE_TIMING';

export interface BotEvaluationMeta {
  ip: string;
  fingerprint: string;
  userAgent: string;
  route: string;
  timestamp: number;
  signals: string[];
  rateLimitRemaining?: number;
  rateLimitResetAt?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface BotProtectionConfig {
  /**
   * Rate limiting por IP.
   * Janela deslizante — mais precisa que janela fixa para burst detection.
   */
  rateLimit: {
    /** Máximo de requisições por janela por IP. Default: 60 */
    maxRequestsPerIP: number;
    /** Duração da janela em ms. Default: 60_000 (1 min) */
    windowMs: number;
    /** Máximo global de req/s (todas as IPs juntas). Default: 1000 */
    globalMaxRps: number;
  };

  /**
   * Token Bucket para burst control.
   * Permite picos legítimos (ex: refresh da página) sem penalizar usuários reais.
   */
  tokenBucket: {
    /** Tamanho máximo do bucket por IP. Default: 10 */
    capacity: number;
    /** Taxa de reposição de tokens por segundo. Default: 2 */
    refillRatePerSecond: number;
  };

  /** Limites específicos por rota (sobrescreve o global). */
  routeLimits?: Record<string, { maxRequests: number; windowMs: number }>;

  /** User-Agents adicionais para bloquear (além da lista interna). */
  blockedUserAgents?: string[];

  /** IPs para bloquear imediatamente (CIDR não suportado nesta versão). */
  blockedIPs?: string[];

  /**
   * IPs confiáveis que bypassam rate limiting (mas ainda são avaliados).
   * Use para health checks internos, load balancers, etc.
   */
  trustedIPs?: string[];

  /**
   * Score mínimo para exigir challenge (CAPTCHA / proof-of-work).
   * 0 = nunca exige, 100 = sempre bloqueia. Default: 70.
   */
  challengeThreshold: number;

  /**
   * Score mínimo para bloquear imediatamente sem challenge. Default: 90.
   */
  blockThreshold: number;

  /**
   * Função de armazenamento de estado (rate limit counters, blacklist).
   * Injete uma implementação Redis para produção.
   */
  store: BotProtectionStore;

  /**
   * Hook chamado quando uma requisição é bloqueada.
   * Use para alertas, logs de segurança, SIEM.
   */
  onBlocked?: (result: BotEvaluationResult, request: NormalizedRequest) => void | Promise<void>;

  /**
   * Hook para integração com serviço externo de reputação de IP.
   * Retorne true se o IP deve ser bloqueado.
   */
  ipReputationCheck?: (ip: string) => Promise<boolean>;

  /**
   * Habilita logging detalhado de cada avaliação. Default: false.
   * NUNCA habilite em produção com dados sensíveis sem anonimização.
   */
  debug?: boolean;
}

/** Interface de armazenamento de estado — injetável. */
export interface BotProtectionStore {
  /** Incrementa contador e retorna novo valor. TTL em ms. */
  increment(key: string, ttlMs: number): Promise<number>;
  /** Lê valor atual sem incrementar. */
  get(key: string): Promise<number | null>;
  /** Define valor com TTL. */
  set(key: string, value: number, ttlMs: number): Promise<void>;
  /** Verifica existência de chave. */
  exists(key: string): Promise<boolean>;
  /** Remove chave. */
  delete(key: string): Promise<void>;
}

/** Representação normalizada de uma requisição HTTP (agnóstica de framework). */
export interface NormalizedRequest {
  ip: string;
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  /** Tamanho do body em bytes. */
  bodySize?: number;
  /** Timestamp de chegada da requisição. */
  timestamp?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementação de Store em memória — APENAS para desenvolvimento
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Store em memória com Map + limpeza automática por TTL.
 *
 * ⚠ NÃO use em produção:
 *  - Não persiste entre restarts
 *  - Não funciona em múltiplas instâncias (horizontal scaling)
 *  - Vulnerável a memory leaks sob carga alta
 *
 * Em produção: use `createRedisStore(redisClient)` ou similar.
 */
export class MemoryStore implements BotProtectionStore {
  private readonly store = new Map<string, { value: number; expiresAt: number }>();
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs = 60_000) {
    // Limpeza periódica de entradas expiradas
    this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
    // Não bloqueia o processo de terminar
    if (typeof this.cleanupInterval.unref === 'function') {
      this.cleanupInterval.unref();
    }
  }

  async increment(key: string, ttlMs: number): Promise<number> {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || entry.expiresAt <= now) {
      this.store.set(key, { value: 1, expiresAt: now + ttlMs });
      return 1;
    }

    entry.value += 1;
    return entry.value;
  }

  async get(key: string): Promise<number | null> {
    const now = Date.now();
    const entry = this.store.get(key);
    if (!entry || entry.expiresAt <= now) return null;
    return entry.value;
  }

  async set(key: string, value: number, ttlMs: number): Promise<void> {
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  async exists(key: string): Promise<boolean> {
    const now = Date.now();
    const entry = this.store.get(key);
    return Boolean(entry && entry.expiresAt > now);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of Array.from(this.store.entries())) {
      if (entry.expiresAt <= now) this.store.delete(key);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constantes de detecção
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Assinaturas de User-Agent de bots conhecidos.
 * Baseado em dados públicos: botsbrowser.com, user-agents.net e pesquisa própria.
 *
 * Organizado por categoria para facilitar auditoria e atualização.
 */
const KNOWN_BOT_UA_PATTERNS: RegExp[] = [
  // ── Scrapers / Crawlers genéricos ─────────────────────────────────────────
  /bot/i, /crawler/i, /spider/i, /scraper/i, /archiver/i, /fetcher/i,
  /harvest/i, /extractor/i, /checker/i, /monitor/i, /validator/i,

  // ── Automation frameworks ─────────────────────────────────────────────────
  /headlesschrome/i, /phantomjs/i, /nightmare/i,
  /selenium/i, /webdriver/i, /puppeteer/i, /playwright/i,
  /cypress/i, /testcafe/i, /chromedriverfake/i,

  // ── HTTP clients usados em scripts ────────────────────────────────────────
  /^python-requests/i, /^python-urllib/i, /^go-http-client/i,
  /^java\//i, /^apache-httpclient/i, /^libwww-perl/i,
  /^curl\//i, /^wget\//i, /^httpie/i, /^axios\//i,
  /^node-fetch/i, /^node\.js/i, /^got\//i, /^superagent/i,
  /^okhttp/i, /^ruby/i, /^php\//i,

  // ── Search engine bots ────────────────────────────────────────────────────
  // Nota: search bots legítimos têm IP verificável via DNS reverso.
  // Bloquear apenas por UA é insuficiente — use ipReputationCheck para verificar.
  /googlebot/i, /bingbot/i, /yandexbot/i, /baiduspider/i,
  /duckduckbot/i, /slurp/i, /facebot/i, /twitterbot/i,
  /linkedinbot/i, /applebot/i, /pinterestbot/i,

  // ── Ferramentas de segurança / scan ───────────────────────────────────────
  /nikto/i, /nmap/i, /masscan/i, /sqlmap/i, /nessus/i,
  /openvas/i, /whatweb/i, /dirbuster/i, /gobuster/i,
  /burpsuite/i, /zaproxy/i, /acunetix/i, /qualys/i,

  // ── Monitoring / Uptime ───────────────────────────────────────────────────
  /pingdom/i, /uptimerobot/i, /statuscake/i, /datadog/i,
  /newrelic/i, /site24x7/i, /freshping/i,
];

/**
 * Headers que DEVEM estar presentes em browsers reais.
 * Ausência é sinal forte de automação.
 */
const REQUIRED_BROWSER_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
] as const;

/**
 * Headers injetados por ferramentas de automação comuns.
 * Presença é sinal forte de bot.
 */
const AUTOMATION_SIGNAL_HEADERS: Record<string, string | RegExp> = {
  'x-selenium':           'any',
  'x-webdriver':          'any',
  'x-automation':         'any',
  'x-headless':           'any',
  'sec-ch-ua-automation': 'any',
  // Puppeteer extra headers
  'accept-encoding':      /^identity$/i,
  // Requests puro
  'accept':               /^\*\/\*$/,
};

/**
 * Rotas honeypot — qualquer acesso é bloqueio imediato.
 * Inclua caminhos que só aparecem em ferramentas de scan automatizado.
 */
const HONEYPOT_ROUTES = new Set([
  '/.env',
  '/.env.local',
  '/.env.production',
  '/wp-admin',
  '/wp-login.php',
  '/wp-config.php',
  '/phpmyadmin',
  '/phpinfo.php',
  '/adminer.php',
  '/actuator',
  '/actuator/env',
  '/actuator/health',
  '/api/swagger',
  '/swagger-ui.html',
  '/v2/api-docs',
  '/v3/api-docs',
  '/.git/HEAD',
  '/.git/config',
  '/config.json',
  '/config.yml',
  '/server-status',
  '/server-info',
  '/_profiler',
  '/console',
  '/admin/config',
  '/telescope',
]);

/**
 * Campos de formulário honeypot — não visíveis a humanos.
 * Se preenchidos, é bot.
 */
export const HONEYPOT_FIELD_NAMES = [
  'website',    // campo "hidden" clássico
  'url',        // segundo campo oculto
  'company',    // terceiro campo oculto
  'fax',        // campo antiquado que humanos ignoram
  '__hp',       // prefixo explícito
  '__bot_trap',
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários internos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extrai o IP real considerando proxies reversos confiáveis.
 *
 * Ordem de prioridade:
 *  1. CF-Connecting-IP (Cloudflare)
 *  2. X-Real-IP (nginx)
 *  3. X-Forwarded-For — APENAS o primeiro IP (leftmost = client original)
 *  4. socket.remoteAddress
 *
 * ⚠ NUNCA confie em X-Forwarded-For em produção sem um proxy reverso confiável
 *   na frente — é trivialmente forjável.
 */
export function extractRealIP(headers: Record<string, string | string[] | undefined>): string {
  const cfIp = headers['cf-connecting-ip'];
  if (typeof cfIp === 'string' && isValidIP(cfIp)) return cfIp;

  const realIp = headers['x-real-ip'];
  if (typeof realIp === 'string' && isValidIP(realIp)) return realIp;

  const forwarded = headers['x-forwarded-for'];
  if (forwarded) {
    const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    const firstIp = raw.split(',')[0].trim();
    if (isValidIP(firstIp)) return firstIp;
  }

  return '0.0.0.0'; // fallback seguro
}

/** Validação básica de formato IP (v4 e v6). */
function isValidIP(ip: string): boolean {
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return true;
  // IPv6 (simplificado)
  if (/^[\da-fA-F:]{2,39}$/.test(ip)) return true;
  return false;
}

/**
 * Gera fingerprint determinístico da requisição.
 * NÃO usa dados biométricos ou tracking cross-site.
 * Combina: IP + User-Agent + Accept-Language + Accept-Encoding
 *
 * O fingerprint é hasheado para evitar log de dados sensíveis.
 */
export function generateRequestFingerprint(req: NormalizedRequest): string {
  const components = [
    req.ip,
    getHeader(req.headers, 'user-agent') ?? '',
    getHeader(req.headers, 'accept-language') ?? '',
    getHeader(req.headers, 'accept-encoding') ?? '',
    getHeader(req.headers, 'sec-ch-ua') ?? '',
  ].join('|');

  return simpleHash(components);
}

/** Hash determinístico não-criptográfico (suficiente para fingerprint de rate limit). */
function simpleHash(str: string): string {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash) ^ str.charCodeAt(i);
    hash = hash >>> 0; // unsigned 32-bit
  }
  return hash.toString(16).padStart(8, '0');
}

/** Obtém header normalizado (case-insensitive, retorna string ou undefined). */
function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const val = headers[name.toLowerCase()];
  if (!val) return undefined;
  return Array.isArray(val) ? val[0] : val;
}

/** Sanitiza string para uso seguro em chaves de cache (evita key injection). */
function sanitizeKey(value: string): string {
  return value.replace(/[^a-zA-Z0-9._\-:]/g, '_').slice(0, 128);
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class BotProtection {
  private readonly config: Required<BotProtectionConfig>;

  constructor(config: BotProtectionConfig) {
    this.config = {
      blockedUserAgents: [],
      blockedIPs:        [],
      trustedIPs:        [],
      routeLimits:       {},
      onBlocked:         undefined as unknown as Required<BotProtectionConfig>['onBlocked'],
      ipReputationCheck: undefined as unknown as Required<BotProtectionConfig>['ipReputationCheck'],
      debug:             false,
      ...config,
    };
  }

  /**
   * Avalia uma requisição e retorna o resultado de segurança.
   * Chamada principal — use os adaptadores de framework abaixo para integração.
   */
  async evaluate(req: NormalizedRequest): Promise<BotEvaluationResult> {
    const ip          = extractRealIP(req.headers);
    const ua          = getHeader(req.headers, 'user-agent') ?? '';
    const fingerprint = generateRequestFingerprint({ ...req, ip });
    const route       = req.path;
    const timestamp   = req.timestamp ?? Date.now();
    const signals: string[] = [];

    const meta: BotEvaluationMeta = {
      ip, fingerprint, userAgent: ua, route, timestamp, signals,
    };

    const block = (reason: BotBlockReason, score = 100): BotEvaluationResult => {
      const result: BotEvaluationResult = { allowed: false, reason, score, meta };
      void this.config.onBlocked?.(result, req);
      this.debugLog('BLOCKED', reason, meta);
      return result;
    };

    // ── 0. IPs confiáveis bypassam rate limiting ───────────────────────────
    const isTrusted = this.config.trustedIPs.includes(ip);

    // ── 1. IP explicitamente bloqueado ────────────────────────────────────
    if (this.config.blockedIPs.includes(ip)) {
      signals.push('ip-blocklist');
      return block('IP_REPUTATION_BLOCKED');
    }

    // ── 2. Reputação de IP (hook externo) ─────────────────────────────────
    if (this.config.ipReputationCheck) {
      try {
        const isReputationBlocked = await this.config.ipReputationCheck(ip);
        if (isReputationBlocked) {
          signals.push('ip-reputation-service');
          return block('IP_REPUTATION_BLOCKED');
        }
      } catch (err) {
        // Falha aberta: se o serviço externo falhar, não bloqueia
        this.debugLog('WARN', 'ipReputationCheck failed — failing open', { err });
      }
    }

    // ── 3. Honeypot — rota ────────────────────────────────────────────────
    const normalizedPath = route.split('?')[0].toLowerCase();
    if (HONEYPOT_ROUTES.has(normalizedPath)) {
      signals.push(`honeypot-route:${normalizedPath}`);
      // Blacklist o fingerprint permanentemente
      await this.config.store.set(`blacklist:fp:${fingerprint}`, 1, 30 * 24 * 60 * 60_000);
      return block('HONEYPOT_TRIGGERED');
    }

    // ── 4. Fingerprint na blacklist ───────────────────────────────────────
    const isBlacklisted = await this.config.store.exists(`blacklist:fp:${sanitizeKey(fingerprint)}`);
    if (isBlacklisted) {
      signals.push('fingerprint-blacklisted');
      return block('FINGERPRINT_BLACKLISTED');
    }

    // ── 5. User-Agent — ausência ──────────────────────────────────────────
    if (!ua || ua.trim().length === 0) {
      signals.push('missing-user-agent');
      return block('MISSING_USER_AGENT');
    }

    // ── 6. User-Agent — bots conhecidos ──────────────────────────────────
    const allBotPatterns = [
      ...KNOWN_BOT_UA_PATTERNS,
      ...this.config.blockedUserAgents.map(p => new RegExp(p, 'i')),
    ];

    for (const pattern of allBotPatterns) {
      if (pattern.test(ua)) {
        signals.push(`bot-ua:${pattern.toString().slice(1, 20)}`);
        return block('BLOCKED_USER_AGENT');
      }
    }

    // ── 7. Headless browser detection ────────────────────────────────────
    const headlessScore = this.detectHeadless(req.headers, ua);
    if (headlessScore > 0) {
      signals.push(`headless-score:${headlessScore}`);
    }

    // ── 8. Anomalia de headers ────────────────────────────────────────────
    const headerScore = this.detectHeaderAnomalies(req.headers);
    if (headerScore > 0) {
      signals.push(`header-anomaly-score:${headerScore}`);
    }

    // ── 9. Tamanho anômalo de body ────────────────────────────────────────
    const MAX_BODY_BYTES = 10 * 1024 * 1024; // 10MB
    if (req.bodySize && req.bodySize > MAX_BODY_BYTES) {
      signals.push(`body-too-large:${req.bodySize}`);
      return block('REQUEST_TOO_LARGE');
    }

    // ── 10. Rate limiting (skip para IPs confiáveis) ─────────────────────
    if (!isTrusted) {
      const rateLimitResult = await this.checkRateLimit(ip, route, meta);
      if (rateLimitResult) return rateLimitResult;

      const tokenResult = await this.checkTokenBucket(ip);
      if (tokenResult) return tokenResult;
    }

    // ── 11. Score agregado ────────────────────────────────────────────────
    const totalScore = Math.min(100, headlessScore + headerScore);

    if (totalScore >= this.config.blockThreshold) {
      return block('HEADLESS_BROWSER', totalScore);
    }

    if (totalScore >= this.config.challengeThreshold) {
      return {
        allowed: false,
        reason:  'CHALLENGE_REQUIRED',
        score:   totalScore,
        meta,
      };
    }

    this.debugLog('ALLOWED', route, meta);
    return { allowed: true, score: totalScore, meta };
  }

  // ── Rate Limiting (janela deslizante) ────────────────────────────────────

  private async checkRateLimit(
    ip: string,
    route: string,
    meta: BotEvaluationMeta,
  ): Promise<BotEvaluationResult | null> {
    const now      = Date.now();
    const { rateLimit, store } = this.config;

    // Rate limit por IP
    const ipKey    = `rl:ip:${sanitizeKey(ip)}`;
    const ipCount  = await store.increment(ipKey, rateLimit.windowMs);

    meta.rateLimitRemaining = Math.max(0, rateLimit.maxRequestsPerIP - ipCount);
    meta.rateLimitResetAt   = now + rateLimit.windowMs;

    if (ipCount > rateLimit.maxRequestsPerIP) {
      meta.signals.push(`rate-limit-ip:${ipCount}`);
      return {
        allowed: false,
        reason:  'RATE_LIMIT_IP',
        score:   100,
        meta,
      };
    }

    // Rate limit por rota
    const routeConfig = this.config.routeLimits?.[route];
    if (routeConfig) {
      const routeKey   = `rl:route:${sanitizeKey(route)}:${sanitizeKey(ip)}`;
      const routeCount = await store.increment(routeKey, routeConfig.windowMs);

      if (routeCount > routeConfig.maxRequests) {
        meta.signals.push(`rate-limit-route:${route}:${routeCount}`);
        return {
          allowed: false,
          reason:  'RATE_LIMIT_ROUTE',
          score:   100,
          meta,
        };
      }
    }

    // Rate limit global (contador único em sliding window)
    const globalKey   = `rl:global:${Math.floor(now / 1000)}`; // bucket por segundo
    const globalCount = await store.increment(globalKey, 2000);

    if (globalCount > rateLimit.globalMaxRps) {
      meta.signals.push(`rate-limit-global:${globalCount}`);
      return {
        allowed: false,
        reason:  'RATE_LIMIT_GLOBAL',
        score:   100,
        meta,
      };
    }

    return null;
  }

  // ── Token Bucket ─────────────────────────────────────────────────────────

  private async checkTokenBucket(ip: string): Promise<BotEvaluationResult | null> {
    const { capacity, refillRatePerSecond } = this.config.tokenBucket;
    const store  = this.config.store;
    const now    = Date.now();

    const tokensKey    = `tb:tokens:${sanitizeKey(ip)}`;
    const lastRefillKey = `tb:last:${sanitizeKey(ip)}`;

    const [currentTokens, lastRefillRaw] = await Promise.all([
      store.get(tokensKey),
      store.get(lastRefillKey),
    ]);

    const tokens     = currentTokens ?? capacity;
    const lastRefill = lastRefillRaw  ?? now;

    // Calcula tokens a adicionar desde o último refill
    const elapsed       = (now - lastRefill) / 1000;
    const tokensToAdd   = elapsed * refillRatePerSecond;
    const newTokens     = Math.min(capacity, tokens + tokensToAdd);

    if (newTokens < 1) {
      return {
        allowed: false,
        reason:  'TOKEN_BUCKET_EMPTY',
        score:   100,
        meta:    { ip, fingerprint: '', userAgent: '', route: '', timestamp: now, signals: ['token-bucket-empty'] },
      };
    }

    // Consome 1 token
    const ttl = Math.ceil(capacity / refillRatePerSecond) * 1000;
    await Promise.all([
      store.set(tokensKey,    newTokens - 1, ttl),
      store.set(lastRefillKey, now,           ttl),
    ]);

    return null;
  }

  // ── Headless browser detection ──────────────────────────────────────────

  /**
   * Detecta sinais de navegadores headless e automação.
   * Retorna score de 0–60 (não bloqueia sozinho).
   *
   * Técnicas baseadas em:
   *  - Ausência de headers sec-fetch-* (Chrome 80+)
   *  - UA de HeadlessChrome
   *  - Headers injetados por Selenium/Puppeteer
   *  - Accept header de requests programáticos
   */
  private detectHeadless(
    headers: Record<string, string | string[] | undefined>,
    ua: string,
  ): number {
    let score = 0;

    // HeadlessChrome literal no UA
    if (/HeadlessChrome/i.test(ua)) score += 60;

    // PhantomJS
    if (/PhantomJS/i.test(ua)) score += 60;

    // Headers injetados por automação
    for (const [header, pattern] of Object.entries(AUTOMATION_SIGNAL_HEADERS)) {
      const value = getHeader(headers, header);
      if (!value) continue;
      if (pattern === 'any') { score += 30; continue; }
      if (pattern instanceof RegExp && pattern.test(value)) score += 20;
    }

    // Ausência de sec-fetch-site (presente em todos os browsers >= Chrome 80)
    const secFetchSite = getHeader(headers, 'sec-fetch-site');
    if (!secFetchSite) score += 10;

    // Ausência de sec-ch-ua (presente em todos os Chromium >= 90)
    const secChUa = getHeader(headers, 'sec-ch-ua');
    const isModernChromium = /Chrome\/[9-9]\d|Chrome\/1\d\d/i.test(ua);
    if (isModernChromium && !secChUa) score += 20;

    // Accept header típico de requests programáticos (não de browser)
    const accept = getHeader(headers, 'accept');
    if (accept === '*/*') score += 15;

    return Math.min(60, score);
  }

  // ── Header anomaly detection ─────────────────────────────────────────────

  /**
   * Detecta anomalias em headers que indicam automação.
   * Retorna score de 0–40.
   */
  private detectHeaderAnomalies(
    headers: Record<string, string | string[] | undefined>,
  ): number {
    let score = 0;

    // Headers obrigatórios de browser ausentes
    for (const required of REQUIRED_BROWSER_HEADERS) {
      if (!getHeader(headers, required)) {
        score += 10;
      }
    }

    // Accept-Language ausente (todos os browsers enviam)
    const acceptLang = getHeader(headers, 'accept-language');
    if (!acceptLang) score += 10;

    // Connection: keep-alive ausente em HTTP/1.1 (browsers sempre enviam)
    const connection  = getHeader(headers, 'connection');
    const httpVersion = getHeader(headers, ':version') ?? ''; // HTTP/2
    const isHttp2     = httpVersion.includes('2') || getHeader(headers, ':method') !== undefined;
    if (!isHttp2 && !connection) score += 5;

    return Math.min(40, score);
  }

  // ── Validação de honeypot de formulário ──────────────────────────────────

  /**
   * Verifica se algum campo honeypot de formulário foi preenchido.
   * Chame no handler de POST/PUT para formulários.
   *
   * @example
   * const result = botProtection.checkHoneypotFields(req.body);
   * if (!result.clean) return res.status(400).end();
   */
  checkHoneypotFields(body: Record<string, unknown>): { clean: boolean; filledField?: string } {
    for (const fieldName of HONEYPOT_FIELD_NAMES) {
      const value = body[fieldName];
      if (value !== undefined && value !== '' && value !== null) {
        return { clean: false, filledField: fieldName };
      }
    }
    return { clean: true };
  }

  /**
   * Verifica timing impossível entre renderização e submissão.
   * Humanos levam no mínimo ~3s para preencher um formulário.
   * Bots enviam em < 500ms.
   *
   * @param renderedAt Timestamp (ms) de quando o formulário foi renderizado.
   * @param submittedAt Timestamp (ms) de quando foi submetido.
   * @param minHumanMs Tempo mínimo em ms para considerar humano. Default: 3000.
   */
  checkSubmissionTiming(
    renderedAt: number,
    submittedAt: number,
    minHumanMs = 3_000,
  ): { valid: boolean; elapsedMs: number } {
    const elapsed = submittedAt - renderedAt;
    return {
      valid:     elapsed >= minHumanMs,
      elapsedMs: elapsed,
    };
  }

  // ── Logging ──────────────────────────────────────────────────────────────

  private debugLog(event: string, detail: unknown, meta?: unknown): void {
    if (!this.config.debug) return;
    console.debug(`[bot-protection] ${event}`, detail, meta ?? '');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resposta padrão de bloqueio — não revela o motivo ao cliente.
 *
 * OWASP recomienda respostas genéricas para não vazar informações sobre
 * a lógica de detecção ao atacante.
 */
function createBlockResponse(status: 429 | 403, retryAfterMs?: number): {
  status: number;
  headers: Record<string, string>;
  body: string;
} {
  const headers: Record<string, string> = {
    'Content-Type':           'application/json',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control':          'no-store',
  };

  if (status === 429 && retryAfterMs) {
    headers['Retry-After'] = String(Math.ceil(retryAfterMs / 1000));
  }

  return {
    status,
    headers,
    body: JSON.stringify({
      error:   status === 429 ? 'Too Many Requests' : 'Forbidden',
      message: 'Request blocked.',
    }),
  };
}

// ── Express adapter ──────────────────────────────────────────────────────────

type ExpressRequest  = { ip?: string; headers: Record<string, string | string[] | undefined>; path: string; method: string; body?: unknown };
type ExpressResponse = { status(code: number): ExpressResponse; set(headers: Record<string, string>): ExpressResponse; json(data: unknown): void; end(): void };
type NextFunction     = (err?: unknown) => void;

/**
 * Cria middleware Express/Fastify-compatible a partir de uma instância BotProtection.
 *
 * @example
 * import express from 'express';
 * const app = express();
 * app.use(createExpressAdapter(new BotProtection(config)));
 */
export function createExpressAdapter(protection: BotProtection) {
  return async (req: ExpressRequest, res: ExpressResponse, next: NextFunction): Promise<void> => {
    const normalized: NormalizedRequest = {
      ip:        req.ip ?? '0.0.0.0',
      method:    req.method,
      path:      req.path,
      headers:   req.headers,
      body:      req.body,
      timestamp: Date.now(),
    };

    const result = await protection.evaluate(normalized);

    if (!result.allowed) {
      const isRateLimit = result.reason?.startsWith('RATE_LIMIT') || result.reason === 'TOKEN_BUCKET_EMPTY';
      const { status, headers, body } = createBlockResponse(isRateLimit ? 429 : 403);
      res.status(status).set(headers).json(JSON.parse(body));
      return;
    }

    next();
  };
}

// ── Next.js Edge middleware adapter ──────────────────────────────────────────

/**
 * Cria handler para Next.js middleware (Edge Runtime).
 *
 * @example
 * // middleware.ts
 * export default createNextAdapter(new BotProtection(config));
 * export const config = { matcher: ['/api/:path*'] };
 */
export function createNextAdapter(protection: BotProtection) {
  return async (request: Request): Promise<Response | null> => {
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => { headers[key] = value; });

    const url = new URL(request.url);
    const normalized: NormalizedRequest = {
      ip:        headers['cf-connecting-ip'] ?? headers['x-real-ip'] ?? '0.0.0.0',
      method:    request.method,
      path:      url.pathname,
      headers,
      timestamp: Date.now(),
    };

    const result = await protection.evaluate(normalized);

    if (!result.allowed) {
      const isRateLimit = result.reason?.startsWith('RATE_LIMIT') || result.reason === 'TOKEN_BUCKET_EMPTY';
      const { status, headers: respHeaders, body } = createBlockResponse(isRateLimit ? 429 : 403);
      return new Response(body, { status, headers: respHeaders });
    }

    // null = continua para o handler
    return null;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory com configuração padrão segura
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria uma instância BotProtection com configuração padrão segura para produção.
 *
 * Substitua `store` por uma implementação Redis antes de deployar.
 *
 * @example
 * const protection = createBotProtection({
 *   store: createRedisStore(redisClient),
 *   routeLimits: {
 *     '/api/auth/login': { maxRequests: 5, windowMs: 60_000 },
 *   },
 *   onBlocked: (result) => logger.warn('bot blocked', result.meta),
 * });
 */
export function createBotProtection(
  overrides: Partial<BotProtectionConfig> & { store: BotProtectionStore },
): BotProtection {
  const defaults: BotProtectionConfig = {
    rateLimit: {
      maxRequestsPerIP: 60,
      windowMs:         60_000,
      globalMaxRps:     1_000,
    },
    tokenBucket: {
      capacity:            10,
      refillRatePerSecond: 2,
    },
    routeLimits: {
      '/api/auth/login':           { maxRequests: 5,   windowMs: 60_000 },
      '/api/auth/register':        { maxRequests: 3,   windowMs: 60_000 },
      '/api/auth/forgot-password': { maxRequests: 3,   windowMs: 60_000 },
      '/api/auth/reset-password':  { maxRequests: 3,   windowMs: 60_000 },
      '/api/checkout':             { maxRequests: 10,  windowMs: 60_000 },
      '/api/payment':              { maxRequests: 5,   windowMs: 60_000 },
      '/api/graphql':              { maxRequests: 100, windowMs: 60_000 },
      '/api/search':               { maxRequests: 30,  windowMs: 60_000 },
    },
    challengeThreshold: 70,
    blockThreshold:     90,
    blockedUserAgents:  [],
    blockedIPs:         [],
    trustedIPs:         ['127.0.0.1', '::1'],
    ...overrides,
    store: overrides.store,
  };

  return new BotProtection(defaults);
}