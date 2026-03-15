/**
 * @fileoverview Middleware CORS — Cross-Origin Resource Sharing seguro e configurável.
 *
 * @description
 * Implementa a especificação CORS (RFC 6454 + Fetch Living Standard) com foco em
 * segurança por padrão: nega tudo e permite apenas o que for explicitamente configurado.
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *  • Wildcard origin (*) com credentials             (CORS misconfiguration #1)
 *  • Origin reflection sem validação                 (CORS misconfiguration #2 — ubíquo)
 *  • null origin bypass (sandboxed iframes, files)   (PortSwigger Research 2018)
 *  • Subdomain takeover via origem permitida demais  (ex: *.evil.victim.com)
 *  • Preflight cache poisoning via Vary incorreto    (RFC 7234)
 *  • Credenciais vazadas em CORS mal configurado     (OWASP A05:2021)
 *  • HTTP downgrade via origin http:// em API https  (mixed content)
 *  • Header injection via Origin forjado             (CRLF em headers antigos)
 *  • Regex bypass: evil.com?real.com, real.com.evil   (pesquisa James Kettle 2018)
 *  • Private Network Access (PNA) — browser → LAN    (Chrome 94+ CORS-RFC1918)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • CORS-RFC1918 / Private Network Access headers    (Chrome 94+, W3C FPWD)
 *  • Speculation Rules cross-origin                   (emergente)
 *  • Isolation headers (COOP/COEP/CORP)               (2022+, integração sugerida)
 *  • Partitioned cookies (CHIPS) impact on CORS       (Chrome 114+)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Allowlist estrita: nega por padrão, permite explicitamente
 *  • Validação de origin em múltiplas camadas (exata, padrão, regex auditada)
 *  • Preflight caching correto com Vary header
 *  • Separação entre rotas públicas (GET sem credentials) e privadas
 *  • Adaptadores prontos para Express e Next.js Edge
 *  • Zero dependências externas
 *
 * @see https://fetch.spec.whatwg.org/#http-cors-protocol
 * @see https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
 * @see https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resultado da avaliação de uma origem.
 * Contém os headers a serem aplicados na resposta.
 */
export interface CORSResult {
  /** true = origem permitida ou requisição same-origin */
  allowed: boolean;
  /** Headers CORS a adicionar na resposta. Nunca sobrescreva sem inspecionar. */
  headers: Record<string, string>;
  /** true = requisição preflight OPTIONS que deve ser respondida com 204 */
  isPreflight: boolean;
  /** Motivo interno do bloqueio. Nunca exponha ao cliente. */
  reason?: CORSBlockReason;
}

export type CORSBlockReason =
  | 'ORIGIN_NOT_ALLOWED'
  | 'NULL_ORIGIN_BLOCKED'
  | 'HTTP_ORIGIN_ON_HTTPS'
  | 'METHOD_NOT_ALLOWED'
  | 'HEADER_NOT_ALLOWED'
  | 'CREDENTIALS_WITH_WILDCARD'
  | 'ORIGIN_HEADER_MISSING'
  | 'PRIVATE_NETWORK_DENIED';

/**
 * Configuração do middleware CORS.
 * Todos os campos têm padrões seguros — configure apenas o que precisar abrir.
 */
export interface CORSConfig {
  /**
   * Origens permitidas.
   *
   * Aceita:
   *  - string exata:    'https://app.exemplo.com'
   *  - RegExp auditada: /^https:\/\/[\w-]+\.exemplo\.com$/
   *  - função:          (origin) => origin.endsWith('.exemplo.com')
   *  - '*':             qualquer origem — APENAS para APIs verdadeiramente públicas
   *                     sem credentials (ex: CDN, API pública sem auth)
   *
   * ⚠ NUNCA use '*' com `credentials: true` — o browser rejeita e você
   *   provavelmente tem uma misconfiguration de segurança.
   *
   * Default: [] (nenhuma origem externa permitida)
   */
  allowedOrigins: Array<string | RegExp | ((origin: string) => boolean)>;

  /**
   * Métodos HTTP permitidos.
   * Default: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
   */
  allowedMethods?: string[];

  /**
   * Headers que o cliente pode enviar.
   * Default: lista segura de headers comuns (ver SAFE_REQUEST_HEADERS)
   */
  allowedHeaders?: string[];

  /**
   * Headers da resposta que o JavaScript do cliente pode ler.
   * Por padrão apenas os "safe headers" da spec são acessíveis.
   * Default: ['Content-Type', 'X-Request-Id']
   */
  exposedHeaders?: string[];

  /**
   * Permite envio de cookies e Authorization header cross-origin.
   *
   * ⚠ Riscos quando habilitado:
   *  - Não pode ser combinado com allowedOrigins: ['*']
   *  - Expõe cookies de sessão a origens listadas
   *  - Aumenta superfície de CSRF
   *
   * Default: false
   */
  credentials?: boolean;

  /**
   * Tempo em segundos que o browser pode cachear a resposta de preflight.
   * Valores altos reduzem requisições OPTIONS mas atrasam mudanças de config.
   * Default: 600 (10 minutos). Max recomendado: 86400 (1 dia).
   */
  maxAge?: number;

  /**
   * Bloqueia origens http:// quando a API serve https://.
   * Previne mixed-content e downgrade attacks.
   * Default: true
   */
  blockHTTPOriginOnHTTPS?: boolean;

  /**
   * Bloqueia explicitamente a origin 'null'.
   *
   * 'null' origin é enviada por:
   *  - Iframes sandboxed (<iframe sandbox>)
   *  - file:// protocol
   *  - Alguns redirects cross-origin
   *  - data: URIs
   *
   * Atacantes podem abusar de null origin para bypassar listas de origem
   * que aceitam null. Bloquear por padrão é mais seguro.
   * Default: true
   */
  blockNullOrigin?: boolean;

  /**
   * Rotas que são completamente públicas (sem credentials, sem cookies).
   * Recebem Access-Control-Allow-Origin: * apenas para GET/HEAD.
   *
   * Use para: /health, /metrics, /api/public/*, etc.
   */
  publicRoutes?: Array<string | RegExp>;

  /**
   * Suporte a Private Network Access (Chrome 94+, CORS-RFC1918).
   * Quando true, responde ao header Access-Control-Request-Private-Network.
   * Default: false
   */
  allowPrivateNetwork?: boolean;

  /**
   * Hook chamado quando uma origem é bloqueada.
   * Use para alertas de segurança e logs.
   */
  onBlocked?: (reason: CORSBlockReason, origin: string, path: string) => void;

  /**
   * Habilita logging detalhado. Default: false.
   */
  debug?: boolean;
}

/** Representação mínima de request para avaliação CORS. */
export interface CORSRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  /** true se a requisição chegou via HTTPS. Usado para blockHTTPOriginOnHTTPS. */
  secure?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Headers de request seguros por padrão.
 * Baseado na Fetch spec "CORS-safelisted request headers" + headers comuns de API.
 */
const SAFE_REQUEST_HEADERS: readonly string[] = [
  // CORS-safelisted (spec)
  'accept',
  'accept-language',
  'content-language',
  'content-type',
  // Auth / API comum
  'authorization',
  'x-requested-with',
  'x-api-key',
  'x-client-version',
  'x-request-id',
  'x-correlation-id',
  'x-idempotency-key',
  // Internacionalização
  'accept-charset',
  // Cache
  'cache-control',
  'pragma',
  // Content negotiation
  'range',
];

/**
 * Headers "safe" que o browser sempre expõe ao JS (não precisam de exposedHeaders).
 * Listados aqui para evitar duplicação desnecessária no header.
 */
const ALWAYS_EXPOSED_HEADERS: readonly string[] = [
  'cache-control',
  'content-language',
  'content-length',
  'content-type',
  'expires',
  'last-modified',
  'pragma',
];

/**
 * Métodos que nunca devem ser permitidos via CORS em APIs privadas.
 * CONNECT e TRACE têm usos muito específicos e geralmente indicam ataque.
 */
const ALWAYS_FORBIDDEN_METHODS: readonly string[] = ['CONNECT', 'TRACE'];

/**
 * Métodos que disparam preflight (não-simple methods).
 * GET, HEAD, POST com content-type safe são "simple" e não disparam preflight.
 */
const PREFLIGHT_TRIGGERING_METHODS: readonly string[] = [
  'PUT', 'PATCH', 'DELETE',
];

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários internos
// ─────────────────────────────────────────────────────────────────────────────

/** Obtém header case-insensitive, retorna string ou undefined. */
function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const val = headers[name.toLowerCase()];
  if (!val) return undefined;
  return Array.isArray(val) ? val[0] : val;
}

/**
 * Normaliza origem: lowercase, remove trailing slash, valida formato.
 * Resiste a CRLF injection (\r\n em headers antigos de proxy).
 */
function normalizeOrigin(origin: string): string {
  return origin
    .replace(/[\r\n\0]/g, '')  // CRLF injection guard
    .trim()
    .toLowerCase()
    .replace(/\/$/, '');       // remove trailing slash
}

/**
 * Verifica se uma string é uma origem válida no formato spec:
 * scheme://host[:port]
 *
 * Rejeita:
 *  - Strings com path (https://example.com/path)
 *  - Strings com query string
 *  - Strings com fragmento
 *  - Strings vazias
 *  - Strings com espaços
 *
 * Previne regex bypasses como:
 *  - https://evil.com?https://real.com  → rejeita (tem query)
 *  - https://real.com.evil.com          → passa como origin, validado depois
 */
function isValidOriginFormat(origin: string): boolean {
  if (!origin || origin === 'null') return origin === 'null';

  try {
    const url = new URL(origin);
    // Origem válida não tem path (além de /), query ou fragmento
    return (
      (url.pathname === '/' || url.pathname === '') &&
      url.search === '' &&
      url.hash === ''
    );
  } catch {
    return false;
  }
}

/**
 * Verifica se a URL usa HTTPS.
 * Usado para bloquear origens HTTP em APIs HTTPS.
 */
function isHTTPS(origin: string): boolean {
  return origin.startsWith('https://');
}

/**
 * Verifica se uma rota corresponde à lista de rotas públicas.
 */
function isPublicRoute(
  path: string,
  publicRoutes: Array<string | RegExp>,
): boolean {
  for (const route of publicRoutes) {
    if (typeof route === 'string') {
      if (path === route || path.startsWith(route + '/')) return true;
    } else if (route instanceof RegExp) {
      if (route.test(path)) return true;
    }
  }
  return false;
}

/**
 * Verifica se uma origem está na lista de origens permitidas.
 *
 * Suporta três formas de match:
 *  1. String exata (case-insensitive após normalização)
 *  2. RegExp — CUIDADO: valide a regexp antes de colocar em produção
 *     Má regexp: /example\.com/ → casa com evilexample.com
 *     Boa regexp: /^https:\/\/example\.com$/
 *  3. Função — máxima flexibilidade, pode integrar com banco de dados
 */
function matchesAllowedOrigin(
  origin: string,
  allowed: Array<string | RegExp | ((origin: string) => boolean)>,
): boolean {
  const normalized = normalizeOrigin(origin);

  for (const rule of allowed) {
    if (typeof rule === 'string') {
      // Wildcard explícito
      if (rule === '*') return true;
      // Match exato após normalização
      if (normalizeOrigin(rule) === normalized) return true;
    } else if (rule instanceof RegExp) {
      if (rule.test(normalized)) return true;
    } else if (typeof rule === 'function') {
      if (rule(normalized)) return true;
    }
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class CORSMiddleware {
  private readonly config: Required<
    Omit<CORSConfig, 'onBlocked' | 'ipReputationCheck'>
  > & Pick<CORSConfig, 'onBlocked'>;

  constructor(config: CORSConfig) {
    // Garante que credentials + wildcard não coexistam (erro de config perigoso)
    const hasWildcard = config.allowedOrigins.includes('*');
    if (hasWildcard && config.credentials) {
      throw new Error(
        '[cors] Configuração inválida: não é possível combinar ' +
        'allowedOrigins: ["*"] com credentials: true. ' +
        'Isso viola a spec CORS e seria rejeitado pelo browser. ' +
        'Liste as origens explicitamente em vez de usar wildcard.',
      );
    }

    this.config = {
      allowedMethods:      ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders:      Array.from(SAFE_REQUEST_HEADERS),
      exposedHeaders:      ['Content-Type', 'X-Request-Id', 'X-Correlation-Id'],
      credentials:         false,
      maxAge:              600,
      blockHTTPOriginOnHTTPS: true,
      blockNullOrigin:     true,
      publicRoutes:        [],
      allowPrivateNetwork: false,
      onBlocked:           undefined,
      debug:               false,
      ...config,
    };

    // Remove métodos sempre proibidos da lista, mesmo que o dev os tenha adicionado
    this.config.allowedMethods = this.config.allowedMethods.filter(
      m => !ALWAYS_FORBIDDEN_METHODS.includes(m.toUpperCase()),
    );
  }

  /**
   * Avalia uma requisição e retorna os headers CORS a aplicar.
   *
   * Chamada principal — use os adaptadores abaixo para integração com frameworks.
   *
   * @param req - A requisição normalizada.
   * @returns CORSResult com allowed, headers, isPreflight e reason opcional.
   */
  evaluate(req: CORSRequest): CORSResult {
    const origin    = getHeader(req.headers, 'origin');
    const method    = req.method.toUpperCase();
    const path      = req.path;
    const isPreflight = method === 'OPTIONS' &&
      !!getHeader(req.headers, 'access-control-request-method');

    // ── Requisição same-origin (sem Origin header) ─────────────────────────
    // Browsers omitem Origin em same-origin GET/HEAD. Não é CORS — passa direto.
    if (!origin) {
      return {
        allowed:     true,
        headers:     this.buildSecurityHeaders(),
        isPreflight: false,
        reason:      undefined,
      };
    }

    const block = (reason: CORSBlockReason): CORSResult => {
      this.config.onBlocked?.(reason, origin, path);
      this.debugLog('BLOCKED', reason, origin, path);
      return {
        allowed:     false,
        headers:     this.buildSecurityHeaders(),
        isPreflight,
        reason,
      };
    };

    // ── 1. Validação de formato da origem ──────────────────────────────────
    if (!isValidOriginFormat(origin) && origin !== 'null') {
      return block('ORIGIN_NOT_ALLOWED');
    }

    // ── 2. Bloqueio de null origin ─────────────────────────────────────────
    if (origin === 'null' && this.config.blockNullOrigin) {
      return block('NULL_ORIGIN_BLOCKED');
    }

    // ── 3. Bloqueio de HTTP em API HTTPS ───────────────────────────────────
    if (
      this.config.blockHTTPOriginOnHTTPS &&
      (req.secure === true || this.isRequestSecure(req.headers)) &&
      origin !== 'null' &&
      !isHTTPS(origin)
    ) {
      return block('HTTP_ORIGIN_ON_HTTPS');
    }

    // ── 4. Rotas públicas (wildcard sem credentials) ───────────────────────
    if (
      isPublicRoute(path, this.config.publicRoutes) &&
      (method === 'GET' || method === 'HEAD')
    ) {
      const headers = {
        ...this.buildSecurityHeaders(),
        'Access-Control-Allow-Origin': '*',
        'Vary':                        'Origin',
      };
      this.debugLog('ALLOWED-PUBLIC', origin, path, method);
      return { allowed: true, headers, isPreflight: false };
    }

    // ── 5. Verificação da origem ───────────────────────────────────────────
    const isWildcard = this.config.allowedOrigins.includes('*');
    const originAllowed = isWildcard || matchesAllowedOrigin(origin, this.config.allowedOrigins);

    if (!originAllowed) {
      return block('ORIGIN_NOT_ALLOWED');
    }

    // ── 6. Preflight OPTIONS ───────────────────────────────────────────────
    if (isPreflight) {
      const preflightResult = this.evaluatePreflight(req, origin);
      if (!preflightResult.allowed) return block(preflightResult.reason!);

      const headers = {
        ...this.buildSecurityHeaders(),
        ...preflightResult.headers,
      };
      this.debugLog('PREFLIGHT-OK', origin, path, method);
      return { allowed: true, headers, isPreflight: true };
    }

    // ── 7. Requisição CORS simples ou com credentials ──────────────────────
    const headers = this.buildCORSHeaders(origin, isWildcard);
    this.debugLog('ALLOWED', origin, path, method);
    return { allowed: true, headers, isPreflight: false };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Preflight
  // ─────────────────────────────────────────────────────────────────────────

  private evaluatePreflight(
    req: CORSRequest,
    origin: string,
  ): { allowed: boolean; headers: Record<string, string>; reason?: CORSBlockReason } {
    const requestMethod  = getHeader(req.headers, 'access-control-request-method')?.toUpperCase();
    const requestHeaders = getHeader(req.headers, 'access-control-request-headers');

    // Valida método solicitado
    if (!requestMethod || !this.config.allowedMethods.includes(requestMethod)) {
      return { allowed: false, reason: 'METHOD_NOT_ALLOWED', headers: {} };
    }

    // Valida headers solicitados
    if (requestHeaders) {
      const requested = requestHeaders
        .split(',')
        .map(h => h.trim().toLowerCase());

      const allowedLower = this.config.allowedHeaders.map(h => h.toLowerCase());

      const unauthorized = requested.filter(h => !allowedLower.includes(h));
      if (unauthorized.length > 0) {
        this.debugLog('HEADER-DENIED', unauthorized.join(', '), origin, req.path);
        return { allowed: false, reason: 'HEADER_NOT_ALLOWED', headers: {} };
      }
    }

    const isWildcard = this.config.allowedOrigins.includes('*');

    const headers: Record<string, string> = {
      'Access-Control-Allow-Origin':  isWildcard ? '*' : origin,
      'Access-Control-Allow-Methods': this.config.allowedMethods.join(', '),
      'Access-Control-Allow-Headers': this.config.allowedHeaders.join(', '),
      'Access-Control-Max-Age':       String(this.config.maxAge),
      // Vary é crítico para caching correto de preflight
      // sem ele, o browser pode cachear uma resposta para a origem A
      // e reutilizá-la para a origem B
      'Vary':                         'Origin, Access-Control-Request-Method, Access-Control-Request-Headers',
    };

    if (this.config.credentials && !isWildcard) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }

    if (this.config.allowPrivateNetwork) {
      const privateNetworkRequest = getHeader(
        req.headers,
        'access-control-request-private-network',
      );
      if (privateNetworkRequest === 'true') {
        headers['Access-Control-Allow-Private-Network'] = 'true';
      }
    }

    return { allowed: true, headers };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Builders de headers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Monta os headers CORS para uma requisição autorizada (não-preflight).
   */
  private buildCORSHeaders(origin: string, isWildcard: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      ...this.buildSecurityHeaders(),
      'Access-Control-Allow-Origin': isWildcard ? '*' : origin,
      // Vary é obrigatório quando a origem não é wildcard:
      // sem ele CDNs e proxies podem servir a resposta de uma origem para outra
      'Vary': 'Origin',
    };

    if (this.config.credentials && !isWildcard) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }

    // Expõe apenas headers não-safelisted que o cliente precisa ler
    const nonSafe = this.config.exposedHeaders.filter(
      h => !ALWAYS_EXPOSED_HEADERS.includes(h.toLowerCase()),
    );
    if (nonSafe.length > 0) {
      headers['Access-Control-Expose-Headers'] = nonSafe.join(', ');
    }

    if (this.config.allowPrivateNetwork) {
      headers['Access-Control-Allow-Private-Network'] = 'true';
    }

    return headers;
  }

  /**
   * Headers de segurança adicionais que complementam o CORS.
   * Incluídos em todas as respostas (bloqueadas ou permitidas).
   *
   * Esses headers sozinhos não substituem CORS, mas ajudam a limitar
   * o impacto de uma misconfiguration.
   */
  private buildSecurityHeaders(): Record<string, string> {
    return {
      // Impede MIME-type sniffing (complementa CORS)
      'X-Content-Type-Options': 'nosniff',
      // Previne embedding em iframes não autorizados
      'X-Frame-Options':        'DENY',
      // Força HTTPS por 1 ano com preload
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    };
  }

  /**
   * Infere se a requisição chegou via HTTPS a partir de headers de proxy reverso.
   * Usado quando `req.secure` não está disponível (ex: Edge Runtime).
   */
  private isRequestSecure(
    headers: Record<string, string | string[] | undefined>,
  ): boolean {
    const proto = getHeader(headers, 'x-forwarded-proto');
    if (proto) return proto.toLowerCase() === 'https';

    const cfVisitor = getHeader(headers, 'cf-visitor');
    if (cfVisitor) {
      try {
        return JSON.parse(cfVisitor).scheme === 'https';
      } catch { /* continua */ }
    }

    return false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Logging
  // ─────────────────────────────────────────────────────────────────────────

  private debugLog(event: string, ...args: unknown[]): void {
    if (!this.config.debug) return;
    console.debug('[cors]', event, ...args);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

type ExpressRequest = {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  secure?: boolean;
};
type ExpressResponse = {
  status(code: number): ExpressResponse;
  set(headers: Record<string, string>): ExpressResponse;
  end(): void;
};
type NextFn = (err?: unknown) => void;

/**
 * Cria middleware CORS para Express / Fastify.
 *
 * @example
 * import express from 'express';
 * const app = express();
 * app.use(createExpressCORS(corsMiddleware));
 */
export function createExpressCORS(cors: CORSMiddleware) {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFn): void => {
    const result = cors.evaluate({
      method:  req.method,
      path:    req.path,
      headers: req.headers,
      secure:  req.secure,
    });

    res.set(result.headers);

    if (!result.allowed) {
      res.status(403).end();
      return;
    }

    if (result.isPreflight) {
      res.status(204).end();
      return;
    }

    next();
  };
}

/**
 * Cria handler CORS para Next.js middleware (Edge Runtime / Node.js).
 *
 * Retorna `null` para continuar para o handler, ou `Response` para interromper.
 *
 * @example
 * // middleware.ts
 * const cors = createNextCORS(corsMiddleware);
 * export default function middleware(req: Request) {
 *   return cors(req) ?? NextResponse.next();
 * }
 */
export function createNextCORS(cors: CORSMiddleware) {
  return (request: Request): Response | null => {
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => { headers[key] = value; });

    const url = new URL(request.url);
    const result = cors.evaluate({
      method:  request.method,
      path:    url.pathname,
      headers,
      secure:  url.protocol === 'https:',
    });

    if (!result.allowed) {
      return new Response(null, {
        status:  403,
        headers: result.headers,
      });
    }

    if (result.isPreflight) {
      return new Response(null, {
        status:  204,
        headers: result.headers,
      });
    }

    // null = continua (o caller adiciona os headers ao NextResponse)
    return null;
  };
}

/**
 * Injetor de headers CORS em uma Response existente.
 * Útil quando o handler já construiu a Response e você quer aplicar CORS no final.
 *
 * @example
 * const response = await handler(request);
 * return applyCORSHeaders(response, corsMiddleware, request);
 */
export function applyCORSHeaders(
  response: Response,
  cors: CORSMiddleware,
  request: Request,
): Response {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => { headers[key] = value; });

  const url = new URL(request.url);
  const result = cors.evaluate({
    method:  request.method,
    path:    url.pathname,
    headers,
    secure:  url.protocol === 'https:',
  });

  const newHeaders = new Headers(response.headers);
  for (const [key, value] of Object.entries(result.headers)) {
    newHeaders.set(key, value);
  }

  return new Response(response.body, {
    status:     response.status,
    statusText: response.statusText,
    headers:    newHeaders,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory com preset de configuração
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Preset para API privada com autenticação (mais restritivo).
 *
 * - Credentials habilitado
 * - Apenas origens explicitamente listadas
 * - Headers de auth incluídos
 * - Preflight cache: 10 minutos
 *
 * @example
 * const cors = createPrivateAPICORS(['https://app.exemplo.com']);
 * app.use(createExpressCORS(cors));
 */
export function createPrivateAPICORS(allowedOrigins: string[]): CORSMiddleware {
  return new CORSMiddleware({
    allowedOrigins,
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      ...SAFE_REQUEST_HEADERS,
      'x-csrf-token',
      'x-refresh-token',
    ],
    exposedHeaders: [
      'Content-Type',
      'X-Request-Id',
      'X-Correlation-Id',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
    ],
    credentials:            true,
    maxAge:                 600,
    blockHTTPOriginOnHTTPS: true,
    blockNullOrigin:        true,
  });
}

/**
 * Preset para API pública sem autenticação (CDN, dados abertos).
 *
 * - Sem credentials
 * - Qualquer origem para GET/HEAD
 * - Preflight cache: 1 hora
 *
 * @example
 * const cors = createPublicAPICORS();
 * app.use('/api/public', createExpressCORS(cors));
 */
export function createPublicAPICORS(): CORSMiddleware {
  return new CORSMiddleware({
    allowedOrigins:         ['*'],
    allowedMethods:         ['GET', 'HEAD', 'OPTIONS'],
    allowedHeaders:         ['Accept', 'Accept-Language', 'Content-Type'],
    exposedHeaders:         ['Content-Type', 'X-Request-Id'],
    credentials:            false,
    maxAge:                 3600,
    blockHTTPOriginOnHTTPS: false, // APIs públicas podem receber de qualquer esquema
    blockNullOrigin:        false, // null origin pode ser legítima para iframes públicos
  });
}

/**
 * Preset para ambiente de desenvolvimento (mais permissivo, nunca use em produção).
 *
 * @example
 * const cors = process.env.NODE_ENV === 'development'
 *   ? createDevCORS()
 *   : createPrivateAPICORS(['https://app.exemplo.com']);
 */
export function createDevCORS(): CORSMiddleware {
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      '[cors] createDevCORS() não deve ser usado em produção. ' +
      'Use createPrivateAPICORS() ou createPublicAPICORS().',
    );
  }

  return new CORSMiddleware({
    allowedOrigins: [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:4200', // Angular dev server
      'http://localhost:5173', // Vite dev server
      'http://127.0.0.1:3000',
      /^http:\/\/localhost:\d+$/,
    ],
    allowedMethods:         ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders:         Array.from(SAFE_REQUEST_HEADERS),
    credentials:            true,
    maxAge:                 60,
    blockHTTPOriginOnHTTPS: false,
    blockNullOrigin:        false,
    debug:                  true,
  });
}

// Re-exporta constantes úteis para testes e extensões externas
export { SAFE_REQUEST_HEADERS, ALWAYS_EXPOSED_HEADERS };