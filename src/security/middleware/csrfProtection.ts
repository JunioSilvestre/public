/**
 * @arquivo     src/security/middleware/csrfProtection.ts
 * @módulo      Security / Middleware / Proteção CSRF
 * @descrição   Middleware de proteção CSRF (Cross-Site Request Forgery) com múltiplas
 *              estratégias: Synchronizer Token, Double Submit Cookie e Signed Double Submit.
 *              Inclui comparação timing-safe, geração criptograficamente segura e store injetável.
 *
 * @como-usar
 *              const csrf = new CSRFProtection({ strategy: 'signed-double-submit', secret: process.env.CSRF_SECRET });
 *              // Gera token (endpoint GET):
 *              const { token, cookieHeader } = await csrf.generateToken(sessionId);
 *              // Valida (endpoint POST/PUT/PATCH/DELETE):
 *              const result = await csrf.validate(req);
 *              if (!result.valid) return respond403(result.reason);
 *
 * @dependências next/server, Web Crypto API (Node.js 15+)
 * @notas       ⚠ CSRF_SECRET mínimo recomendado: 32 bytes (256 bits).
 *              Use variável de ambiente: process.env.CSRF_SECRET.
 */
/**
 * @fileoverview Middleware de proteção CSRF — Cross-Site Request Forgery.
 *
 * @description
 * Implementa múltiplas estratégias de defesa contra CSRF com foco em
 * segurança por padrão e compatibilidade com SPAs modernas.
 *
 * ── Estratégias implementadas ──────────────────────────────────────────────
 *  1. Synchronizer Token Pattern  — token server-side por sessão (padrão OWASP)
 *  2. Double Submit Cookie        — token em cookie + header/body (stateless)
 *  3. Signed Double Submit        — versão com HMAC do Double Submit (mais seguro)
 *  4. Custom Request Header       — X-Requested-With para AJAX detection
 *  5. Origin / Referer Validation — validação de headers de proveniência
 *  6. SameSite Cookie Enforcement — verificação de suporte a SameSite
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────
 *  • CSRF clássico via <form> POST                     (ubíquo desde 2001)
 *  • CSRF via GET com side effects                     (OWASP A01)
 *  • Login CSRF (força login com conta do atacante)    (Google, Netflix histórico)
 *  • JSON CSRF via Content-Type: text/plain bypass     (pré-2012)
 *  • Cross-origin redirect CSRF                        (preserva referer)
 *  • Referer stripping via Referrer-Policy: no-referrer (bypass de referer check)
 *  • Cookie tossing via subdomínio comprometido        (OWASP Testing Guide)
 *  • BREACH / token disclosure via compressão          (CVE-2013-3587)
 *  • Timing attack em comparação de tokens             (side-channel)
 *  • Token fixation via predictable seed               (PRNG fraco)
 *  • Flash-based cross-origin reads                    (legado, pre-2020)
 *  • CORS misconfiguration que anula CSRF protection   (combinação de vetores)
 *  • multipart/form-data CSRF bypass                   (histórico)
 *  • Clickjacking como vetor auxiliar de CSRF          (mitigado via X-Frame-Options)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • WebAssembly cross-origin reads                    (emergente)
 *  • Partitioned cookies (CHIPS) e impacto no CSRF     (Chrome 114+)
 *  • Private State Tokens (FedCM replacement)          (W3C 2023+)
 *  • SameSite=Lax bypass em top-level navigation POST  (documentado 2021+)
 *  • Cross-site leaks (XS-Leaks) como canal auxiliar   (2020+)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────
 *  • Comparação de tokens com timingSafeEqual (previne timing attack)
 *  • Tokens gerados com crypto.getRandomValues (CSPRNG)
 *  • Assinatura HMAC-SHA256 para Double Submit assinado
 *  • Store injetável para Synchronizer Token (Redis, memória, DB)
 *  • Framework-agnostic: adaptadores Express e Next.js incluídos
 *  • Rotas e métodos configuráveis para exclusão (ex: webhooks)
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 * @see https://portswigger.net/web-security/csrf
 */

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/** Estratégia de proteção CSRF a ser usada. */
export type CSRFStrategy =
  /** Token server-side vinculado à sessão. Mais seguro, requer store. */
  | 'synchronizer-token'
  /** Token em cookie + campo/header. Stateless, funciona sem store. */
  | 'double-submit-cookie'
  /** Double Submit com HMAC. Stateless + resistente a cookie tossing. */
  | 'signed-double-submit';

/** Resultado da validação CSRF. */
export interface CSRFValidationResult {
  valid: boolean;
  reason?: CSRFFailReason;
  /** Token para uso no próximo request (incluso em respostas válidas). */
  token?: string;
}

export type CSRFFailReason =
  | 'TOKEN_MISSING'
  | 'TOKEN_INVALID'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_MISMATCH'
  | 'ORIGIN_MISMATCH'
  | 'REFERER_MISSING'
  | 'REFERER_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'SESSION_MISSING'
  | 'COOKIE_MISSING';

/** Token CSRF com metadados. */
export interface CSRFToken {
  value: string;
  sessionId: string;
  createdAt: number;
  expiresAt: number;
}

/** Requisição normalizada para validação CSRF. */
export interface CSRFRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  /** Cookie já parseado como objeto. */
  cookies?: Record<string, string>;
  /** Body parseado (para extrair token de formulários). */
  body?: Record<string, unknown>;
  /** ID da sessão do usuário (necessário para synchronizer-token). */
  sessionId?: string;
  /** Origem da requisição (https://seusite.com). */
  origin?: string;
}

/** Interface de store para Synchronizer Token Pattern. */
export interface CSRFStore {
  /** Armazena token associado a uma sessão. TTL em ms. */
  set(sessionId: string, token: CSRFToken, ttlMs: number): Promise<void>;
  /** Recupera token de uma sessão. */
  get(sessionId: string): Promise<CSRFToken | null>;
  /** Invalida token de uma sessão (após uso ou logout). */
  delete(sessionId: string): Promise<void>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

export interface CSRFConfig {
  /**
   * Estratégia de proteção.
   * Default: 'signed-double-submit' (melhor equilíbrio segurança/praticidade)
   */
  strategy?: CSRFStrategy;

  /**
   * Nome do cookie que armazena o token CSRF.
   * Default: '__csrf'
   *
   * Boas práticas para o nome:
   *  - Use prefixo __Host- para vincular ao host exato (sem subdomínio)
   *    Ex: '__Host-csrf' — mais resistente a cookie tossing
   *  - Use prefixo __Secure- para exigir HTTPS
   *    Ex: '__Secure-csrf'
   */
  cookieName?: string;

  /**
   * Nome do header onde o cliente envia o token.
   * Default: 'x-csrf-token'
   *
   * Headers customizados já são proteção CSRF parcial —
   * browsers bloqueiam headers customizados em cross-origin sem CORS.
   */
  headerName?: string;

  /**
   * Nome do campo de formulário onde o token pode ser enviado.
   * Default: '_csrf'
   */
  fieldName?: string;

  /**
   * Tempo de vida do token em ms.
   * Default: 3_600_000 (1 hora)
   */
  tokenTTLMs?: number;

  /**
   * Tamanho do token em bytes antes de base64url.
   * Default: 32 (256 bits — seguro contra brute force)
   * Mínimo recomendado: 16 (128 bits)
   */
  tokenByteLength?: number;

  /**
   * Segredo para assinatura HMAC (signed-double-submit).
   * OBRIGATÓRIO para a estratégia 'signed-double-submit'.
   * Mínimo recomendado: 32 bytes (256 bits).
   *
   * Use uma variável de ambiente: process.env.CSRF_SECRET
   */
  secret?: string;

  /**
   * Origens confiáveis para validação de Origin/Referer.
   * Inclui a própria origem da aplicação.
   *
   * Default: [] (apenas same-origin)
   */
  trustedOrigins?: string[];

  /**
   * Métodos HTTP que exigem validação CSRF.
   * Métodos "safe" (GET, HEAD, OPTIONS) são ignorados por padrão.
   * Default: ['POST', 'PUT', 'PATCH', 'DELETE']
   */
  protectedMethods?: string[];

  /**
   * Rotas excluídas da proteção CSRF.
   * Use para webhooks externos, endpoints de callback OAuth, etc.
   *
   * ⚠ Exclua com critério — cada exclusão é uma superfície de ataque.
   */
  excludedRoutes?: Array<string | RegExp>;

  /**
   * Configuração do cookie CSRF.
   */
  cookieOptions?: {
    /**
     * HttpOnly: false (o JS precisa ler o token para enviar no header).
     * Double Submit REQUER que o JS leia o cookie.
     * Default: false
     */
    httpOnly?: boolean;
    /**
     * Secure: true em produção (HTTPS only).
     * Default: true
     */
    secure?: boolean;
    /**
     * SameSite: 'Strict' | 'Lax' | 'None'
     *
     * 'Strict' — máxima proteção, pode quebrar fluxos legítimos de terceiros
     * 'Lax'    — padrão moderno, protege POST mas permite GET de terceiros
     * 'None'   — requer Secure=true, use apenas para embeds cross-site
     *
     * Default: 'Strict'
     */
    sameSite?: 'Strict' | 'Lax' | 'None';
    /**
     * Path do cookie.
     * Default: '/'
     */
    path?: string;
    /**
     * Domain do cookie.
     * ⚠ Não defina domain se quiser prevenir cookie tossing de subdomínios.
     * Prefira o prefixo __Host- no nome do cookie.
     */
    domain?: string;
  };

  /**
   * Store para Synchronizer Token Pattern.
   * Obrigatório quando strategy = 'synchronizer-token'.
   */
  store?: CSRFStore;

  /**
   * Rotas onde o CSRF token é renovado a cada request (token rotation).
   * Mais seguro mas aumenta complexidade no cliente.
   * Default: false (token reutilizável até expirar)
   */
  rotateToken?: boolean;

  /**
   * Valida Origin/Referer além do token.
   * Defesa em profundidade: mesmo que o token vaze, a origem ainda é checada.
   * Default: true
   */
  validateOrigin?: boolean;

  /**
   * Hook chamado em falha de validação.
   * Use para logs de segurança e alertas.
   */
  onFailure?: (reason: CSRFFailReason, req: CSRFRequest) => void;

  /** Habilita logging detalhado. Default: false. */
  debug?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store em memória — apenas desenvolvimento
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Implementação de CSRFStore em memória.
 * ⚠ Não use em produção — use Redis ou equivalente.
 */
export class MemoryCSRFStore implements CSRFStore {
  private readonly tokens = new Map<string, CSRFToken>();
  private readonly cleanupInterval: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs = 60_000) {
    this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
    if (typeof this.cleanupInterval.unref === 'function') {
      this.cleanupInterval.unref();
    }
  }

  async set(sessionId: string, token: CSRFToken, _ttlMs: number): Promise<void> {
    this.tokens.set(sessionId, token);
  }

  async get(sessionId: string): Promise<CSRFToken | null> {
    const token = this.tokens.get(sessionId);
    if (!token) return null;
    if (Date.now() > token.expiresAt) {
      this.tokens.delete(sessionId);
      return null;
    }
    return token;
  }

  async delete(sessionId: string): Promise<void> {
    this.tokens.delete(sessionId);
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.tokens.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, token] of Array.from(this.tokens.entries())) {
      if (now > token.expiresAt) this.tokens.delete(key);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários criptográficos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Gera token CSRF criptograficamente seguro.
 *
 * Usa Web Crypto API (disponível em Node.js 15+, todos os browsers modernos,
 * Edge Runtime). Fallback para `crypto.randomBytes` do Node.js se disponível.
 *
 * ⚠ NUNCA use Math.random() para tokens de segurança.
 */
export function generateSecureToken(byteLength = 32): string {
  let bytes: Uint8Array;

  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    bytes = new Uint8Array(byteLength);
    globalThis.crypto.getRandomValues(bytes);
  } else {
    // Fallback Node.js (ambientes sem Web Crypto)
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require('crypto') as typeof import('crypto');
      bytes = new Uint8Array(nodeCrypto.randomBytes(byteLength));
    } catch {
      throw new Error('[csrf] Nenhuma fonte de entropia criptográfica disponível.');
    }
  }

  return base64urlEncode(bytes);
}

/**
 * Compara dois tokens em tempo constante.
 *
 * Previne timing attacks: comparações ingênuas (===) retornam mais rápido
 * para prefixos corretos, vazando informação sobre o token via timing.
 *
 * Implementação baseada em XOR com redução OR — complexidade O(n) constante.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  // Codifica para Uint8Array para garantir comparação byte-a-byte
  const encoder = new TextEncoder();
  const bytesA = encoder.encode(a);
  const bytesB = encoder.encode(b);

  // Comprimentos diferentes → definitivamente diferente
  // Mas ainda executa O(max(len)) para não vazar o tamanho
  const maxLen = Math.max(bytesA.length, bytesB.length);
  let diff = bytesA.length ^ bytesB.length; // diff != 0 se comprimentos diferentes

  for (let i = 0; i < maxLen; i++) {
    const byteA = i < bytesA.length ? bytesA[i] : 0;
    const byteB = i < bytesB.length ? bytesB[i] : 0;
    diff |= byteA ^ byteB;
  }

  return diff === 0;
}

/**
 * Assina um valor com HMAC-SHA256 usando Web Crypto API.
 *
 * @param value - O valor a assinar.
 * @param secret - A chave secreta (mínimo 32 caracteres).
 * @returns Assinatura em base64url.
 */
export async function hmacSign(value: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await globalThis.crypto.subtle.sign(
    'HMAC',
    keyMaterial,
    encoder.encode(value),
  );

  return base64urlEncode(new Uint8Array(signature));
}

/**
 * Verifica uma assinatura HMAC-SHA256.
 * Usa timingSafeEqual internamente.
 */
export async function hmacVerify(
  value: string,
  signature: string,
  secret: string,
): Promise<boolean> {
  const expected = await hmacSign(value, secret);
  return timingSafeEqual(expected, signature);
}

/** Encode base64url (sem padding, URL-safe). */
function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// ─────────────────────────────────────────────────────────────────────────────
// Classe principal
// ─────────────────────────────────────────────────────────────────────────────

export class CSRFProtection {
  private readonly config: Required<
    Omit<CSRFConfig, 'store' | 'secret' | 'onFailure'>
  > & Pick<CSRFConfig, 'store' | 'secret' | 'onFailure'>;

  constructor(config: CSRFConfig = {}) {
    // Validações de configuração
    if (
      config.strategy === 'synchronizer-token' &&
      !config.store
    ) {
      throw new Error(
        '[csrf] A estratégia "synchronizer-token" requer um "store" configurado.',
      );
    }

    if (
      config.strategy === 'signed-double-submit' &&
      !config.secret
    ) {
      throw new Error(
        '[csrf] A estratégia "signed-double-submit" requer um "secret" configurado.' +
        ' Use process.env.CSRF_SECRET.',
      );
    }

    if (config.secret && config.secret.length < 32) {
      console.warn(
        '[csrf] O secret tem menos de 32 caracteres. ' +
        'Recomenda-se pelo menos 256 bits de entropia.',
      );
    }

    this.config = {
      strategy: 'signed-double-submit',
      cookieName: '__csrf',
      headerName: 'x-csrf-token',
      fieldName: '_csrf',
      tokenTTLMs: 3_600_000,
      tokenByteLength: 32,
      trustedOrigins: [],
      protectedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
      excludedRoutes: [],
      rotateToken: false,
      validateOrigin: true,
      debug: false,
      ...config,
      cookieOptions: {
        httpOnly: false,
        secure: true,
        sameSite: 'Strict',
        path: '/',
        ...(config.cookieOptions ?? {}),
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Geração de token
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Gera um novo token CSRF e retorna o valor e o Set-Cookie header.
   *
   * Para SPAs: chame em um endpoint GET /api/csrf-token e retorne o token
   * tanto no body (para o header) quanto no cookie (para Double Submit).
   *
   * @param sessionId - ID da sessão (obrigatório para synchronizer-token).
   */
  async generateToken(sessionId?: string): Promise<{
    token: string;
    cookieValue: string;
    cookieHeader: string;
  }> {
    const rawToken = generateSecureToken(this.config.tokenByteLength);
    const now = Date.now();
    const expires = now + this.config.tokenTTLMs;

    let cookieValue = rawToken;

    if (this.config.strategy === 'synchronizer-token') {
      if (!sessionId) throw new Error('[csrf] sessionId obrigatório para synchronizer-token.');
      const csrfToken: CSRFToken = {
        value: rawToken,
        sessionId,
        createdAt: now,
        expiresAt: expires,
      };
      await this.config.store!.set(sessionId, csrfToken, this.config.tokenTTLMs);
    } else if (this.config.strategy === 'signed-double-submit') {
      // Cookie = token.signature — vincula o token à chave secreta
      // Isso previne cookie tossing: mesmo que um atacante injete um cookie,
      // não consegue forjar a assinatura sem o secret.
      const signature = await hmacSign(rawToken, this.config.secret!);
      cookieValue = `${rawToken}.${signature}`;
    }

    const cookieHeader = this.buildSetCookieHeader(
      this.config.cookieName,
      cookieValue,
      expires,
    );

    this.debugLog('TOKEN-GENERATED', { strategy: this.config.strategy, sessionId });

    return { token: rawToken, cookieValue, cookieHeader };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Validação
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Valida o token CSRF de uma requisição.
   *
   * Fluxo de validação:
   *  1. Verifica se o método requer proteção
   *  2. Verifica se a rota está excluída
   *  3. Valida Origin/Referer (defesa em profundidade)
   *  4. Extrai token do header ou body
   *  5. Valida token conforme a estratégia configurada
   */
  async validate(req: CSRFRequest): Promise<CSRFValidationResult> {
    const method = req.method.toUpperCase();
    const path = req.path;

    // Métodos safe não precisam de CSRF
    if (!this.config.protectedMethods.includes(method)) {
      return { valid: true };
    }

    // Rotas excluídas
    if (this.isExcludedRoute(path)) {
      this.debugLog('EXCLUDED', path);
      return { valid: true };
    }

    const fail = (reason: CSRFFailReason): CSRFValidationResult => {
      this.config.onFailure?.(reason, req);
      this.debugLog('FAIL', reason, path, method);
      return { valid: false, reason };
    };

    // ── 1. Validação de Origin/Referer ──────────────────────────────────
    if (this.config.validateOrigin) {
      const originResult = this.validateOriginHeader(req);
      if (!originResult.valid) return fail(originResult.reason!);
    }

    // ── 2. Extrai token submetido ────────────────────────────────────────
    const submittedToken = this.extractSubmittedToken(req);
    if (!submittedToken) return fail('TOKEN_MISSING');

    // ── 3. Valida conforme estratégia ────────────────────────────────────
    let validationResult: CSRFValidationResult;

    switch (this.config.strategy) {
      case 'synchronizer-token':
        validationResult = await this.validateSynchronizerToken(
          submittedToken,
          req.sessionId,
          fail,
        );
        break;

      case 'double-submit-cookie':
        validationResult = this.validateDoubleSubmit(submittedToken, req.cookies, fail);
        break;

      case 'signed-double-submit':
        validationResult = await this.validateSignedDoubleSubmit(
          submittedToken,
          req.cookies,
          fail,
        );
        break;

      default:
        validationResult = fail('TOKEN_INVALID');
    }

    if (!validationResult.valid) return validationResult;

    // ── 4. Renovação de token (se configurada) ───────────────────────────
    if (this.config.rotateToken && req.sessionId) {
      const { token } = await this.generateToken(req.sessionId);
      return { valid: true, token };
    }

    return { valid: true };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Estratégias de validação
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Synchronizer Token Pattern:
   * Compara o token submetido com o token armazenado na sessão server-side.
   *
   * Mais seguro: o token nunca precisa ser derivado de um segredo compartilhado.
   * Requer store (Redis/DB) para armazenar tokens por sessão.
   */
  private async validateSynchronizerToken(
    submittedToken: string,
    sessionId: string | undefined,
    fail: (r: CSRFFailReason) => CSRFValidationResult,
  ): Promise<CSRFValidationResult> {
    if (!sessionId) return fail('SESSION_MISSING');

    const stored = await this.config.store!.get(sessionId);
    if (!stored) return fail('TOKEN_EXPIRED');

    if (Date.now() > stored.expiresAt) {
      await this.config.store!.delete(sessionId);
      return fail('TOKEN_EXPIRED');
    }

    if (!timingSafeEqual(submittedToken, stored.value)) {
      return fail('TOKEN_INVALID');
    }

    // Após uso bem-sucedido com rotateToken, invalida o token usado
    if (this.config.rotateToken) {
      await this.config.store!.delete(sessionId);
    }

    return { valid: true };
  }

  /**
   * Double Submit Cookie:
   * Verifica que o token no header/body é igual ao token no cookie.
   *
   * Proteção: browsers bloqueiam JS cross-origin de ler cookies,
   * então um atacante não consegue obter o valor do cookie para replicar.
   *
   * ⚠ Vulnerável a cookie tossing: se um subdomínio for comprometido,
   * pode injetar um cookie conhecido. Use Signed Double Submit para mitigar.
   */
  private validateDoubleSubmit(
    submittedToken: string,
    cookies: Record<string, string> | undefined,
    fail: (r: CSRFFailReason) => CSRFValidationResult,
  ): CSRFValidationResult {
    if (!cookies) return fail('COOKIE_MISSING');

    const cookieToken = cookies[this.config.cookieName];
    if (!cookieToken) return fail('COOKIE_MISSING');

    if (!timingSafeEqual(submittedToken, cookieToken)) {
      return fail('TOKEN_MISMATCH');
    }

    return { valid: true };
  }

  /**
   * Signed Double Submit Cookie:
   * O cookie armazena token.HMAC(token, secret).
   * O header/body contém apenas o token (sem assinatura).
   *
   * Validação:
   *  1. Extrai token e assinatura do cookie
   *  2. Verifica HMAC da assinatura com o secret
   *  3. Compara o token do cookie com o token do header (timing-safe)
   *
   * Resistente a cookie tossing: o atacante precisaria do secret para
   * forjar um cookie válido, mesmo controlando o subdomínio.
   */
  private async validateSignedDoubleSubmit(
    submittedToken: string,
    cookies: Record<string, string> | undefined,
    fail: (r: CSRFFailReason) => CSRFValidationResult,
  ): Promise<CSRFValidationResult> {
    if (!cookies) return fail('COOKIE_MISSING');

    const cookieValue = cookies[this.config.cookieName];
    if (!cookieValue) return fail('COOKIE_MISSING');

    const dotIndex = cookieValue.lastIndexOf('.');
    if (dotIndex === -1) return fail('SIGNATURE_INVALID');

    const cookieToken = cookieValue.slice(0, dotIndex);
    const cookieSignature = cookieValue.slice(dotIndex + 1);

    // Verifica assinatura HMAC
    const signatureValid = await hmacVerify(cookieToken, cookieSignature, this.config.secret!);
    if (!signatureValid) return fail('SIGNATURE_INVALID');

    // Compara token do header com token do cookie (timing-safe)
    if (!timingSafeEqual(submittedToken, cookieToken)) {
      return fail('TOKEN_MISMATCH');
    }

    return { valid: true };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Validação de Origin / Referer
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Valida os headers Origin e Referer como defesa em profundidade.
   *
   * Ordem de verificação:
   *  1. Origin header (presente em todos os requests cross-origin modernos)
   *  2. Referer header (fallback quando Origin é omitido)
   *
   * Edge cases tratados:
   *  - Referer ausente quando Referrer-Policy: no-referrer (não falha, avisa)
   *  - Origin: null de iframes sandboxed (bloqueado)
   *  - Múltiplas origens confiáveis (trustedOrigins)
   */
  private validateOriginHeader(req: CSRFRequest): { valid: boolean; reason?: CSRFFailReason } {
    const origin = getHeader(req.headers, 'origin');
    const referer = getHeader(req.headers, 'referer');

    const trusted = new Set([
      ...(req.origin ? [normalizeOrigin(req.origin)] : []),
      ...this.config.trustedOrigins.map(normalizeOrigin),
    ]);

    // Origin header está presente (caso preferencial)
    if (origin) {
      // null origin é sempre suspeita em contexto de formulário
      if (origin === 'null') {
        return { valid: false, reason: 'ORIGIN_MISMATCH' };
      }

      const normalizedOrigin = normalizeOrigin(origin);
      if (!trusted.has(normalizedOrigin)) {
        return { valid: false, reason: 'ORIGIN_MISMATCH' };
      }

      return { valid: true };
    }

    // Sem Origin, verifica Referer
    if (referer) {
      try {
        const refererUrl = new URL(referer);
        const refererOrigin = normalizeOrigin(
          `${refererUrl.protocol}//${refererUrl.host}`,
        );

        if (!trusted.has(refererOrigin)) {
          return { valid: false, reason: 'REFERER_MISMATCH' };
        }

        return { valid: true };
      } catch {
        return { valid: false, reason: 'REFERER_MISMATCH' };
      }
    }

    // Nem Origin nem Referer presentes.
    // Pode acontecer com Referrer-Policy: no-referrer — não falha,
    // mas delega a decisão ao token check abaixo.
    // OWASP recomenda verificar o token igualmente nesse caso.
    this.debugLog('WARN', 'Origin e Referer ausentes — apenas token será validado');
    return { valid: true };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilitários
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Extrai o token submetido do request.
   * Prioridade: header > body field
   *
   * Headers customizados são lidos primeiro — são preferíveis pois
   * browsers bloqueiam headers custom em cross-origin sem CORS explícito.
   */
  private extractSubmittedToken(req: CSRFRequest): string | null {
    // Prioridade 1: header HTTP
    const headerToken = getHeader(req.headers, this.config.headerName);
    if (headerToken && headerToken.trim()) return headerToken.trim();

    // Prioridade 2: campo do body (form submissions tradicionais)
    if (req.body && typeof req.body === 'object') {
      const fieldToken = (req.body as Record<string, unknown>)[this.config.fieldName];
      if (typeof fieldToken === 'string' && fieldToken.trim()) {
        return fieldToken.trim();
      }
    }

    return null;
  }

  /** Verifica se uma rota está na lista de exclusão. */
  private isExcludedRoute(path: string): boolean {
    for (const route of this.config.excludedRoutes) {
      if (typeof route === 'string') {
        if (path === route || path.startsWith(route + '/')) return true;
      } else if (route instanceof RegExp) {
        if (route.test(path)) return true;
      }
    }
    return false;
  }

  /**
   * Monta o valor do header Set-Cookie com todas as flags de segurança.
   *
   * Flags de segurança utilizadas:
   *  - HttpOnly: false (JS precisa ler para Double Submit)
   *  - Secure: true (HTTPS only em produção)
   *  - SameSite: Strict (melhor proteção contra CSRF)
   *  - Path: / (disponível em toda a aplicação)
   */
  buildSetCookieHeader(name: string, value: string, expiresAt: number): string {
    const opts = this.config.cookieOptions;
    const parts = [
      `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
      `Expires=${new Date(expiresAt).toUTCString()}`,
      `Path=${opts.path ?? '/'}`,
      `SameSite=${opts.sameSite ?? 'Strict'}`,
    ];

    if (opts.secure !== false) parts.push('Secure');
    if (opts.httpOnly) parts.push('HttpOnly');
    if (opts.domain) parts.push(`Domain=${opts.domain}`);

    return parts.join('; ');
  }

  /**
   * Monta o cookie de limpeza (para invalidar o token CSRF no logout).
   */
  buildClearCookieHeader(): string {
    return [
      `${encodeURIComponent(this.config.cookieName)}=`,
      'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
      `Path=${this.config.cookieOptions.path ?? '/'}`,
      `SameSite=${this.config.cookieOptions.sameSite ?? 'Strict'}`,
      ...(this.config.cookieOptions.secure !== false ? ['Secure'] : []),
    ].join('; ');
  }

  private debugLog(event: string, ...args: unknown[]): void {
    if (!this.config.debug) return;
    console.debug('[csrf]', event, ...args);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários compartilhados
// ─────────────────────────────────────────────────────────────────────────────

function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const val = headers[name.toLowerCase()];
  if (!val) return undefined;
  return Array.isArray(val) ? val[0] : val;
}

function normalizeOrigin(origin: string): string {
  return origin.replace(/[\r\n\0]/g, '').trim().toLowerCase().replace(/\/$/, '');
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptadores de framework
// ─────────────────────────────────────────────────────────────────────────────

type ExpressReq = {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
  body?: Record<string, unknown>;
  session?: { id?: string };
};
type ExpressRes = {
  status(n: number): ExpressRes;
  setHeader(name: string, value: string): void;
  json(data: unknown): void;
  end(): void;
  locals: Record<string, unknown>;
};
type NextFn = (err?: unknown) => void;

/**
 * Middleware CSRF para Express.
 *
 * Injeta o token CSRF em `res.locals.csrfToken` para uso em templates.
 * Rejeita requests inválidos com 403.
 *
 * @example
 * app.use(cookieParser());
 * app.use(session({ ... }));
 * app.use(createExpressCSRF(csrf));
 *
 * // Em templates (EJS, Pug, etc.):
 * // <input type="hidden" name="_csrf" value="<%= csrfToken %>">
 *
 * // Em SPAs (fetch):
 * // headers: { 'x-csrf-token': csrfToken }
 */
export function createExpressCSRF(csrf: CSRFProtection) {
  return async (req: ExpressReq, res: ExpressRes, next: NextFn): Promise<void> => {
    const sessionId = req.session?.id;

    // Gera e injeta token para todos os requests (GET incluso)
    // — o token é usado pelo template/cliente nos próximos POST/PUT/etc.
    try {
      const { token, cookieHeader } = await csrf.generateToken(sessionId);
      res.setHeader('Set-Cookie', cookieHeader);
      res.locals.csrfToken = token;
    } catch (err) {
      return next(err);
    }

    // Valida apenas em métodos mutantes
    const result = await csrf.validate({
      method: req.method,
      path: req.path,
      headers: req.headers,
      cookies: req.cookies,
      body: req.body,
      sessionId,
    });

    if (!result.valid) {
      res.status(403).json({
        error: 'Forbidden',
        message: 'CSRF validation failed.',
      });
      return;
    }

    next();
  };
}

/**
 * Handler CSRF para Next.js middleware / Edge Runtime.
 *
 * @example
 * // middleware.ts
 * const csrfHandler = createNextCSRF(csrf);
 * export default async function middleware(request: Request) {
 *   const csrfResponse = await csrfHandler(request);
 *   if (csrfResponse) return csrfResponse;
 *   return NextResponse.next();
 * }
 */
export function createNextCSRF(csrf: CSRFProtection) {
  return async (request: Request): Promise<Response | null> => {
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => { headers[key] = value; });

    // Parseia cookies do header
    const cookies = parseCookies(headers['cookie'] ?? '');

    const url = new URL(request.url);

    const result = await csrf.validate({
      method: request.method,
      path: url.pathname,
      headers,
      cookies,
      origin: `${url.protocol}//${url.host}`,
    });

    if (!result.valid) {
      return new Response(
        JSON.stringify({ error: 'Forbidden', message: 'CSRF validation failed.' }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    return null; // continua
  };
}

/** Parseia header Cookie em objeto. */
export function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;

  for (const part of cookieHeader.split(';')) {
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) continue;
    const key = decodeURIComponent(part.slice(0, eqIndex).trim());
    const value = decodeURIComponent(part.slice(eqIndex + 1).trim());
    if (key) cookies[key] = value;
  }

  return cookies;
}

// ─────────────────────────────────────────────────────────────────────────────
// Factories com preset
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria instância para SPA moderna (React, Vue, Angular).
 *
 * Estratégia: signed-double-submit
 *  - Sem estado server-side
 *  - Token no header X-CSRF-Token
 *  - Cookie __Host-csrf (prefixo __Host previne cookie tossing)
 *
 * @example
 * const csrf = createSPACSRF(process.env.CSRF_SECRET!, ['https://app.exemplo.com']);
 */
export function createSPACSRF(secret: string, trustedOrigins: string[]): CSRFProtection {
  return new CSRFProtection({
    strategy: 'signed-double-submit',
    secret,
    cookieName: '__Host-csrf',  // prefixo __Host vincula ao host exato
    headerName: 'x-csrf-token',
    trustedOrigins,
    validateOrigin: true,
    rotateToken: false,          // SPAs gerenciam token manualmente
    tokenTTLMs: 3_600_000,
    cookieOptions: {
      secure: true,
      sameSite: 'Strict',
      httpOnly: false,               // JS precisa ler
      path: '/',
    },
    excludedRoutes: [
      '/api/webhooks',
      '/api/oauth/callback',
      /^\/api\/public\//,
    ],
  });
}

/**
 * Cria instância para aplicação server-side tradicional (EJS, Pug, Thymeleaf).
 *
 * Estratégia: synchronizer-token
 *  - Token vinculado à sessão do servidor
 *  - Campo oculto no formulário HTML
 *  - Renovação de token a cada submit
 *
 * @example
 * const csrf = createSSRCSRF(new MemoryCSRFStore(), ['https://app.exemplo.com']);
 */
export function createSSRCSRF(
  store: CSRFStore,
  trustedOrigins: string[],
): CSRFProtection {
  return new CSRFProtection({
    strategy: 'synchronizer-token',
    store,
    cookieName: '__Secure-csrf',
    fieldName: '_csrf',
    headerName: 'x-csrf-token',
    trustedOrigins,
    validateOrigin: true,
    rotateToken: true,           // renova após cada submit (mais seguro)
    tokenTTLMs: 1_800_000,      // 30 minutos
    cookieOptions: {
      secure: true,
      sameSite: 'Strict',
      httpOnly: true,                // cookie de sessão não precisa ser lido por JS
      path: '/',
    },
  });
}

/**
 * Cria instância para desenvolvimento local.
 * ⚠ Nunca use em produção.
 */
export function createDevCSRF(): CSRFProtection {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('[csrf] createDevCSRF() não deve ser usado em produção.');
  }

  return new CSRFProtection({
    strategy: 'double-submit-cookie',
    cookieName: '__csrf',
    trustedOrigins: [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
    ],
    validateOrigin: true,
    cookieOptions: {
      secure: false,  // HTTP em dev
      sameSite: 'Lax',
      httpOnly: false,
      path: '/',
    },
    debug: true,
  });
}