/**
 * @arquivo     src/security/index.ts
 * @módulo      Security / Índice Principal
 * @descrição   Ponto de entrada centralizado para todos os módulos de segurança do PRJ-BASE.
 *              Reexporta as APIs de: XSS, CSRF, Sanitização, Validação,
 *              Proteção de Dados, Segurança de API e Security Headers.
 *
 * @como-usar   import { sanitizeHtml, validateEmail, createSecureFetch } from '@/security';
 *
 * @dependências Todos os submódulos de src/security/
 * @notas       Importe sempre por este arquivo — não acesse submódulos diretamente
 *              para garantir que as APIs públicas sejam estáveis.
 *
 * @módulo security
 */

// ── XSS Protection ──────────────────────────────────────────────────────────
export { sanitizeHtml, sanitizeTextOnly, sanitizeHtmlToFragment } from './xss';
export { escapeHtml, escapeHtmlAttr, escapeUrl, escapeJs, escapeCss } from './xss';

// ── CSRF Protection ─────────────────────────────────────────────────────────
export { initCSRFProtection, getCSRFHeaders, generateCSRFToken } from './csrf/csrf-token-manager';
export { validateCSRFRequest, csrfFetch } from './csrf/csrf-request-validator';

// ── Input Sanitization ──────────────────────────────────────────────────────
export { sanitizeInput, sanitizeEmail, sanitizePhone, sanitizeUsername, sanitizeText } from './sanitize/input';
export { sanitizeUrl, isRelativeUrl, isSameOrigin } from './sanitize/url';

// ── Validation ──────────────────────────────────────────────────────────────
export { validateEmail, validatePhone, validateCPF, validateCNPJ, validatePassword } from './validation/input-validator';
export { validateForm } from './validation/form-security-validator';

// ── Data Protection ─────────────────────────────────────────────────────────
export { secureLocalStorage, secureSessionStorage } from './data/secure-storage';
export { setSecureCookie, getCookie, removeCookie } from './data/secure-cookie-manager';
export { containsSensitiveData, auditClientStorage } from './data/sensitive-data-guard';

// ── API Security ────────────────────────────────────────────────────────────
export { createSecureFetch } from './api/request-security-interceptor';
export { ClientRateLimiter, globalRateLimiter } from './api/request-rate-limiter';
export { throttle, debounce } from './api/api-request-throttle';

// ── Security Headers ────────────────────────────────────────────────────────
export { getSecurityHeaders } from './headers';
