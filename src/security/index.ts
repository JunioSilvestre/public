/**
 * @fileoverview Security Module — Ponto de entrada principal para todos os módulos de segurança.
 *
 * Importações centralizadas para o sistema de segurança do PRJ-BASE.
 * Use este arquivo para acessar todas as APIs de segurança.
 *
 * @module security
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
