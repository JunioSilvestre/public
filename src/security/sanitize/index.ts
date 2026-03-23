/**
 * @fileoverview Sanitize Module — Ponto de entrada para sanitização de dados.
 *
 * @module security/sanitize
 */

export { sanitizeInput, sanitizeEmail, sanitizePhone, sanitizeUsername, sanitizeText, sanitizeDocument } from './input';
export { sanitizeUrl, isRelativeUrl, isSameOrigin } from './url';
export { sanitizeHtml, sanitizeTextOnly, sanitizeHtmlToFragment } from './html';
