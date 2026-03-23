/**
 * @fileoverview HTML Sanitizer — Wrapper simplificado para sanitização de HTML.
 *
 * Reexporta funções do módulo XSS principal para manter a API do pacote sanitize consistente.
 *
 * @module security/sanitize
 */

// Reexporta do módulo XSS principal (que tem a implementação completa com DOMPurify)
export { sanitizeHtml, sanitizeTextOnly, sanitizeHtmlToFragment } from '../xss';
