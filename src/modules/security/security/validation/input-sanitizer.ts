/**
 * @fileoverview Input Sanitizer — Ponte entre os módulos de validação e sanitização.
 *
 * Reexporta sanitização do módulo sanitize para manter a API consistente.
 *
 * @module security/validation
 */

export { sanitizeInput, sanitizeEmail, sanitizePhone, sanitizeUsername, sanitizeText } from '../sanitize/input';
