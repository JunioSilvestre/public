/**
 * @fileoverview Security Headers — Configuração e geração de headers de segurança.
 *
 * Exporta funções para gerar headers CSP, HSTS, Permissions-Policy e outros.
 * Usado pelo middleware.ts e next.config.mjs.
 *
 * @module security/headers
 */

import { generateCSPHeader } from './csp';
import { generateHSTSHeader } from './hsts';
import { generatePermissionsPolicyHeader } from './permissions';

export { generateCSPHeader, type CSPDirectives } from './csp';
export { generateHSTSHeader, type HSTSOptions } from './hsts';
export { generatePermissionsPolicyHeader, type PermissionsPolicyOptions } from './permissions';

/**
 * Gera o conjunto completo de security headers recomendados.
 */
export function getSecurityHeaders(): Array<{ key: string; value: string }> {
    return [
        { key: 'Content-Security-Policy', value: generateCSPHeader() },
        { key: 'Strict-Transport-Security', value: generateHSTSHeader() },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-XSS-Protection', value: '0' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Permissions-Policy', value: generatePermissionsPolicyHeader() },
        { key: 'X-DNS-Prefetch-Control', value: 'on' },
    ];
}
