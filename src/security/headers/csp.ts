/**
 * @fileoverview Content Security Policy (CSP) — Geração de header CSP.
 *
 * Configura diretrizes CSP para controlar quais recursos o browser pode carregar.
 * Bloqueia execução de scripts inline e recursos de origens não autorizadas.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
 */

export interface CSPDirectives {
    'default-src'?: string[];
    'script-src'?: string[];
    'style-src'?: string[];
    'img-src'?: string[];
    'font-src'?: string[];
    'connect-src'?: string[];
    'frame-src'?: string[];
    'frame-ancestors'?: string[];
    'base-uri'?: string[];
    'form-action'?: string[];
    'object-src'?: string[];
    'media-src'?: string[];
    'worker-src'?: string[];
    'manifest-src'?: string[];
    'upgrade-insecure-requests'?: boolean;
    'block-all-mixed-content'?: boolean;
}

const DEFAULT_CSP: CSPDirectives = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-eval'", "'unsafe-inline'", 'https://www.google.com', 'https://www.gstatic.com', 'https://challenges.cloudflare.com'],
    'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    'img-src': ["'self'", 'data:', 'https:', 'blob:'],
    'font-src': ["'self'", 'https://fonts.gstatic.com'],
    'connect-src': ["'self'", 'https:', 'wss:'],
    'frame-src': ["'self'", 'https://www.google.com', 'https://challenges.cloudflare.com'],
    'frame-ancestors': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'object-src': ["'none'"],
    'upgrade-insecure-requests': true,
};

/**
 * Gera a string do header Content-Security-Policy.
 *
 * @param overrides — Diretrizes para sobrescrever os defaults.
 * @returns A string CSP formatada.
 *
 * @example
 * ```ts
 * const csp = generateCSPHeader({ 'script-src': ["'self'", 'https://cdn.example.com'] });
 * response.headers.set('Content-Security-Policy', csp);
 * ```
 */
export function generateCSPHeader(overrides: Partial<CSPDirectives> = {}): string {
    const merged = { ...DEFAULT_CSP, ...overrides };
    const parts: string[] = [];

    for (const [key, value] of Object.entries(merged)) {
        if (value === true) {
            parts.push(key);
        } else if (value === false) {
            continue;
        } else if (Array.isArray(value)) {
            parts.push(`${key} ${value.join(' ')}`);
        }
    }

    return parts.join('; ');
}
