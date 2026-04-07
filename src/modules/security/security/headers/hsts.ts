/**
 * @fileoverview HSTS — Strict Transport Security header.
 *
 * Força browsers a usar HTTPS para todas as requisições ao domínio.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
 */

export interface HSTSOptions {
    /** Tempo em segundos que o browser deve lembrar a política HSTS. Default: 2 anos. */
    maxAge?: number;
    /** Aplica a todos os subdomínios. Default: true. */
    includeSubDomains?: boolean;
    /** Permite inclusão na lista de preload de HSTS dos browsers. Default: true. */
    preload?: boolean;
}

/**
 * Gera o header Strict-Transport-Security.
 *
 * @example
 * ```ts
 * response.headers.set('Strict-Transport-Security', generateHSTSHeader());
 * // → "max-age=63072000; includeSubDomains; preload"
 * ```
 */
export function generateHSTSHeader(options: HSTSOptions = {}): string {
    const maxAge = options.maxAge ?? 63072000; // 2 anos
    const includeSubDomains = options.includeSubDomains ?? true;
    const preload = options.preload ?? true;

    let header = `max-age=${maxAge}`;
    if (includeSubDomains) header += '; includeSubDomains';
    if (preload) header += '; preload';

    return header;
}
