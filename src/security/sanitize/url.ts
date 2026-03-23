/**
 * @fileoverview URL Sanitizer — Sanitização e validação de URLs.
 *
 * Valida e normaliza URLs para prevenir open redirects, SSRF e protocol injection.
 *
 * @module security/sanitize
 */

/** Protocolos seguros para URLs navegáveis. */
const SAFE_PROTOCOLS = new Set(['http:', 'https:', 'mailto:', 'tel:']);

/** Protocolos perigosos que NUNCA devem ser permitidos. */
const BLOCKED_PROTOCOLS = new Set([
    'javascript:', 'vbscript:', 'data:', 'blob:',
    'filesystem:', 'jar:', 'livescript:', 'mocha:',
]);

/**
 * Valida e sanitiza uma URL.
 *
 * @param url — URL a ser validada.
 * @param allowedHosts — Lista de hosts permitidos (para prevenir open redirect). Null = qualquer host.
 * @returns URL sanitizada ou '#' se inválida/perigosa.
 */
export function sanitizeUrl(url: string, allowedHosts: string[] | null = null): string {
    if (typeof url !== 'string' || url.trim() === '') return '#';

    const cleaned = url
        .replace(/\0/g, '')
        .replace(/[\r\n\t]/g, '')
        .trim();

    // URLs relativas são seguras
    if (/^(\/[^/]|#|\.\/)/.test(cleaned)) {
        // Mas verificar se não tem protocol injection embutido
        if (/javascript\s*:/i.test(cleaned) || /vbscript\s*:/i.test(cleaned)) {
            return '#';
        }
        return encodeURI(cleaned);
    }

    try {
        const parsed = new URL(cleaned);

        // Verificar protocolo
        if (BLOCKED_PROTOCOLS.has(parsed.protocol.toLowerCase())) {
            return '#';
        }
        if (!SAFE_PROTOCOLS.has(parsed.protocol.toLowerCase())) {
            return '#';
        }

        // Verificar host allowed (proteção contra open redirect)
        if (allowedHosts && !allowedHosts.includes(parsed.hostname)) {
            return '#';
        }

        return parsed.href;
    } catch {
        return '#';
    }
}

/**
 * Verifica se uma URL é relativa (segura para navegação interna).
 */
export function isRelativeUrl(url: string): boolean {
    return /^(\/[^/]|#|\.\/)/.test(url.trim());
}

/**
 * Verifica se uma URL pertence ao mesmo domínio.
 */
export function isSameOrigin(url: string): boolean {
    if (typeof window === 'undefined') return false;
    try {
        const parsed = new URL(url, window.location.origin);
        return parsed.origin === window.location.origin;
    } catch {
        return false;
    }
}
