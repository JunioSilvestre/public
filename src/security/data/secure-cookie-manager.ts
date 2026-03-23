/**
 * @fileoverview Secure Cookie Manager — Gerencia cookies com atributos de segurança.
 *
 * Garante uso de HttpOnly (via server-side), Secure, SameSite e Path
 * em todos os cookies criados pela aplicação.
 *
 * @module security/data
 */

export interface CookieOptions {
    /** Expiração em segundos. Default: sessão. */
    maxAge?: number;
    /** Path do cookie. Default: '/'. */
    path?: string;
    /** Apenas HTTPS. Default: true em produção. */
    secure?: boolean;
    /** Política SameSite. Default: 'Lax'. */
    sameSite?: 'Strict' | 'Lax' | 'None';
    /** Domínio do cookie. */
    domain?: string;
}

const IS_PRODUCTION = typeof window !== 'undefined' && window.location.protocol === 'https:';

/**
 * Define um cookie com atributos de segurança.
 *
 * ⚠ Nota: HttpOnly só pode ser definido via header Set-Cookie no server-side.
 * Esta função é para cookies client-side (não-HttpOnly).
 */
export function setSecureCookie(name: string, value: string, options: CookieOptions = {}): void {
    if (typeof document === 'undefined') return;

    const {
        maxAge,
        path = '/',
        secure = IS_PRODUCTION,
        sameSite = 'Lax',
        domain,
    } = options;

    const parts = [
        `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
        `Path=${path}`,
        `SameSite=${sameSite}`,
    ];

    if (maxAge !== undefined) parts.push(`Max-Age=${maxAge}`);
    if (secure) parts.push('Secure');
    if (domain) parts.push(`Domain=${domain}`);

    document.cookie = parts.join('; ');
}

/**
 * Obtém o valor de um cookie pelo nome.
 */
export function getCookie(name: string): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(
        new RegExp(`(?:^|;\\s*)${escapeRegex(name)}=([^;]*)`)
    );
    return match ? decodeURIComponent(match[1]!) : null;
}

/**
 * Remove um cookie definindo Max-Age=0.
 */
export function removeCookie(name: string, path = '/'): void {
    if (typeof document === 'undefined') return;
    document.cookie = `${encodeURIComponent(name)}=; Path=${path}; Max-Age=0`;
}

function escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
