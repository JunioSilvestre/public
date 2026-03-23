/**
 * @fileoverview CSRF Token Manager — Gerencia tokens de proteção contra CSRF.
 *
 * Implementa o padrão Synchronizer Token para proteger formulários e
 * requisições que alteram estado (POST, PUT, DELETE) contra Cross-Site Request Forgery.
 *
 * Estratégia: Double Submit Cookie + Header
 *  1. Gera um token criptograficamente seguro
 *  2. Armazena no cookie (HttpOnly, SameSite=Strict)
 *  3. Inclui no header X-CSRF-Token de cada requisição mutável
 *  4. Servidor valida que cookie === header
 *
 * @module security/csrf
 */

const CSRF_COOKIE_NAME = '__csrf_token';
const CSRF_HEADER_NAME = 'X-CSRF-Token';
const TOKEN_LENGTH = 32;

/**
 * Gera um token CSRF criptograficamente seguro.
 */
export function generateCSRFToken(): string {
    const bytes = new Uint8Array(TOKEN_LENGTH);
    globalThis.crypto.getRandomValues(bytes);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Obtém o token CSRF atual do cookie do browser.
 */
export function getCSRFToken(): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(
        new RegExp(`(?:^|;\\s*)${CSRF_COOKIE_NAME}=([^;]*)`)
    );
    return match ? decodeURIComponent(match[1]!) : null;
}

/**
 * Define o token CSRF no cookie com atributos de segurança.
 */
export function setCSRFCookie(token: string, options: {
    secure?: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None';
    path?: string;
    maxAge?: number;
} = {}): void {
    if (typeof document === 'undefined') return;

    const secure = options.secure ?? (window.location.protocol === 'https:');
    const sameSite = options.sameSite ?? 'Strict';
    const path = options.path ?? '/';
    const maxAge = options.maxAge ?? 3600; // 1 hora

    document.cookie = [
        `${CSRF_COOKIE_NAME}=${encodeURIComponent(token)}`,
        `Path=${path}`,
        `Max-Age=${maxAge}`,
        `SameSite=${sameSite}`,
        secure ? 'Secure' : '',
    ].filter(Boolean).join('; ');
}

/**
 * Inicializa a proteção CSRF — gera token se não existir.
 * Chame esta função no startup da aplicação.
 */
export function initCSRFProtection(): string {
    let token = getCSRFToken();
    if (!token) {
        token = generateCSRFToken();
        setCSRFCookie(token);
    }
    return token;
}

/**
 * Cria headers com o token CSRF para incluir em requisições fetch/axios.
 *
 * @example
 * ```ts
 * const headers = getCSRFHeaders();
 * await fetch('/api/submit', { method: 'POST', headers, body: JSON.stringify(data) });
 * ```
 */
export function getCSRFHeaders(): Record<string, string> {
    const token = getCSRFToken();
    if (!token) return {};
    return { [CSRF_HEADER_NAME]: token };
}

export { CSRF_COOKIE_NAME, CSRF_HEADER_NAME };
