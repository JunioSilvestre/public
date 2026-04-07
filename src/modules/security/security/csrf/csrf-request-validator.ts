/**
 * @fileoverview CSRF Request Validator — Valida tokens CSRF em requisições mutáveis.
 *
 * Garante que requisições POST, PUT, DELETE, PATCH incluam o token CSRF
 * correto antes de serem processadas.
 *
 * @module security/csrf
 */

import { CSRF_HEADER_NAME, getCSRFToken } from './csrf-token-manager';

/** Métodos HTTP que requerem validação CSRF. */
const MUTABLE_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

/**
 * Valida se uma requisição inclui o token CSRF correto.
 *
 * @param method — O método HTTP da requisição.
 * @param headers — Os headers da requisição (ou o valor do header X-CSRF-Token).
 * @returns `true` se a requisição é válida, `false` caso contrário.
 *
 * @example
 * ```ts
 * if (!validateCSRFRequest('POST', request.headers)) {
 *   return new Response('CSRF token inválido', { status: 403 });
 * }
 * ```
 */
export function validateCSRFRequest(
    method: string,
    headers: Record<string, string | string[] | undefined> | Headers,
): boolean {
    // GET, HEAD, OPTIONS não precisam de CSRF
    if (!MUTABLE_METHODS.has(method.toUpperCase())) return true;

    const expectedToken = getCSRFToken();
    if (!expectedToken) return false;

    let headerToken: string | null = null;
    if (headers instanceof Headers) {
        headerToken = headers.get(CSRF_HEADER_NAME);
    } else {
        const val = headers[CSRF_HEADER_NAME];
        headerToken = typeof val === 'string' ? val : null;
    }

    if (!headerToken) return false;

    // Comparação em tempo constante
    return timingSafeStringEqual(expectedToken, headerToken);
}

/**
 * Comparação em tempo constante para prevenir timing attack.
 */
function timingSafeStringEqual(a: string, b: string): boolean {
    const encoder = new TextEncoder();
    const ba = encoder.encode(a);
    const bb = encoder.encode(b);
    let diff = ba.length ^ bb.length;
    const max = Math.max(ba.length, bb.length);
    for (let i = 0; i < max; i++) {
        diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
    }
    return diff === 0;
}

/**
 * Wrapper para fetch que automaticamente inclui o token CSRF.
 *
 * @example
 * ```ts
 * const response = await csrfFetch('/api/data', { method: 'POST', body: '...' });
 * ```
 */
export async function csrfFetch(
    url: string | URL | Request,
    init: RequestInit = {},
): Promise<Response> {
    const token = getCSRFToken();
    const headers = new Headers(init.headers);

    if (token && MUTABLE_METHODS.has((init.method ?? 'GET').toUpperCase())) {
        headers.set(CSRF_HEADER_NAME, token);
    }

    return fetch(url, { ...init, headers });
}
