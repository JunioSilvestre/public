/**
 * @fileoverview Request Security Interceptor — Intercepta requisições para adicionar segurança.
 *
 * Adiciona headers de segurança (CSRF, Authorization, Content-Type)
 * automaticamente em todas as requisições fetch/axios.
 *
 * @module security/api
 */

import { getCSRFHeaders } from '../csrf/csrf-token-manager';

/** Métodos que requerem CSRF token. */
const MUTABLE_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

export interface InterceptorConfig {
    /** Adicionar CSRF token automaticamente. Default: true */
    csrf?: boolean;
    /** Headers customizados para adicionar a todas as requests. */
    customHeaders?: Record<string, string>;
    /** Timeout em ms. Default: 30000 */
    timeout?: number;
    /** Base URL para requests relativas. */
    baseUrl?: string;
}

const DEFAULT_CONFIG: InterceptorConfig = {
    csrf: true,
    timeout: 30000,
};

/**
 * Cria um wrapper de fetch com interceptors de segurança.
 *
 * @example
 * ```ts
 * const api = createSecureFetch({ baseUrl: '/api' });
 * const data = await api.get('/users');
 * await api.post('/users', { name: 'João' });
 * ```
 */
export function createSecureFetch(config: InterceptorConfig = {}) {
    const cfg = { ...DEFAULT_CONFIG, ...config };

    async function secureFetch(url: string, init: RequestInit = {}): Promise<Response> {
        const fullUrl = cfg.baseUrl ? `${cfg.baseUrl}${url}` : url;
        const method = (init.method ?? 'GET').toUpperCase();
        const headers = new Headers(init.headers);

        // Content-Type default para JSON
        if (!headers.has('Content-Type') && MUTABLE_METHODS.has(method)) {
            headers.set('Content-Type', 'application/json');
        }

        // CSRF token para métodos mutáveis
        if (cfg.csrf && MUTABLE_METHODS.has(method)) {
            const csrfHeaders = getCSRFHeaders();
            for (const [key, value] of Object.entries(csrfHeaders)) {
                headers.set(key, value);
            }
        }

        // Headers customizados
        if (cfg.customHeaders) {
            for (const [key, value] of Object.entries(cfg.customHeaders)) {
                headers.set(key, value);
            }
        }

        // Timeout via AbortController
        const controller = new AbortController();
        const timeoutId = cfg.timeout
            ? setTimeout(() => controller.abort(), cfg.timeout)
            : null;

        try {
            return await fetch(fullUrl, {
                ...init,
                method,
                headers,
                signal: controller.signal,
                credentials: init.credentials ?? 'same-origin',
            });
        } finally {
            if (timeoutId) clearTimeout(timeoutId);
        }
    }

    return {
        fetch: secureFetch,
        get: (url: string, init?: RequestInit) => secureFetch(url, { ...init, method: 'GET' }),
        post: (url: string, body?: unknown, init?: RequestInit) =>
            secureFetch(url, { ...init, method: 'POST', body: body ? JSON.stringify(body) : undefined }),
        put: (url: string, body?: unknown, init?: RequestInit) =>
            secureFetch(url, { ...init, method: 'PUT', body: body ? JSON.stringify(body) : undefined }),
        delete: (url: string, init?: RequestInit) => secureFetch(url, { ...init, method: 'DELETE' }),
    };
}
