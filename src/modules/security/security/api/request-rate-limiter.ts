/**
 * @fileoverview Request Rate Limiter — Controle de frequência de requisições client-side.
 *
 * Limita o número de requisições por intervalo de tempo para evitar abuso.
 *
 * @module security/api
 */

export interface RateLimiterConfig {
    /** Número máximo de requisições por janela. Default: 60 */
    maxRequests?: number;
    /** Janela de tempo em ms. Default: 60000 (1 min) */
    windowMs?: number;
}

/**
 * Rate limiter simples por chave (endpoint, ação, etc).
 */
export class ClientRateLimiter {
    private readonly maxRequests: number;
    private readonly windowMs: number;
    private readonly requests = new Map<string, number[]>();

    constructor(config: RateLimiterConfig = {}) {
        this.maxRequests = config.maxRequests ?? 60;
        this.windowMs = config.windowMs ?? 60_000;
    }

    /**
     * Verifica se uma requisição é permitida para a chave dada.
     *
     * @param key — Identificador da ação (ex: 'login', 'search', '/api/users')
     * @returns `true` se permitido, `false` se rate-limited.
     */
    allow(key: string): boolean {
        const now = Date.now();
        const timestamps = this.requests.get(key) ?? [];

        // Remove timestamps fora da janela
        const recent = timestamps.filter((t) => now - t < this.windowMs);

        if (recent.length >= this.maxRequests) {
            this.requests.set(key, recent);
            return false;
        }

        recent.push(now);
        this.requests.set(key, recent);
        return true;
    }

    /**
     * Retorna quantas requisições restam na janela atual.
     */
    remaining(key: string): number {
        const now = Date.now();
        const timestamps = this.requests.get(key) ?? [];
        const recent = timestamps.filter((t) => now - t < this.windowMs);
        return Math.max(0, this.maxRequests - recent.length);
    }

    /**
     * Reset do rate limiter para uma chave.
     */
    reset(key: string): void {
        this.requests.delete(key);
    }

    /**
     * Reset total.
     */
    resetAll(): void {
        this.requests.clear();
    }
}

/** Instância singleton global. */
export const globalRateLimiter = new ClientRateLimiter();
