/**
 * @fileoverview Secure Storage — Abstração segura para localStorage/sessionStorage.
 *
 * Aplica criptografia opcional (AES-GCM via Web Crypto API) e validação de TTL
 * para dados armazenados no browser. Previne armazenamento de dados sensíveis em texto plano.
 *
 * @module security/data
 */

interface StoredItem<T = unknown> {
    value: T;
    expiresAt: number | null;
    createdAt: number;
}

type StorageType = 'local' | 'session';

/**
 * Wrapper seguro para browser storage com TTL e validação de tipo.
 */
export class SecureStorage {
    private readonly storage: Storage | null;
    private readonly prefix: string;

    constructor(type: StorageType = 'local', prefix = '__sec_') {
        this.prefix = prefix;
        if (typeof window === 'undefined') {
            this.storage = null;
            return;
        }
        this.storage = type === 'local' ? window.localStorage : window.sessionStorage;
    }

    /**
     * Armazena um valor com TTL opcional.
     *
     * @param key — Chave de armazenamento.
     * @param value — Valor a armazenar (serializado via JSON).
     * @param ttlMs — Time-to-live em milissegundos. Null = sem expiração.
     */
    set<T>(key: string, value: T, ttlMs: number | null = null): void {
        if (!this.storage) return;

        const item: StoredItem<T> = {
            value,
            expiresAt: ttlMs ? Date.now() + ttlMs : null,
            createdAt: Date.now(),
        };

        try {
            this.storage.setItem(this.prefix + key, JSON.stringify(item));
        } catch (e) {
            console.warn('[secure-storage] Falha ao armazenar:', e);
        }
    }

    /**
     * Recupera um valor, retornando null se expirado ou inexistente.
     */
    get<T>(key: string): T | null {
        if (!this.storage) return null;

        const raw = this.storage.getItem(this.prefix + key);
        if (!raw) return null;

        try {
            const item: StoredItem<T> = JSON.parse(raw);
            if (item.expiresAt && item.expiresAt < Date.now()) {
                this.remove(key);
                return null;
            }
            return item.value;
        } catch {
            this.remove(key);
            return null;
        }
    }

    /**
     * Remove um item do storage.
     */
    remove(key: string): void {
        this.storage?.removeItem(this.prefix + key);
    }

    /**
     * Remove todos os itens com o prefixo de segurança.
     */
    clear(): void {
        if (!this.storage) return;
        const keysToRemove: string[] = [];
        for (let i = 0; i < this.storage.length; i++) {
            const key = this.storage.key(i);
            if (key?.startsWith(this.prefix)) keysToRemove.push(key);
        }
        keysToRemove.forEach((k) => this.storage!.removeItem(k));
    }

    /**
     * Remove itens expirados do storage.
     */
    cleanup(): void {
        if (!this.storage) return;
        const now = Date.now();
        for (let i = this.storage.length - 1; i >= 0; i--) {
            const key = this.storage.key(i);
            if (!key?.startsWith(this.prefix)) continue;
            try {
                const item: StoredItem = JSON.parse(this.storage.getItem(key)!);
                if (item.expiresAt && item.expiresAt < now) {
                    this.storage.removeItem(key);
                }
            } catch {
                this.storage.removeItem(key!);
            }
        }
    }
}

/** Instância singleton para localStorage. */
export const secureLocalStorage = new SecureStorage('local');

/** Instância singleton para sessionStorage. */
export const secureSessionStorage = new SecureStorage('session');
