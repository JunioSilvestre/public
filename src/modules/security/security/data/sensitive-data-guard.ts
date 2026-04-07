/**
 * @fileoverview Sensitive Data Guard — Previne armazenamento de dados sensíveis no client-side.
 *
 * Monitora e bloqueia tentativas de armazenar tokens, chaves de API, PII e outros
 * dados sensíveis em localStorage, sessionStorage ou cookies não-HttpOnly.
 *
 * @module security/data
 */

/** Padrões que indicam dados sensíveis — nunca devem estar em client storage. */
const SENSITIVE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, label: 'JWT token' },
    { pattern: /^(sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]+$/, label: 'API key (Stripe-like)' },
    { pattern: /^AKIA[0-9A-Z]{16}$/, label: 'AWS Access Key' },
    { pattern: /^ghp_[a-zA-Z0-9]{36}$/, label: 'GitHub PAT' },
    { pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i, label: 'Bearer token' },
    { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, label: 'Private key' },
    { pattern: /\b\d{3}-\d{2}-\d{4}\b/, label: 'SSN-like pattern' },
    { pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, label: 'Credit card number' },
];

/** Chaves de storage que nunca devem conter dados sensíveis. */
const SENSITIVE_KEY_PATTERNS = [
    /token/i, /secret/i, /password/i, /passwd/i, /api.?key/i,
    /private.?key/i, /access.?key/i, /auth/i, /credential/i,
    /credit.?card/i, /ssn/i, /cpf/i, /cnpj/i,
];

/**
 * Verifica se um valor contém dados sensíveis.
 */
export function containsSensitiveData(value: string): { sensitive: boolean; label?: string } {
    for (const { pattern, label } of SENSITIVE_PATTERNS) {
        if (pattern.test(value)) {
            return { sensitive: true, label };
        }
    }
    return { sensitive: false };
}

/**
 * Verifica se uma chave de storage sugere dados sensíveis.
 */
export function isSensitiveKey(key: string): boolean {
    return SENSITIVE_KEY_PATTERNS.some((p) => p.test(key));
}

/**
 * Audita o storage do browser em busca de dados sensíveis.
 *
 * @returns Array de findings — cada um com tipo, chave e label do dado sensível.
 */
export function auditClientStorage(): Array<{ type: string; key: string; label: string }> {
    const findings: Array<{ type: string; key: string; label: string }> = [];
    if (typeof window === 'undefined') return findings;

    for (const [storageType, storage] of [
        ['localStorage', window.localStorage],
        ['sessionStorage', window.sessionStorage],
    ] as const) {
        for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i);
            if (!key) continue;

            if (isSensitiveKey(key)) {
                findings.push({ type: storageType, key, label: 'Chave sugere dado sensível' });
            }

            const value = storage.getItem(key) ?? '';
            const check = containsSensitiveData(value);
            if (check.sensitive) {
                findings.push({ type: storageType, key, label: check.label! });
            }
        }
    }

    return findings;
}
