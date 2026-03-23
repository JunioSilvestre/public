/**
 * @fileoverview Cookie Policy — Regras de uso e armazenamento de cookies.
 *
 * Define categorias de cookies e funções de conformidade com LGPD/GDPR.
 *
 * @module security/data
 */

/** Categorias de cookies conforme regulamentações de privacidade. */
export type CookieCategory = 'necessary' | 'functional' | 'analytics' | 'marketing';

export interface CookiePolicy {
    name: string;
    category: CookieCategory;
    description: string;
    maxAge: number;
    required: boolean;
}

/** Políticas de cookies registradas na aplicação. */
export const COOKIE_POLICIES: CookiePolicy[] = [
    {
        name: '__csrf_token',
        category: 'necessary',
        description: 'Token de proteção contra CSRF. Essencial para segurança.',
        maxAge: 3600,
        required: true,
    },
    {
        name: '__session',
        category: 'necessary',
        description: 'Identificador de sessão do usuário.',
        maxAge: 86400,
        required: true,
    },
    {
        name: '__consent',
        category: 'necessary',
        description: 'Armazena as preferências de consentimento de cookies.',
        maxAge: 31536000, // 1 ano
        required: true,
    },
];

/**
 * Verifica se uma categoria de cookie foi consentida pelo usuário.
 */
export function isCategoryConsented(category: CookieCategory): boolean {
    if (category === 'necessary') return true; // sempre permitido
    if (typeof document === 'undefined') return false;

    const consent = document.cookie.match(/(?:^|;\s*)__consent=([^;]*)/);
    if (!consent) return false;

    try {
        const consented: string[] = JSON.parse(decodeURIComponent(consent[1]!));
        return consented.includes(category);
    } catch {
        return false;
    }
}

/**
 * Retorna cookies que NÃO deveriam existir sem consentimento.
 */
export function getUnconsentedCookies(): string[] {
    if (typeof document === 'undefined') return [];

    const nonRequiredPolicies = COOKIE_POLICIES.filter((p) => !p.required);
    const unconsentedCategories = new Set(
        nonRequiredPolicies
            .map((p) => p.category)
            .filter((c) => !isCategoryConsented(c)),
    );

    return nonRequiredPolicies
        .filter((p) => unconsentedCategories.has(p.category))
        .map((p) => p.name);
}
