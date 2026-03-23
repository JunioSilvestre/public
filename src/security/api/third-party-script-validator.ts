/**
 * @fileoverview Third-Party Script Validator — Valida integridade de scripts de terceiros.
 *
 * Verifica scripts externos contra hashes SRI (Subresource Integrity) e
 * monitora carregamento de scripts não autorizados.
 *
 * @module security/api
 */

export interface TrustedScript {
    /** URL do script. */
    src: string;
    /** Hash SRI esperado (sha256-, sha384- ou sha512-). */
    integrity?: string;
    /** Descrição para logs. */
    label: string;
}

/** Scripts de terceiros autorizados na aplicação. */
export const TRUSTED_SCRIPTS: TrustedScript[] = [
    {
        src: 'https://www.google.com/recaptcha/api.js',
        label: 'Google reCAPTCHA',
    },
    {
        src: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
        label: 'Cloudflare Turnstile',
    },
    {
        src: 'https://www.googletagmanager.com/gtag/js',
        label: 'Google Analytics',
    },
];

/**
 * Verifica se um script está na lista de scripts autorizados.
 */
export function isScriptTrusted(src: string): boolean {
    return TRUSTED_SCRIPTS.some((s) =>
        src.startsWith(s.src) || src === s.src
    );
}

/**
 * Audita scripts carregados na página em busca de scripts não autorizados.
 *
 * @returns Array de URLs de scripts não autorizados.
 */
export function auditLoadedScripts(): string[] {
    if (typeof document === 'undefined') return [];

    const unauthorized: string[] = [];
    const scripts = document.querySelectorAll('script[src]');

    scripts.forEach((script) => {
        const src = script.getAttribute('src');
        if (!src) return;

        // Scripts internos (relativos) são sempre permitidos
        if (src.startsWith('/') || src.startsWith('./') || src.startsWith('../')) return;

        // Scripts do mesmo domínio são permitidos
        try {
            const parsed = new URL(src, window.location.origin);
            if (parsed.origin === window.location.origin) return;
        } catch {
            // URL inválida — suspeito
        }

        if (!isScriptTrusted(src)) {
            unauthorized.push(src);
        }
    });

    return unauthorized;
}

/**
 * Cria um elemento <script> com integridade SRI.
 */
export function createTrustedScriptElement(trustedScript: TrustedScript): HTMLScriptElement {
    const script = document.createElement('script');
    script.src = trustedScript.src;
    script.async = true;
    if (trustedScript.integrity) {
        script.integrity = trustedScript.integrity;
        script.crossOrigin = 'anonymous';
    }
    return script;
}
