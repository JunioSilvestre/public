/**
 * @arquivo     src/footer/footer.config.tsx
 * @módulo      Footer / Configuração
 * @descrição   Configuração centralizada de conteúdo do rodapé. Define os links
 *              de redes sociais padrão (com ícones SVG inline) e o texto de
 *              copyright padrão utilizado pelo componente Footer.
 *
 * @como-usar   import { FALLBACK_SOCIAL_LINKS, FOOTER_CONFIG } from './footer.config';
 *              // Passe via prop ou use como padrão: <Footer socialLinks={FALLBACK_SOCIAL_LINKS} />
 *
 * @dependências ./footer.types (SocialLink), React (para JSX dos SVG icons)
 * @notas       Atualize FALLBACK_SOCIAL_LINKS com URLs reais de perfis sociais
 *              antes de ir para produção.
 */

import React from 'react';
import { SocialLink } from './footer.types';

/**
 * Links de redes sociais padrão com ícones SVG.
 */
export const FALLBACK_SOCIAL_LINKS: SocialLink[] = [
    {
        id: 'instagram',
        label: 'Instagram',
        href: 'https://instagram.com',
        icon: (
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="2" width="20" height="20" rx="5" ry="5"></rect>
                <path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"></path>
                <line x1="17.5" y1="6.5" x2="17.51" y2="6.5"></line>
            </svg>
        ),
    },
    {
        id: 'facebook',
        label: 'Facebook',
        href: 'https://facebook.com',
        icon: (
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"></path>
            </svg>
        ),
    },
    {
        id: 'linkedin',
        label: 'LinkedIn',
        href: 'https://linkedin.com',
        icon: (
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path>
                <rect x="2" y="9" width="4" height="12"></rect>
                <circle cx="4" cy="4" r="2"></circle>
            </svg>
        ),
    },
];

export const FOOTER_CONFIG = {
    copyright: "Todos os direitos reservados.",
};
