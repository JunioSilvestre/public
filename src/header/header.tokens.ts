/**
 * @arquivo     src/header/header.tokens.ts
 * @módulo      Header / Design Tokens
 * @descrição   Design tokens centralizados para o componente Header.
 *              Define a paleta de cores, espaçamentos, transições e z-index
 *              utilizados pelo Header e seus sub-componentes.
 *
 * @como-usar   Importe e use como referência para manter consistência visual:
 *              import { HEADER_TOKENS } from './header.tokens';
 *              // Idealmente espelhados em variáveis CSS (--header-bg, etc.)
 *
 * @dependências Nenhuma
 * @notas       Tokens devem estar sincronizados com as variáveis CSS em
 *              Header.module.css para garantir consistência visual.
 */

/**
 * HEADER_TOKENS
 *
 * Tokens de design centralizados para o componente Header.
 * Devem ser espelhados em variáveis CSS para consistência visual.
 */
export const HEADER_TOKENS = {
    /** Paleta de cores do header. */
    colors: {
        background: '#f5f5f5',
        text: '#000000',
        textSecondary: '#4A4A4A',
        accentBg: '#000000',      // Fundo preto do botão "Get Started"
        accentText: '#FFFFFF',    // Texto branco do botão "Get Started"
        border: 'rgba(0,0,0,0.08)',
        hover: 'rgba(0,0,0,0.05)',
    },
    /** Tokens de espaçamento e dimensionamento. */
    spacing: {
        px: '24px',
        py: '16px',
        gap: '32px',
    },
    /** Durações de animações e transições. */
    transitions: {
        default: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
    },
    /** Profundidade de camadas (z-index). */
    zIndex: {
        header: 1000,
        mobileMenu: 1001,
    },
};
