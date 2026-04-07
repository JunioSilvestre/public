/**
 * @arquivo     src/footer/footer.tokens.ts
 * @módulo      Footer / Design Tokens
 * @descrição   Tokens de design centralizados para o componente Footer.
 *              Define paleta de cores, espaçamentos e transições utilizados
 *              pelo Footer e seus sub-componentes.
 *
 * @como-usar   import { FOOTER_TOKENS } from './footer.tokens';
 *              // Use como referência para manter consistência visual.
 *
 * @dependências Nenhuma
 * @notas       Tokens devem estar sincronizados com os valores em Footer.module.css.
 */

export const FOOTER_TOKENS = {
    colors: {
        background: '#000000',
        text: '#FFFFFF',
        textSecondary: '#A0A0A0',
        iconHover: '#FFFFFF',
        iconDefault: 'rgba(255, 255, 255, 0.6)',
        border: 'rgba(255, 255, 255, 0.1)',
    },
    spacing: {
        containerPadding: '48px 24px',
        itemGap: '24px',
    },
    transitions: {
        smooth: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
    },
};
