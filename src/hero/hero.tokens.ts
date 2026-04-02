/**
 * @arquivo     src/hero/hero.tokens.ts
 * @módulo      Hero / Design Tokens
 * @descrição   Tokens de design para o componente Hero baseados no modelo cyber-tech
 *              do projeto. Define a paleta de cores (primary, secondary, tertiary),
 *              efeitos visuais (glass, blur, glow) e a configuração do grid de fundo.
 *
 * @como-usar   import { HERO_TOKENS } from './hero.tokens';
 *              // Reference: HERO_TOKENS.colors.primary, .effects.glow, .grid.color
 *
 * @dependências Nenhuma
 * @notas       Todos os valores de cor são baseados no Material You adaptado para
 *              dark mode. O sufixo `as const` garante tipo literal estríto para
 *              uso em CSS-in-JS ou propriedades de estilo inline.
 */

export const HERO_TOKENS = {
    colors: {
        primary: '#b0c6ff',
        secondary: '#bdf4ff',
        tertiary: '#f8acff',
        error: '#ffb4ab',
        background: '#121318',
        surface: '#121318',
        onSurface: '#e3e1e9',
        onSurfaceVariant: '#c3c6d4',
        outline: '#8d909d',
        outlineVariant: 'rgba(67, 70, 82, 0.2)',
        primaryContainer: 'rgba(0, 71, 165, 0.2)',
        tertiaryContainer: 'rgba(131, 0, 154, 0.1)',
        surfaceContainerHigh: '#292a2f',
        secondaryContainer: 'rgba(0, 227, 253, 0.1)',
    },
    effects: {
        glass: 'rgba(30,31,37,0.7)',
        blur: '24px',
        glow: '0 0 40px -10px rgba(176,198,255,0.3)',
        pulseShadow: '0 0 8px rgba(176,198,255,0.8)',
    },
    grid: {
        color: '#434652',
        size: '40px',
    }
} as const;
