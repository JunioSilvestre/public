/**
 * @arquivo     src/hero/hero.tokens.ts
 * @módulo      Hero / Design Tokens
 * @descrição   Tokens de design do Hero — paleta HealthBridge com fundo neutro
 *              (#f5f5f5) e destaques em verde-esmeralda (#006494) e azul-cibernético
 *              (#2DD4F5). Mantém contraste alto sobre fundo claro com texto escuro.
 */

export const HERO_TOKENS = {
  colors: {
    bg:           '#f5f5f5',
    bg2:          '#efefef',
    bg3:          '#e8e8e8',
    accent:       '#006494',
    accentDark:   '#009e6e',
    accent2:      '#2DD4F5',
    warn:         '#F59E0B',
    red:          '#EF4444',
    purple:       '#a78bfa',
    text:         '#111827',
    textMid:      '#374151',
    textMuted:    '#6B7280',
    border:       'rgba(0,0,0,0.08)',
    card:         'rgba(255,255,255,0.72)',
    cardStrong:   'rgba(255,255,255,0.90)',
    nodeColors:   ['#00C98A', '#2DD4F5', '#F59E0B', '#a78bfa'],
  },
  shadows: {
    card:  '0 2px 16px rgba(0,0,0,0.08)',
    chip:  '0 4px 20px rgba(0,0,0,0.10)',
    glow:  '0 0 30px -6px rgba(0,201,138,0.25)',
  },
  fonts: {
    head: "'Syne', sans-serif",
    body: "'DM Sans', sans-serif",
    mono: "'DM Mono', monospace",
  },
} as const;
