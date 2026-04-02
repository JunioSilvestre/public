/**
 * @arquivo     src/hero/hero.types.ts
 * @módulo      Hero / Tipos
 * @descrição   Definições de tipos TypeScript para o componente Hero e seus
 *              sub-componentes. Centraliza interfaces para garantir consistência
 *              entre config, componentes e props.
 *
 * @como-usar   import { TechBadge, HeroProps } from './hero.types';
 *
 * @dependências Apenas tipos nativos do TypeScript e React
 * @notas       Nenhum código de runtime neste arquivo — apenas definições de tipos.
 */

export interface NavLink {
    label: string;
    href: string;
}

export interface TechBadge {
    label: string;
    color: string;
    glowColor: string;
}

export interface HeroProps {
    headline?: React.ReactNode;
    subHeadline?: string;
    techStack?: TechBadge[];
    ctaPrimary?: { label: string; onClick?: () => void };
    ctaSecondary?: { label: string; onClick?: () => void };
}
