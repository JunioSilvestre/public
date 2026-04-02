/**
 * @arquivo     src/header/header.config.ts
 * @módulo      Header / Configuração
 * @descrição   Configuração padrão do componente Header. Removido "Get Started"
 *              conforme solicitado para o portfólio.
 */

import { NavLink } from './header.types';

/**
 * Links de navegação padrão do header.
 * Ajustado para portfólio (apenas links internos).
 */
export const HEADER_LINKS: NavLink[] = [
    { id: '1', label: 'Home', href: '/' },
    { id: '2', label: 'About', href: '/about' },
    { id: '3', label: 'Contact', href: '/contact' },
];

/**
 * Configuração geral do Header.
 */
export const HEADER_CONFIG = {
    /** Nome da marca exibido no logotipo. */
    logoText: 'JS',
    /** Largura de tela em pixels abaixo da qual o layout mobile é ativado. */
    breakpoint: 768,
    /** Altura base do header (usada para calcular padding-top no conteúdo). */
    height: '72px',
};
