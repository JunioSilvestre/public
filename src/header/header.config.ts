/**
 * @arquivo     src/header/header.config.ts
 * @módulo      Header / Configuração
 * @descrição   Configuração do componente Header para o Portfólio.
 *              Inclui links para About, Works, Contact e o botão Get Started.
 */

import { NavLink } from './header.types';

/**
 * Links de navegação padrão do header.
 * Ajustado para âncoras na mesma página (Smooth Scroll).
 */
export const HEADER_LINKS: NavLink[] = [
    { id: '1', label: 'About', href: '#about' },
    { id: '2', label: 'Works', href: '#works' },
    { id: '3', label: 'Contact', href: '#contact' },
    { id: '4', label: 'Get Started', href: '#contact', isPrimary: true },
];

/**
 * Configuração geral do Header.
 */
export const HEADER_CONFIG = {
    /** Nome da marca exibido no logotipo. */
    logoText: 'JS',
    /** Largura de tela em pixels abaixo da qual o layout mobile é ativado. */
    breakpoint: 768,
    /** Altura base do header. */
    height: '72px',
};
