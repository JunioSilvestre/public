/**
 * @arquivo     src/header/header.config.ts
 * @módulo      Header / Configuração
 * @descrição   Configuração padrão do componente Header. Define os links de
 *              navegação exibidos por padrão e as constantes de configuração
 *              geral como texto do logo, breakpoint responsivo e altura do header.
 *
 * @como-usar   Importe as constantes para sobrescrever no componente:
 *              import { HEADER_LINKS, HEADER_CONFIG } from './header.config';
 *              // Passe links customizados via prop: <Header links={meusLinks} />
 *
 * @dependências ./header.types (NavLink)
 * @notas       Altere `HEADER_LINKS` para personalizar o menu de navegação.
 *              `breakpoint` deve espelhar a media query em Header.module.css.
 */

import { NavLink } from './header.types';

/**
 * Links de navegação padrão do header.
 * Altere esta lista para personalizar o menu da aplicação.
 */
export const HEADER_LINKS: NavLink[] = [
    { id: '1', label: 'Home', href: '/' },
    { id: '2', label: 'About', href: '/about' },
    { id: '3', label: 'Contact', href: '/contact' },
    { id: '4', label: 'Get Started', href: '/get-started', isPrimary: true },
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
