/**
 * @arquivo     src/header/Header.tsx
 * @módulo      Header / Componente Principal
 * @descrição   Componente de cabeçalho responsivo principal do PRJ-BASE.
 *              Orquestra o logotipo, os links de navegação e os layouts
 *              separados para desktop e mobile. Gerencia estado de scroll
 *              e abertura/fechamento do menu mobile via `useHeader`.
 *
 * @como-usar
 *              import Header from '@/header';
 *              // No layout:
 *              <Header />
 *              // Com customização:
 *              <Header logo="MEU LOGO" links={linksCustomizados} />
 *
 * @dependências ./header.config, ./hooks/useHeader, ./components/DesktopHeader,
 *              ./components/MobileHeader, ./Header.module.css, ./header.types
 * @notas       O componente é "use client" pois depende de hooks de estado e
 *              eventos do browser (scroll, keyboard). O header é `position: fixed`
 *              — garanta que o conteúdo abaixo tenha padding-top equivalente.
 */
"use client";

import React from 'react';
import { HEADER_LINKS, HEADER_CONFIG } from './header.config';
import { useHeader } from './hooks/useHeader';
import { DesktopHeader } from './components/DesktopHeader';
import { MobileHeader } from './components/MobileHeader';
import styles from './Header.module.css';
import { HeaderProps } from './header.types';

/**
 * Componente Header.
 *
 * @param links     - Links de navegação exibidos no desktop e mobile.
 * @param logo      - Texto ou nó React para o logotipo da marca.
 * @param className - Classes CSS adicionais para o container do header.
 */
export const Header: React.FC<HeaderProps> = ({
    links = HEADER_LINKS,
    logo = HEADER_CONFIG.logoText,
    className = ''
}) => {
    const { isMenuOpen, toggleMenu, closeMenu, scrolled } = useHeader();

    return (
        <header
            role="banner"
            className={`${styles.headerContainer} ${scrolled ? styles.scrolled : ''} ${className}`}
        >
            <div className={styles.contentWrapper}>
                <a href="/" className={styles.logo} aria-label="Voltar para a home">
                    {logo}
                </a>

                {/* Navegação Desktop */}
                <DesktopHeader links={links} />

                {/* Navegação Mobile e Botão de Toggle */}
                <MobileHeader
                    links={links}
                    isOpen={isMenuOpen}
                    toggleMenu={toggleMenu}
                    onClose={closeMenu}
                />
            </div>
        </header>
    );
};

export default Header;
