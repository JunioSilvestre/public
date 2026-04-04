/**
 * @file        src/header/Header.tsx
 * @module      Header / Main Component
 * @description Responsive header component for the portfolio.
 *              Orchestrates the logo, navigation links, and the
 *              different layouts for desktop and mobile. Manages scroll
 *              state and mobile menu toggle via `useHeader`.
 *
 * @usage
 *              import Header from '@/header';
 *              // In layout:
 *              <Header />
 *              // Optional customization:
 *              <Header logo="MY LOGO" links={customLinks} />
 *
 * @dependencies ./header.config, ./hooks/useHeader, ./components/DesktopHeader,
 *              ./components/MobileHeader, ./Header.module.css, ./header.types
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
                <a href="#hero" className={styles.logo} aria-label="Back to top">
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
