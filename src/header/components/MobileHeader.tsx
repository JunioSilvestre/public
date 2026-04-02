/**
 * @arquivo     src/header/components/MobileHeader.tsx
 * @módulo      Header / Componente Mobile
 * @descrição   Componente de navegação específico para mobile com menu overlay.
 *              Inclui o botão hamburger (animável para ×) e o painel de navegação
 *              de tela cheia que desliza de cima para baixo. Suporta fechamento
 *              via tecla Escape (gerenciado no hook `useHeader`).
 *
 * @como-usar   Renderizado automaticamente pelo Header em resoluções ≤ 768px.
 *              <MobileHeader links={links} isOpen={isMenuOpen} toggleMenu={toggleMenu} onClose={closeMenu} />
 *
 * @dependências ../header.types (NavLink), ../hooks/useActiveRoute, ../Header.module.css
 * @notas       O overlay usa `position: fixed` e bloqueia o scroll do body quando aberto.
 *              A acessibilidade é gerenciada via `aria-expanded` e `aria-hidden`.
 */

import React from 'react';
import { NavLink } from '../header.types';
import { useActiveRoute } from '../hooks/useActiveRoute';
import styles from '../Header.module.css';

interface MobileHeaderProps {
    /** Links de navegação a exibir no menu. */
    links: NavLink[];
    /** Define se o menu mobile está visível. */
    isOpen: boolean;
    /** Callback para alternar (abrir/fechar) o estado do menu. */
    toggleMenu: () => void;
    /** Callback para fechar o menu (geralmente ao clicar em um link). */
    onClose: () => void;
}

/**
 * Componente MobileHeader.
 * Inclui o toggle hamburger e um menu em overlay de tela cheia.
 *
 * @param links      - Array de objetos de link de navegação.
 * @param isOpen     - Estado de visibilidade do menu.
 * @param toggleMenu - Handler para alternar o menu.
 * @param onClose    - Handler para fechar o menu (chamado ao clicar em um link).
 */
export const MobileHeader: React.FC<MobileHeaderProps> = ({
    links,
    isOpen,
    toggleMenu,
    onClose
}) => {
    const { isActive } = useActiveRoute();

    return (
        <>
            <button
                className={`${styles.mobileToggle} ${isOpen ? styles.mobileToggleOpen : ''}`}
                onClick={toggleMenu}
                aria-label={isOpen ? "Fechar menu" : "Abrir menu"}
                aria-expanded={isOpen}
                aria-controls="mobile-navigation-menu"
            >
                <div className={styles.hamburger}></div>
            </button>

            <div
                id="mobile-navigation-menu"
                className={`${styles.mobileMenu} ${isOpen ? styles.mobileMenuOpen : ''}`}
                aria-hidden={!isOpen}
            >
                <nav className={styles.mobileNavLinks} aria-label="Mobile navigation">
                    {links.map((link) => {
                        const active = isActive(link.href);
                        return (
                            <a
                                key={link.id}
                                href={link.href}
                                className={`${styles.mobileNavLink} ${active ? styles.active : ''}`}
                                onClick={onClose}
                                aria-current={active ? 'page' : undefined}
                            >
                                {link.label}
                            </a>
                        );
                    })}
                </nav>
            </div>
        </>
    );
};
