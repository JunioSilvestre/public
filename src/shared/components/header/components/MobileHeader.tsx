/**
 * @file        src/header/components/MobileHeader.tsx
 * @module      Header / Mobile Component
 * @description Mobile-specific navigation component with overlay menu.
 *              Includes the hamburger button (animatable to ×) and the
 *              full-screen navigation panel that slides down. Supports closing
 *              via Escape key (managed in the `useHeader` hook).
 */

import React from 'react';
import { NavLink } from '../header.types';
import { useActiveRoute } from '../hooks/useActiveRoute';
import styles from '../Header.module.css';

import { useAuthContext } from '@/shared/providers/AuthProvider';

interface MobileHeaderProps {
    /** Navigation links to display in the menu. */
    links: NavLink[];
    /** Defines whether the mobile menu is visible. */
    isOpen: boolean;
    /** Callback to toggle (open/close) the menu state. */
    toggleMenu: () => void;
    /** Callback to close the menu (usually when clicking a link). */
    onClose: () => void;
}

/**
 * MobileHeader Component.
 * Includes the hamburger toggle and a full-screen overlay menu.
 */
export const MobileHeader: React.FC<MobileHeaderProps> = ({
    links,
    isOpen,
    toggleMenu,
    onClose
}) => {
    const { isActive } = useActiveRoute();
    const { openAuthModal } = useAuthContext();

    return (
        <>
            <button
                className={`${styles.mobileToggle} ${isOpen ? styles.mobileToggleOpen : ''}`}
                onClick={toggleMenu}
                aria-label={isOpen ? "Close menu" : "Open menu"}
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

                        if (link.isPrimary) {
                            return (
                                <button
                                    key={link.id}
                                    onClick={() => {
                                        onClose();
                                        openAuthModal('login');
                                    }}
                                    className={`${styles.mobileNavLink} ${styles.primaryButton || ''} font-bold mt-4 px-6 py-3 w-fit mx-auto bg-black text-white rounded-xl`}
                                >
                                    {link.label}
                                </button>
                            );
                        }

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
