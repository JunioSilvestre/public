/**
 * @arquivo     src/header/components/DesktopHeader.tsx
 * @módulo      Header / Componente Desktop
 * @descrição   Componente de navegação específico para desktop.
 *              Exibe uma lista horizontal de links, com suporte a estado de
 *              rota ativa (`aria-current="page"`) e estilos diferenciados
 *              para o link de ação primária (botão "Get Started").
 *
 * @como-usar   Renderizado automaticamente pelo Header em resoluções > 768px.
 *              <DesktopHeader links={links} />
 *
 * @dependências ../header.types (NavLink), ../hooks/useActiveRoute, ../Header.module.css
 * @notas       Ocultado via CSS (display:none) em mobile. Não renderiza condicionalmente
 *              para manter consistência de hidratação SSR/CSR.
 */

import React from 'react';
import { NavLink } from '../header.types';
import { useActiveRoute } from '../hooks/useActiveRoute';
import styles from '../Header.module.css';

import { useAuthContext } from '@/shared/providers/AuthProvider';

interface DesktopHeaderProps {
    /** Links de navegação a exibir na barra horizontal. */
    links: NavLink[];
}

/**
 * Componente DesktopHeader.
 * Exibe uma lista horizontal de links de navegação.
 *
 * @param links - Array de objetos de link de navegação.
 */
export const DesktopHeader: React.FC<DesktopHeaderProps> = ({ links }) => {
    const { isActive } = useActiveRoute();
    const { openAuthModal } = useAuthContext();

    return (
        <nav className={styles.nav} aria-label="Desktop navigation">
            {links.map((link) => {
                const active = isActive(link.href);

                if (link.isPrimary) {
                    return (
                        <button
                            key={link.id}
                            onClick={() => openAuthModal('login')}
                            className={`${styles.navLink} ${styles.primaryButton}`}
                        >
                            {link.label}
                        </button>
                    );
                }

                return (
                    <a
                        key={link.id}
                        href={link.href}
                        className={`${styles.navLink} ${active ? styles.active : ''}`}
                        aria-current={active ? 'page' : undefined}
                    >
                        {link.label}
                    </a>
                );
            })}
        </nav>
    );
};
