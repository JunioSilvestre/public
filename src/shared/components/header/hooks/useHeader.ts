/**
 * @arquivo     src/header/hooks/useHeader.ts
 * @módulo      Header / Hook de Estado
 * @descrição   Hook que centraliza toda a lógica de estado do componente Header:
 *              gerencia abertura do menu mobile, detecção de scroll e
 *              fechamento do menu via teclado (tecla Escape).
 *
 * @como-usar
 *              const { isMenuOpen, toggleMenu, closeMenu, scrolled } = useHeader();
 *              // `scrolled` = true quando o usuário rolou mais de 20px
 *              // `isMenuOpen` = estado do menu mobile
 *
 * @dependências React (useState, useCallback, useEffect, useRef)
 * @notas       Usa `requestAnimationFrame` para otimizar o handler de scroll
 *              e evitar jank. O body tem overflow bloqueado quando o menu está aberto.
 */

import { useState, useCallback, useEffect, useRef } from 'react';

export const useHeader = () => {
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);
    const lastScrollY = useRef(0);

    /**
     * Alterna o estado de abertura do menu mobile.
     */
    const toggleMenu = useCallback(() => {
        setIsMenuOpen((prev) => !prev);
    }, []);

    /**
     * Fecha o menu mobile forçosamente.
     */
    const closeMenu = useCallback(() => {
        setIsMenuOpen(false);
    }, []);

    // Handler de scroll otimizado com comportamento de throttle via requestAnimationFrame.
    useEffect(() => {
        let ticking = false;

        const handleScroll = () => {
            if (!ticking) {
                window.requestAnimationFrame(() => {
                    setScrolled(window.scrollY > 20);
                    ticking = false;
                });
                ticking = true;
            }
        };

        window.addEventListener('scroll', handleScroll, { passive: true });
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    // Bloqueia o scroll do body quando o menu mobile está aberto.
    useEffect(() => {
        if (isMenuOpen) {
            document.body.style.overflow = 'hidden';

            // Fecha o menu ao pressionar a tecla Escape.
            const handleEscape = (e: KeyboardEvent) => {
                if (e.key === 'Escape') closeMenu();
            };

            window.addEventListener('keydown', handleEscape);
            return () => window.removeEventListener('keydown', handleEscape);
        } else {
            document.body.style.overflow = 'unset';
        }
    }, [isMenuOpen, closeMenu]);

    return {
        isMenuOpen,
        toggleMenu,
        closeMenu,
        scrolled,
    };
};
