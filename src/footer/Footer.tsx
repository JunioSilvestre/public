/**
 * @arquivo     src/footer/Footer.tsx
 * @módulo      Footer / Componente Principal
 * @descrição   Componente de rodapé responsivo premium com fundo preto.
 *              Exibe links de redes sociais (FooterSocial) e aviso de
 *              direitos autorais dinâmico com o ano atual (FooterCopyright).
 *
 * @como-usar   import Footer from '@/footer';
 *              // No layout:
 *              <Footer />
 *              // Com customização:
 *              <Footer socialLinks={meusLinks} copyrightText="Minha Empresa" />
 *
 * @dependências ./footer.types, ./footer.config, ./hooks/useFooter,
 *              ./components/FooterSocial, ./components/FooterCopyright, ./Footer.module.css
 * @notas       O componente é "use client" pois usa o hook `useFooter` que
 *              acessa o ano atual via JavaScript (client-side only).
 */
"use client";

import React from 'react';
import { FooterProps } from './footer.types';
import { FALLBACK_SOCIAL_LINKS, FOOTER_CONFIG } from './footer.config';
import { useFooter } from './hooks/useFooter';
import { FooterSocial } from './components/FooterSocial';
import { FooterCopyright } from './components/FooterCopyright';
import styles from './Footer.module.css';

/**
 * Componente Footer.
 *
 * @param socialLinks    - Array opcional de objetos de links de redes sociais.
 * @param copyrightText  - Texto opcional para sobrescrever o copyright padrão.
 * @param className      - Classe CSS adicional para o container do footer.
 */
export const Footer: React.FC<FooterProps> = ({
    socialLinks = FALLBACK_SOCIAL_LINKS,
    copyrightText = FOOTER_CONFIG.copyright,
    className = ''
}) => {
    const { currentYear } = useFooter();

    return (
        <footer className={`${styles.footer} ${className}`} role="contentinfo">
            <div className={styles.container}>
                {/* Seção de links de redes sociais */}
                <FooterSocial links={socialLinks} />

                {/* Seção do aviso de direitos autorais */}
                <FooterCopyright text={`© ${currentYear} ${copyrightText}`} />
            </div>
        </footer>
    );
};

export default Footer;
