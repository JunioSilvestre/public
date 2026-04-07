/**
 * @arquivo     src/footer/components/FooterSocial.tsx
 * @módulo      Footer / Social
 * @descrição   Sub-componente que renderiza a lista de ícones clicáveis
 *              de redes sociais. Cada link abre em nova aba com target _blank
 *              e rel noopener noreferrer para segurança.
 *
 * @como-usar   Renderizado internamente pelo Footer.tsx.
 *              <FooterSocial links={socialLinks} />
 *
 * @dependências ../footer.types (FooterSocialProps), ../Footer.module.css
 * @notas       O aria-label de cada link usa o nome da plataforma definido
 *              em SocialLink.label para acessibilidade.
 */

import React from 'react';
import { FooterSocialProps } from '../footer.types';
import styles from '../Footer.module.css';

/**
 * Renderiza uma lista de ícones clicáveis de redes sociais.
 */
export const FooterSocial: React.FC<FooterSocialProps> = ({ links }) => {
    return (
        <div className={styles.socialSection} aria-label="Social media links">
            {links.map((social) => (
                <a
                    key={social.id}
                    href={social.href}
                    className={styles.socialLink}
                    data-platform={social.id}
                    aria-label={social.label}
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    {social.icon}
                </a>
            ))}
        </div>
    );
};
