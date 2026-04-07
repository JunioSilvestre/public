/**
 * @arquivo     src/footer/components/FooterCopyright.tsx
 * @módulo      Footer / Copyright
 * @descrição   Sub-componente que renderiza o aviso de direitos autorais
 *              na parte inferior do rodapé. Exibe o texto recebido via prop.
 *
 * @como-usar   Renderizado internamente pelo Footer.tsx.
 *              <FooterCopyright text={copyright} />
 *
 * @dependências ../footer.types (FooterCopyrightProps), ../Footer.module.css
 * @notas       O ano dinâmico é calculado no hook useFooter e injetado
 *              no texto antes de ser passado para este componente.
 */

import React from 'react';
import { FooterCopyrightProps } from '../footer.types';
import styles from '../Footer.module.css';

/**
 * Renderiza o aviso de direitos autorais no rodapé.
 */
export const FooterCopyright: React.FC<FooterCopyrightProps> = ({ text }) => {
    return (
        <div className={styles.copyrightSection}>
            <p className={styles.copyrightText}>
                {text}
            </p>
        </div>
    );
};
