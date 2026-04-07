/**
 * @arquivo     src/footer/hooks/useFooter.ts
 * @módulo      Footer / Hook de Estado
 * @descrição   Hook que centraliza a lógica de estado do componente Footer.
 *              Atualmente calcula o ano atual para o aviso de copyright.
 *
 * @como-usar
 *              const { currentYear } = useFooter();
 *              // Use em texto: `Direitos reservados ${currentYear}`
 *
 * @dependências React (useMemo)
 * @notas       O `useMemo` garante que o ano seja calculado apenas uma vez
 *              por montagem, evitando recalculos desnecessários.
 */

import { useMemo } from 'react';

export const useFooter = () => {
    /**
     * Retorna o ano atual para o aviso de direitos autorais.
     */
    const currentYear = useMemo(() => new Date().getFullYear(), []);

    return {
        currentYear,
    };
};
