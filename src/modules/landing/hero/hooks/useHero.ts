/**
 * @arquivo     src/hero/hooks/useHero.ts
 * @módulo      Hero / Hook de Estado
 * @descrição   Hook que gerencia o estado de visibilidade do componente Hero.
 *              Controla a animação de entrada (fade-in) ao montar o componente.
 *
 * @como-usar
 *              const { isVisible } = useHero();
 *              // Use `isVisible` para aplicar classe de opacidade:
 *              // className={isVisible ? 'opacity-100' : 'opacity-0'}
 *
 * @dependências React (useState, useEffect)
 * @notas       `isVisible` inicia como `false` e muda para `true` após a montagem,
 *              gerando um efeito de fade-in CSS via transição de opacidade.
 */
import { useState, useEffect } from 'react';

export function useHero() {
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        setIsVisible(true);
    }, []);

    return {
        isVisible,
    };
}
