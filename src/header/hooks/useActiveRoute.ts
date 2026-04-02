/**
 * @arquivo     src/header/hooks/useActiveRoute.ts
 * @módulo      Header / Hook de Rota Ativa
 * @descrição   Hook customizado para detectar se uma determinada rota está
 *              ativa no momento. Escuta eventos `popstate` e usa polling
 *              como fallback para bibliotecas de roteamento que não disparam
 *              `popstate` no `pushState`.
 *
 * @como-usar
 *              const { isActive, currentPath } = useActiveRoute();
 *              isActive('/about'); // true se a rota atual começa com '/about'
 *
 * @dependências React (useState, useEffect)
 * @notas       O intervalo de polling (1s) é uma medida de segurança para
 *              roteamentos que não emitem eventos nativos. Considere removê-lo
 *              se o projeto usar Next.js Router com `usePathname`.
 */

import { useState, useEffect } from 'react';

export const useActiveRoute = () => {
    const [currentPath, setCurrentPath] = useState('');

    useEffect(() => {
        // Executa apenas no cliente (sem SSR)
        if (typeof window === 'undefined') return;

        // Atualiza o caminho ao montar e nas navegações (botão voltar/avançar)
        const updatePath = () => {
            setCurrentPath(window.location.pathname);
        };

        updatePath();

        // Escuta eventos de navegação nativa do browser (popstate)
        window.addEventListener('popstate', updatePath);

        // Polling como fallback para roteadores que não disparam popstate no pushState
        const interval = setInterval(updatePath, 1000);

        return () => {
            window.removeEventListener('popstate', updatePath);
            clearInterval(interval);
        };
    }, []);

    /**
     * Verifica se um dado href corresponde à rota ativa atual.
     * @param href O caminho a verificar.
     * @returns `true` se a rota estiver ativa.
     */
    const isActive = (href: string) => {
        if (!currentPath) return false;
        if (href === '/') {
            return currentPath === '/';
        }
        return currentPath.startsWith(href);
    };

    return { isActive, currentPath };
};
