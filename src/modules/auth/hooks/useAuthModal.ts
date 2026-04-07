import { useState } from 'react';
import { AuthView } from '../auth.types';

/**
 * useAuthModal: Hook para gerenciar as rotas internas do Modal de Auth.
 * 
 * Centraliza a navegação entre as visões de login, cadastro e recuperação.
 * Garante que o estado seja consistente durante a transição.
 */
export const useAuthModal = () => {
    const [view, setView] = useState<AuthView>('login');

    const navigateTo = (newView: AuthView) => {
        // Lógica de transição suave if needed
        setView(newView);
    };

    return {
        view,
        navigateTo,
        closeModal: () => { /* Chamar context global de modal */ }
    };
};
