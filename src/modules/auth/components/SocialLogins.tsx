import React from 'react';

/**
 * Login Social (OAuth2).
 * 
 * Centraliza botões de autenticação via provedores (Google, GitHub, Facebook).
 * Gerencia o redirecionamento e captura de callback.
 */
export const SocialLogins: React.FC = () => {
    return (
        <div>
            <hr />
            <p>Ou conecte-se com:</p>
            <button>Google</button>
            <button>GitHub</button>
            <button>Facebook</button>
        </div>
    );
};
