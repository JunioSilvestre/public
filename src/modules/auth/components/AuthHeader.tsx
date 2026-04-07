import React from 'react';

/**
 * Cabeçalho unificado do Modal de Autenticação.
 * 
 * Exibe logos, títulos contextuais e botão de fechamento.
 * Gerencia a navegação entre telas via props contextuais.
 */
export const AuthHeader: React.FC = () => {
    return (
        <header>
            {/* Logo do Portal */}
            <h3>Identidade de Usuário</h3>
            <p>Escolha como deseja se conectar com o Portal.</p>
        </header>
    );
};
