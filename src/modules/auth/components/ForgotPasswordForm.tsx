import React from 'react';

/**
 * Solicitação de Recuperação de Senha.
 * 
 * Envia e-mail com link de recuperação de conta.
 * Recebe o e-mail do usuário e envia o token de reset.
 */
export const ForgotPasswordForm: React.FC = () => {
    return (
        <div>
            <h2>Recuperar Senha</h2>
            <p>Informe o seu e-mail para receber as instruções de recuperação.</p>
            <form>
                {/* Input E-mail do usuário */}
                {/* Botão Enviar Link */}
            </form>
        </div>
    );
};
