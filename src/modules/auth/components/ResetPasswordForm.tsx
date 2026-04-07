import React from 'react';

/**
 * Definição de Nova Senha via Token.
 * 
 * Tela para o usuário digitar e confirmar nova senha.
 * Exibe as regras de validação para a nova senha.
 */
export const ResetPasswordForm: React.FC<{ token: string }> = ({ token }) => {
    return (
        <div>
            <h2>Nova Senha</h2>
            <form>
                {/* Input Nova Senha */}
                {/* Input Confirmar Nova Senha */}
                {/* Botão Redefinir */}
            </form>
        </div>
    );
};
