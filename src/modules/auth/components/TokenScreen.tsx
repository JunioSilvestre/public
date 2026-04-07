import React, { useState } from 'react';
import styles from '../AuthModal.module.css';
import { useAuthContext } from '@/shared/providers/AuthProvider';
import { useTokenInput } from '../hooks/useTokenInput';

export const TokenScreen: React.FC = () => {
    const { setAuthView } = useAuthContext();
    const [loading, setLoading] = useState(false);
    const { inputRefs, handleInput, handleKeyDown, handlePaste, length } = useTokenInput(9);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setTimeout(() => {
            setLoading(false);
            setAuthView('success');
        }, 1500);
    };

    return (
        <div className="p-8 md:p-10">
            <button onClick={() => setAuthView('signup')} className="mb-6 flex items-center text-xs font-semibold text-gray-400 hover:text-gray-600 uppercase tracking-widest">
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7"></path></svg>
                Alterar E-mail
            </button>

            <div className="mb-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Verifique seu e-mail</h2>
                <p className="text-gray-500 text-sm">Enviamos um código de segurança de 9 dígitos para o seu endereço de e-mail.</p>
            </div>

            <form onSubmit={handleSubmit}>
                <div className="flex flex-wrap justify-center gap-2 mb-8">
                    {Array.from({ length }).map((_, index) => (
                        <React.Fragment key={index}>
                            {index === 3 || index === 6 ? <div className="w-full h-1 md:hidden"></div> : null}
                            <input
                                type="text"
                                maxLength={1}
                                className={styles.tokenSlot}
                                required
                                ref={(el: HTMLInputElement | null) => { inputRefs.current[index] = el; }}
                                onChange={(e) => handleInput(index, e)}
                                onKeyDown={(e) => handleKeyDown(index, e)}
                                onPaste={handlePaste}
                            />
                        </React.Fragment>
                    ))}
                </div>

                <button type="submit" disabled={loading} className={`${styles.btnPrimary} w-full py-3.5 rounded-xl text-white font-medium text-sm shadow-lg shadow-gray-200 flex items-center justify-center`}>
                    {loading ? (
                        <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                    ) : 'Verificar e Entrar'}
                </button>
            </form>

            <div className="mt-8 text-center">
                <p className="text-sm text-gray-500">
                    Não recebeu o código?{' '}
                    <button type="button" onClick={() => alert('Novo código enviado!')} className="font-semibold text-gray-900 hover:underline">
                        Reenviar
                    </button>
                </p>
            </div>
        </div>
    );
};
