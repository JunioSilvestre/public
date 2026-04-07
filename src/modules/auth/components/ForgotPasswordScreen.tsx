import React, { useState } from 'react';
import styles from '../AuthModal.module.css';
import { useAuthContext } from '@/shared/providers/AuthProvider';

export const ForgotPasswordScreen: React.FC = () => {
    const { setAuthView } = useAuthContext();
    const [loading, setLoading] = useState(false);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setTimeout(() => {
            setLoading(false);
            alert("E-mail de recuperação enviado.");
            setAuthView('login');
        }, 1500);
    };

    return (
        <div className="p-8 md:p-10">
            <button onClick={() => setAuthView('login')} className="mb-6 flex items-center text-xs font-semibold text-gray-400 hover:text-gray-600 uppercase tracking-widest">
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7"></path></svg>
                Voltar
            </button>
            
            <div className="mb-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Redefinir senha</h2>
                <p className="text-gray-500 text-sm">Enviaremos um link de recuperação para o seu e-mail cadastrado.</p>
            </div>

            <form onSubmit={handleSubmit}>
                <div className="space-y-5">
                    <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 ml-1">Seu E-mail</label>
                        <input type="email" required placeholder="nome@exemplo.com" className={`${styles.inputField} w-full px-4 py-3.5 rounded-xl bg-white text-gray-900`} />
                    </div>
                </div>

                <button type="submit" disabled={loading} className={`${styles.btnPrimary} w-full mt-8 py-3.5 rounded-xl text-white font-medium text-sm flex items-center justify-center`}>
                    {loading ? (
                        <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                    ) : 'Enviar link de acesso'}
                </button>
            </form>
        </div>
    );
};
