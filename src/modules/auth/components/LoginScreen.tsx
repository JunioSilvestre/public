import React, { useState } from 'react';
import styles from '../AuthModal.module.css';
import { useAuthContext } from '@/shared/providers/AuthProvider';

export const LoginScreen: React.FC = () => {
    const { setAuthView } = useAuthContext();
    const [loading, setLoading] = useState(false);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setTimeout(() => {
            setLoading(false);
            window.location.href = '/dashboard';
        }, 1500);
    };

    return (
        <div className="p-8 md:p-10">
            <div className="mb-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Bem-vindo de volta</h2>
                <p className="text-gray-500 text-sm">Insira suas credenciais para acessar sua conta.</p>
            </div>

            <form onSubmit={handleSubmit}>
                <div className="space-y-5">
                    <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 ml-1">E-mail</label>
                        <input type="email" required placeholder="nome@exemplo.com" className={`${styles.inputField} w-full px-4 py-3.5 rounded-xl bg-white text-gray-900 placeholder-gray-400`} />
                    </div>
                    <div>
                        <div className="flex justify-between mb-2 ml-1">
                            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider">Senha</label>
                            <button type="button" onClick={() => setAuthView('forgot-password')} className="text-xs font-medium text-blue-600 hover:text-blue-700">Esqueceu a senha?</button>
                        </div>
                        <input type="password" required placeholder="••••••••" className={`${styles.inputField} w-full px-4 py-3.5 rounded-xl bg-white text-gray-900 placeholder-gray-400`} />
                    </div>
                </div>

                <button type="submit" disabled={loading} className={`${styles.btnPrimary} w-full mt-8 py-3.5 rounded-xl text-white font-medium text-sm shadow-lg shadow-gray-200 flex items-center justify-center`}>
                    {loading ? (
                        <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                    ) : 'Entrar'}
                </button>
            </form>

            <div className="mt-8 pt-8 border-t border-gray-100">
                <p className="text-center text-sm text-gray-500">
                    Não tem uma conta?{' '}
                    <button onClick={() => setAuthView('signup')} className="font-semibold text-gray-900 hover:underline">
                        Crie agora
                    </button>
                </p>
            </div>
        </div>
    );
};
