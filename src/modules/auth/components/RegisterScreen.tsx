import React, { useState } from 'react';
import styles from '../AuthModal.module.css';
import { useAuthContext } from '@/shared/providers/AuthProvider';

export const RegisterScreen: React.FC = () => {
    const { setAuthView } = useAuthContext();
    const [loading, setLoading] = useState(false);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setTimeout(() => {
            setLoading(false);
            // Simulate sending token to email and navigating to token validation
            setAuthView('token'); // "token" is conceptually handled via changing view state. Wait, the type of AuthView might need 'token'. I'll ensure it exists.
        }, 1500);
    };

    return (
        <div className="p-8 md:p-10">
            <div className="mb-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Comece agora</h2>
                <p className="text-gray-500 text-sm">Crie sua conta em segundos e comece a criar.</p>
            </div>

            <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 ml-1">Nome</label>
                            <input type="text" required placeholder="Nome" className={`${styles.inputField} w-full px-4 py-3.5 rounded-xl bg-white text-gray-900 placeholder-gray-400`} />
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 ml-1">Sobrenome</label>
                            <input type="text" required placeholder="Silva" className={`${styles.inputField} w-full px-4 py-3.5 rounded-xl bg-white text-gray-900 placeholder-gray-400`} />
                        </div>
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 ml-1">E-mail</label>
                        <input type="email" required placeholder="nome@exemplo.com" className={`${styles.inputField} w-full px-4 py-3.5 rounded-xl bg-white text-gray-900 placeholder-gray-400`} />
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 ml-1">Senha</label>
                        <input type="password" required placeholder="Crie uma senha forte" className={`${styles.inputField} w-full px-4 py-3.5 rounded-xl bg-white text-gray-900 placeholder-gray-400`} />
                    </div>
                </div>

                <div className="mt-6 flex items-start">
                    <input id="terms" type="checkbox" required className="mt-1 h-4 w-4 rounded border-gray-300 text-[#006494] focus:ring-[#006494]" />
                    <label htmlFor="terms" className="ml-2 text-xs text-gray-500 leading-relaxed">
                        Eu concordo com os <a href="#" className="underline text-[#006494]">Termos de Serviço</a>.
                    </label>
                </div>

                <button type="submit" disabled={loading} className={`${styles.btnPrimary} w-full mt-8 py-3.5 rounded-xl text-white font-medium text-sm flex items-center justify-center`}>
                    {loading ? (
                        <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                    ) : 'Criar conta'}
                </button>
            </form>

            <div className="mt-8 pt-8 border-t border-gray-100">
                <p className="text-center text-sm text-gray-500">
                    Já possui conta?{' '}
                    <button onClick={() => setAuthView('login')} className="font-semibold text-gray-900 hover:underline">
                        Fazer login
                    </button>
                </p>
            </div>
        </div>
    );
};
