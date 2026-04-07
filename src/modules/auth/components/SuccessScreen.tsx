import React from 'react';
import styles from '../AuthModal.module.css';
import { useAuthContext } from '@/shared/providers/AuthProvider';

export const SuccessScreen: React.FC = () => {
    const { closeAuthModal } = useAuthContext();

    return (
        <div className="p-8 md:p-10 text-center">
            <div className="w-20 h-20 bg-[#006494]/10 rounded-full flex items-center justify-center mx-auto mb-6">
                <svg className="w-10 h-10 text-[#006494]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                </svg>
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">Conta Verificada!</h2>
            <p className="text-gray-500 text-sm mb-8">Tudo pronto. Você será redirecionado para o seu dashboard em instantes.</p>
            
            <button onClick={closeAuthModal} className={`${styles.btnPrimary} w-full py-3.5 rounded-xl text-white font-medium text-sm`}>
                Acessar Dashboard
            </button>
        </div>
    );
};
