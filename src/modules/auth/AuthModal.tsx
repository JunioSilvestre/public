import React, { useEffect, useState } from 'react';
import styles from './AuthModal.module.css';
import { useAuthContext } from '@/shared/providers/AuthProvider';
import { LoginScreen } from './components/LoginScreen';
import { RegisterScreen } from './components/RegisterScreen';
import { TokenScreen } from './components/TokenScreen';
import { ForgotPasswordScreen } from './components/ForgotPasswordScreen';
import { SuccessScreen } from './components/SuccessScreen';

export const AuthModal: React.FC = () => {
    const { isModalOpen, currentView, closeAuthModal } = useAuthContext();
    const [render, setRender] = useState(false);

    useEffect(() => {
        if (isModalOpen) {
            setRender(true);
        } else {
            // Optional: delay unmount for animations
            const timer = setTimeout(() => setRender(false), 300);
            return () => clearTimeout(timer);
        }
    }, [isModalOpen]);

    if (!render) return null;

    return (
        <div className={styles.modalOverlay} style={{ opacity: isModalOpen ? 1 : 0, transition: 'opacity 0.3s ease' }}>
            <div className={`${styles.glassCard} ${styles.modalContent}`}>
                <button
                    className={styles.closeButton}
                    onClick={closeAuthModal}
                    aria-label="Close authentication modal"
                >
                    &times;
                </button>

                {/* Logo/Header Mock */}
                <div className="flex flex-col items-center pt-8 md:pt-10 mb-[-1rem]">
                    <div className="w-12 h-12 bg-[#006494] rounded-2xl flex items-center justify-center mb-4 shadow-xl shadow-[#006494]/20 border border-[#006494]/10">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 2L3 7V17L12 22L21 17V7L12 2Z" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                    </div>
                    <h1 className="text-xl font-semibold text-gray-900 tracking-tight">Nexus Cloud</h1>
                </div>

                {/* Content switching based on state */}
                {currentView === 'login' && <LoginScreen />}
                {currentView === 'signup' && <RegisterScreen />}
                {currentView === 'token' && <TokenScreen />}
                {currentView === 'forgot-password' && <ForgotPasswordScreen />}
                {currentView === 'success' && <SuccessScreen />}

                {/* Footer */}
                <div className="pb-8 md:pb-10 pt-4 text-center">
                    <p className="text-xs text-gray-400 font-medium tracking-wide uppercase">Nexus Security Infrastructure • 2025</p>
                </div>
            </div>
        </div>
    );
};
