'use client';

import React, { createContext, useContext, useState, ReactNode } from 'react';
import { AuthView } from '@/modules/auth/auth.types';
import { AuthModal } from '@/modules/auth/AuthModal';

interface AuthContextData {
    isModalOpen: boolean;
    currentView: AuthView;
    openAuthModal: (view?: AuthView) => void;
    closeAuthModal: () => void;
    setAuthView: (view: AuthView) => void;
}

const AuthContext = createContext<AuthContextData | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [currentView, setCurrentView] = useState<AuthView>('login');

    const openAuthModal = (view: AuthView = 'login') => {
        setCurrentView(view);
        setIsModalOpen(true);
    };

    const closeAuthModal = () => {
        setIsModalOpen(false);
    };

    const setAuthView = (view: AuthView) => {
        setCurrentView(view);
    };

    return (
        <AuthContext.Provider
            value={{
                isModalOpen,
                currentView,
                openAuthModal,
                closeAuthModal,
                setAuthView,
            }}
        >
            {children}
            <AuthModal />
        </AuthContext.Provider>
    );
};

export const useAuthContext = (): AuthContextData => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuthContext deve ser usado dentro de um AuthProvider');
    }
    return context;
};
