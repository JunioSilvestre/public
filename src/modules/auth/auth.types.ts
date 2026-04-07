/**
 * Definições de Tipagem do Módulo de Autenticação.
 * 
 * Centraliza as interfaces de estados, usuários, tokens e eventos.
 * Segue as melhores práticas de manutenção do TypeScript.
 */

export type AuthView = 'login' | 'signup' | 'forgot-password' | 'reset-password' | 'success' | 'token';

export interface UserAuthData {
    email: string;
    token?: string;
    refreshToken?: string;
    expiresAt?: number;
}

export interface AuthState {
    view: AuthView;
    isLoading: boolean;
    error: string | null;
    user: UserAuthData | null;
}

export interface ResetPasswordRequest {
    email: string;
}

export interface ResetPasswordSubmit {
    token: string;
    newPassword: string;
}
