/**
 * Constants and Configuration for the Auth Module.
 * 
 * Centralizing strings, error messages, and API endpoint references.
 * Segue as melhores práticas de manutenibilidade do código.
 */

export const AUTH_ERRORS = {
    INVALID_CREDENTIALS: 'Credenciais inválidas, por favor tente novamente.',
    EXPIRED_TOKEN: 'O token expirou, solicite um novo.',
    WEAK_PASSWORD: 'A senha deve ter pelo menos 8 caracteres, 1 letra e 1 número.',
    EMAIL_TAKEN: 'Este e-mail já está em uso.',
    GENERAL_ERROR: 'Ocorreu um erro inesperado. Tente mais tarde.'
};

export const AUTH_REDIRECTS = {
    LOGIN_SUCCESS: '/',
    LOGOUT: '/login',
    AUTH_ERROR: '/login?error=auth'
};

export const AUTH_CONFIG = {
    PASSWORD_MIN_LENGTH: 8,
    TOKEN_RETRY_INTERVAL_MS: 3000
};
