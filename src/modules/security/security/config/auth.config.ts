/**
 * @fileoverview Security Config — Configurações centralizadas de segurança.
 *
 * Todas as configurações de segurança da aplicação num só lugar.
 * Importe deste módulo ao invés de hardcodar valores.
 *
 * @module security/config
 */

/** Configurações de CSP. */
export { generateCSPHeader } from '../headers/csp';
export type { CSPDirectives } from '../headers/csp';

/** Configurações de HSTS. */
export { generateHSTSHeader } from '../headers/hsts';
export type { HSTSOptions } from '../headers/hsts';

/** Configurações de Rate Limit (client-side). */
export const RATE_LIMIT_CONFIG = {
    /** Requisições por minuto para APIs gerais. */
    api: { maxRequests: 60, windowMs: 60_000 },
    /** Requisições por minuto para login. */
    login: { maxRequests: 5, windowMs: 60_000 },
    /** Requisições por minuto para registro. */
    register: { maxRequests: 3, windowMs: 60_000 },
    /** Requisições por minuto para formulários de contato. */
    contact: { maxRequests: 3, windowMs: 300_000 },
} as const;

/** Configurações de CORS permitidos. */
export const CORS_CONFIG = {
    allowedOrigins: [
        process.env.NEXT_PUBLIC_APP_URL ?? 'http://localhost:3000',
    ],
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Request-Signature'],
    maxAge: 86_400,
    credentials: true,
} as const;

/** Configurações de autenticação. */
export const AUTH_CONFIG = {
    /** TTL do token de acesso em segundos. */
    accessTokenTTL: 900, // 15 min
    /** TTL do refresh token em segundos. */
    refreshTokenTTL: 604_800, // 7 dias
    /** Número máximo de tentativas de login antes de lockout. */
    maxLoginAttempts: 5,
    /** Tempo de lockout em ms. */
    lockoutDurationMs: 900_000, // 15 min
    /** Nível de hash bcrypt. */
    bcryptRounds: 12,
} as const;

/** Configurações de criptografia client-side. */
export const ENCRYPTION_CONFIG = {
    /** Algoritmo para Web Crypto API. */
    algorithm: 'AES-GCM' as const,
    /** Tamanho da chave em bits. */
    keyLength: 256,
    /** Tamanho do IV em bytes. */
    ivLength: 12,
} as const;
