/**
 * @fileoverview Input Validator — Validação de inputs com regras de segurança.
 *
 * Fornece validações reutilizáveis para campos de formulário com foco em
 * prevenir injection, overflow e formatação maliciosa.
 *
 * @module security/validation
 */

export interface ValidationResult {
    valid: boolean;
    error?: string;
}

/**
 * Valida um email.
 */
export function validateEmail(email: string): ValidationResult {
    if (!email || typeof email !== 'string') return { valid: false, error: 'Email é obrigatório' };
    if (email.length > 254) return { valid: false, error: 'Email muito longo' };
    // RFC 5322 simplificado
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!emailRegex.test(email)) return { valid: false, error: 'Email inválido' };
    return { valid: true };
}

/**
 * Valida um telefone brasileiro.
 */
export function validatePhone(phone: string): ValidationResult {
    if (!phone) return { valid: false, error: 'Telefone é obrigatório' };
    const digits = phone.replace(/\D/g, '');
    if (digits.length < 10 || digits.length > 11) {
        return { valid: false, error: 'Telefone deve ter 10 ou 11 dígitos' };
    }
    return { valid: true };
}

/**
 * Valida um CPF.
 */
export function validateCPF(cpf: string): ValidationResult {
    const digits = cpf.replace(/\D/g, '');
    if (digits.length !== 11) return { valid: false, error: 'CPF deve ter 11 dígitos' };
    if (/^(\d)\1{10}$/.test(digits)) return { valid: false, error: 'CPF inválido' };

    // Validação de dígitos verificadores
    for (let t = 9; t < 11; t++) {
        let s = 0;
        for (let i = 0; i < t; i++) {
            s += parseInt(digits.charAt(i), 10) * (t + 1 - i);
        }
        const r = ((s * 10) % 11) % 10;
        if (parseInt(digits.charAt(t), 10) !== r) {
            return { valid: false, error: 'CPF inválido' };
        }
    }
    return { valid: true };
}

/**
 * Valida um CNPJ.
 */
export function validateCNPJ(cnpj: string): ValidationResult {
    const digits = cnpj.replace(/\D/g, '');
    if (digits.length !== 14) return { valid: false, error: 'CNPJ deve ter 14 dígitos' };
    if (/^(\d)\1{13}$/.test(digits)) return { valid: false, error: 'CNPJ inválido' };

    const weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

    let sum = 0;
    for (let i = 0; i < 12; i++) sum += parseInt(digits[i]!, 10) * weights1[i]!;
    let r = sum % 11 < 2 ? 0 : 11 - (sum % 11);
    if (parseInt(digits[12]!, 10) !== r) return { valid: false, error: 'CNPJ inválido' };

    sum = 0;
    for (let i = 0; i < 13; i++) sum += parseInt(digits[i]!, 10) * weights2[i]!;
    r = sum % 11 < 2 ? 0 : 11 - (sum % 11);
    if (parseInt(digits[13]!, 10) !== r) return { valid: false, error: 'CNPJ inválido' };

    return { valid: true };
}

/**
 * Valida senha com requisitos de segurança.
 */
export function validatePassword(password: string, minLength = 8): ValidationResult {
    if (!password) return { valid: false, error: 'Senha é obrigatória' };
    if (password.length < minLength) return { valid: false, error: `Senha deve ter pelo menos ${minLength} caracteres` };
    if (password.length > 128) return { valid: false, error: 'Senha muito longa' };
    if (!/[A-Z]/.test(password)) return { valid: false, error: 'Senha deve conter letra maiúscula' };
    if (!/[a-z]/.test(password)) return { valid: false, error: 'Senha deve conter letra minúscula' };
    if (!/[0-9]/.test(password)) return { valid: false, error: 'Senha deve conter número' };
    if (!/[^A-Za-z0-9]/.test(password)) return { valid: false, error: 'Senha deve conter caractere especial' };
    return { valid: true };
}

/**
 * Valida comprimento de string genérica.
 */
export function validateLength(value: string, min: number, max: number, label = 'Campo'): ValidationResult {
    if (value.length < min) return { valid: false, error: `${label} deve ter pelo menos ${min} caracteres` };
    if (value.length > max) return { valid: false, error: `${label} deve ter no máximo ${max} caracteres` };
    return { valid: true };
}
