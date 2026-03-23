/**
 * @fileoverview Form Security Validator — Valida formulários inteiros com regras de segurança.
 *
 * Aplica validação e sanitização a todos os campos de um formulário de forma declarativa.
 *
 * @module security/validation
 */

import { sanitizeInput } from '../sanitize/input';
import type { ValidationResult } from './input-validator';

export interface FieldRule {
    /** Nome do campo no formulário. */
    field: string;
    /** O campo é obrigatório? */
    required?: boolean;
    /** Tamanho mínimo. */
    minLength?: number;
    /** Tamanho máximo. */
    maxLength?: number;
    /** Regex de validação personalizada. */
    pattern?: RegExp;
    /** Mensagem de erro para pattern. */
    patternMessage?: string;
    /** Função de validação custom. */
    validate?: (value: string) => ValidationResult;
}

export interface FormValidationResult {
    valid: boolean;
    errors: Record<string, string>;
    sanitizedValues: Record<string, string>;
}

/**
 * Valida e sanitiza todos os campos de um formulário.
 *
 * @example
 * ```ts
 * const result = validateForm(formData, [
 *   { field: 'name', required: true, minLength: 2, maxLength: 100 },
 *   { field: 'email', required: true, validate: validateEmail },
 *   { field: 'message', required: true, maxLength: 5000 },
 * ]);
 *
 * if (!result.valid) {
 *   // result.errors = { email: 'Email inválido', ... }
 * }
 * ```
 */
export function validateForm(
    data: Record<string, unknown>,
    rules: FieldRule[],
): FormValidationResult {
    const errors: Record<string, string> = {};
    const sanitizedValues: Record<string, string> = {};

    for (const rule of rules) {
        const rawValue = data[rule.field];
        const value = typeof rawValue === 'string' ? sanitizeInput(rawValue) : '';
        sanitizedValues[rule.field] = value;

        // Required
        if (rule.required && !value) {
            errors[rule.field] = `${rule.field} é obrigatório`;
            continue;
        }

        if (!value) continue; // campo opcional vazio

        // Min length
        if (rule.minLength && value.length < rule.minLength) {
            errors[rule.field] = `${rule.field} deve ter pelo menos ${rule.minLength} caracteres`;
            continue;
        }

        // Max length
        if (rule.maxLength && value.length > rule.maxLength) {
            errors[rule.field] = `${rule.field} deve ter no máximo ${rule.maxLength} caracteres`;
            continue;
        }

        // Pattern
        if (rule.pattern && !rule.pattern.test(value)) {
            errors[rule.field] = rule.patternMessage ?? `${rule.field} formato inválido`;
            continue;
        }

        // Custom validation
        if (rule.validate) {
            const result = rule.validate(value);
            if (!result.valid) {
                errors[rule.field] = result.error ?? `${rule.field} inválido`;
            }
        }
    }

    return {
        valid: Object.keys(errors).length === 0,
        errors,
        sanitizedValues,
    };
}
