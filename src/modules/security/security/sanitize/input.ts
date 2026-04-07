/**
 * @fileoverview Input Sanitizer — Sanitização de inputs de formulário.
 *
 * Remove caracteres perigosos e normaliza inputs antes de processamento.
 * Complementa o módulo XSS com sanitização a nível de campo individual.
 *
 * @module security/sanitize
 */

/**
 * Remove caracteres de controle perigosos de uma string.
 * Mantém apenas caracteres imprimíveis + whitespace básico.
 */
export function sanitizeInput(input: string): string {
    if (typeof input !== 'string') return '';
    return input
        .replace(/\0/g, '')                          // null bytes
        .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F]/g, '') // controle ASCII (exceto tab, CR, LF)
        .replace(/\u200B/g, '')                       // zero-width space
        .replace(/\uFEFF/g, '')                       // BOM
        .trim();
}

/**
 * Sanitiza um email removendo caracteres perigosos.
 */
export function sanitizeEmail(email: string): string {
    return sanitizeInput(email)
        .toLowerCase()
        .replace(/[^a-z0-9@._+\-]/g, '')
        .slice(0, 254); // RFC 5321 max
}

/**
 * Sanitiza um número de telefone.
 */
export function sanitizePhone(phone: string): string {
    return sanitizeInput(phone)
        .replace(/[^0-9+\-() ]/g, '')
        .slice(0, 20);
}

/**
 * Sanitiza um nome de usuário.
 */
export function sanitizeUsername(username: string): string {
    return sanitizeInput(username)
        .replace(/[^a-zA-Z0-9._\-@]/g, '')
        .slice(0, 100);
}

/**
 * Sanitiza texto livre (comentários, bios, mensagens).
 * Remove HTML tags mas mantém formatação básica de texto.
 */
export function sanitizeText(text: string, maxLength = 5000): string {
    return sanitizeInput(text)
        .replace(/<[^>]*>/g, '') // strip HTML tags
        .slice(0, maxLength);
}

/**
 * Sanitiza um CPF/CNPJ.
 */
export function sanitizeDocument(doc: string): string {
    return sanitizeInput(doc)
        .replace(/[^0-9.\-/]/g, '')
        .slice(0, 18);
}
