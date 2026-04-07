/**
 * @fileoverview API Request Signer — Assina requisições para garantir integridade.
 *
 * Gera uma assinatura HMAC-SHA256 do body/timestamp para que o servidor
 * possa verificar que a requisição não foi adulterada em trânsito.
 *
 * @module security/api
 */

/**
 * Assina o payload de uma requisição com HMAC-SHA256.
 *
 * @param payload — O body da requisição serializado.
 * @param secret — Segredo compartilhado com o backend.
 * @param timestamp — Timestamp da requisição (previne replay attack).
 * @returns A assinatura em formato base64url.
 */
export async function signRequest(
    payload: string,
    secret: string,
    timestamp: number = Date.now(),
): Promise<{ signature: string; timestamp: number }> {
    const data = `${timestamp}.${payload}`;
    const enc = new TextEncoder();

    const key = await globalThis.crypto.subtle.importKey(
        'raw',
        enc.encode(secret).buffer.slice(0) as ArrayBuffer,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );

    const sig = await globalThis.crypto.subtle.sign(
        'HMAC',
        key,
        enc.encode(data).buffer.slice(0) as ArrayBuffer,
    );

    let binary = '';
    const bytes = new Uint8Array(sig);
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }

    const signature = btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    return { signature, timestamp };
}

/**
 * Cria headers de assinatura para uma requisição.
 *
 * @example
 * ```ts
 * const body = JSON.stringify({ name: 'João' });
 * const headers = await getSignatureHeaders(body, process.env.API_SECRET!);
 * await fetch('/api/data', { method: 'POST', headers, body });
 * ```
 */
export async function getSignatureHeaders(
    payload: string,
    secret: string,
): Promise<Record<string, string>> {
    const { signature, timestamp } = await signRequest(payload, secret);
    return {
        'X-Request-Signature': signature,
        'X-Request-Timestamp': String(timestamp),
    };
}
