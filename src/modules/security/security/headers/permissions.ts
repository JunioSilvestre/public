/**
 * @fileoverview Permissions Policy — Controla quais APIs do browser estão disponíveis.
 *
 * Restringe acesso a features como câmera, microfone, geolocation, payment, etc.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
 */

export interface PermissionsPolicyOptions {
    camera?: string;
    microphone?: string;
    geolocation?: string;
    payment?: string;
    usb?: string;
    magnetometer?: string;
    gyroscope?: string;
    accelerometer?: string;
    autoplay?: string;
    fullscreen?: string;
    'picture-in-picture'?: string;
}

const DEFAULT_PERMISSIONS: PermissionsPolicyOptions = {
    camera: '()',
    microphone: '()',
    geolocation: '()',
    payment: '()',
    usb: '()',
    magnetometer: '()',
    gyroscope: '()',
    accelerometer: '()',
    autoplay: '(self)',
    fullscreen: '(self)',
    'picture-in-picture': '(self)',
};

/**
 * Gera o header Permissions-Policy.
 *
 * @example
 * ```ts
 * response.headers.set('Permissions-Policy', generatePermissionsPolicyHeader());
 * // → "camera=(), microphone=(), geolocation=(), ..."
 * ```
 */
export function generatePermissionsPolicyHeader(
    overrides: Partial<PermissionsPolicyOptions> = {},
): string {
    const merged = { ...DEFAULT_PERMISSIONS, ...overrides };
    return Object.entries(merged)
        .map(([key, value]) => `${key}=${value}`)
        .join(', ');
}
