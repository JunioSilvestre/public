/**
 * @fileoverview API Request Throttle — Controla chamadas excessivas a APIs.
 *
 * Aplica debounce e agrupamento de requisições para evitar sobrecarga.
 *
 * @module security/api
 */

/**
 * Cria uma função throttled que limita a frequência de chamadas.
 *
 * @param fn — Função a ser throttled.
 * @param delayMs — Intervalo mínimo entre execuções em ms.
 */
export function throttle<T extends (...args: unknown[]) => unknown>(
    fn: T,
    delayMs: number,
): (...args: Parameters<T>) => void {
    let lastCall = 0;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    return (...args: Parameters<T>) => {
        const now = Date.now();
        const remaining = delayMs - (now - lastCall);

        if (remaining <= 0) {
            lastCall = now;
            fn(...args);
        } else if (!timeoutId) {
            timeoutId = setTimeout(() => {
                lastCall = Date.now();
                timeoutId = null;
                fn(...args);
            }, remaining);
        }
    };
}

/**
 * Cria uma função debounced que atrasa a execução até o fim de uma sequência de chamadas.
 *
 * @param fn — Função a ser debounced.
 * @param delayMs — Tempo de espera após a última chamada.
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
    fn: T,
    delayMs: number,
): (...args: Parameters<T>) => void {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    return (...args: Parameters<T>) => {
        if (timeoutId) clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
            timeoutId = null;
            fn(...args);
        }, delayMs);
    };
}
