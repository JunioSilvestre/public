/**
 * @fileoverview Data Exposure Detector — Detecta vazamentos de dados sensíveis no client.
 *
 * Monitora DOM, console e network para dados sensíveis expostos acidentalmente.
 *
 * @module security/data
 */

import { containsSensitiveData, auditClientStorage } from './sensitive-data-guard';

/**
 * Resultados de uma varredura de exposição de dados.
 */
export interface ExposureReport {
    storageFindings: Array<{ type: string; key: string; label: string }>;
    domFindings: string[];
    timestamp: number;
}

/**
 * Executa uma varredura completa de exposição de dados no client.
 */
export function detectDataExposure(): ExposureReport {
    return {
        storageFindings: auditClientStorage(),
        domFindings: auditDOMForSensitiveData(),
        timestamp: Date.now(),
    };
}

/**
 * Verifica o DOM visível em busca de dados sensíveis renderizados.
 */
function auditDOMForSensitiveData(): string[] {
    const findings: string[] = [];
    if (typeof document === 'undefined') return findings;

    // Verifica inputs com valores sensíveis
    const inputs = document.querySelectorAll<HTMLInputElement>('input[type="hidden"], input[type="text"]');
    inputs.forEach((input) => {
        const check = containsSensitiveData(input.value);
        if (check.sensitive) {
            findings.push(
                `<input name="${input.name || input.id}"> contém ${check.label}: "${input.value.slice(0, 20)}..."`
            );
        }
    });

    // Verifica data attributes com valores sensíveis
    const allElements = document.querySelectorAll('[data-token], [data-key], [data-secret], [data-api-key]');
    allElements.forEach((el) => {
        for (const attr of Array.from(el.attributes)) {
            if (attr.name.startsWith('data-')) {
                const check = containsSensitiveData(attr.value);
                if (check.sensitive) {
                    findings.push(
                        `<${el.tagName.toLowerCase()}> tem ${attr.name} com ${check.label}`
                    );
                }
            }
        }
    });

    return findings;
}

/**
 * Monitora console.log para alertar sobre dados sensíveis logados.
 * Chame no startup da aplicação em modo development.
 */
export function monitorConsoleLogs(): void {
    if (typeof console === 'undefined') return;

    const originalLog = console.log;
    console.log = (...args: unknown[]) => {
        for (const arg of args) {
            if (typeof arg === 'string') {
                const check = containsSensitiveData(arg);
                if (check.sensitive) {
                    console.warn(
                        `[data-exposure-detector] ⚠️ Possível ${check.label} logado no console!`
                    );
                }
            }
        }
        originalLog.apply(console, args);
    };
}
