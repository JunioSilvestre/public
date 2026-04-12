"use client";

import { useEffect, useState } from 'react';

interface SystemInfo {
    os: string;
    browser: string;
    currentAccess: string;
    lastAccess: string | null;
}

/**
 * Parses the user-agent string to extract the operating system name.
 */
function detectOS(ua: string): string {
    if (/Windows NT 10/i.test(ua)) return 'Windows 10/11';
    if (/Windows NT/i.test(ua)) return 'Windows';
    if (/Mac OS X/i.test(ua)) return 'macOS';
    if (/Android/i.test(ua)) return 'Android';
    if (/iPhone|iPad|iPod/i.test(ua)) return 'iOS';
    if (/Linux/i.test(ua)) return 'Linux';
    return 'Desconhecido';
}

/**
 * Parses the user-agent string to extract the browser name + version.
 */
function detectBrowser(ua: string): string {
    // Order matters — Edge includes "Chrome", so check Edge first.
    if (/Edg\//i.test(ua)) {
        const m = ua.match(/Edg\/([\d.]+)/);
        return `Edge ${m?.[1] ?? ''}`.trim();
    }
    if (/OPR\//i.test(ua) || /Opera/i.test(ua)) {
        const m = ua.match(/OPR\/([\d.]+)/);
        return `Opera ${m?.[1] ?? ''}`.trim();
    }
    if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) {
        const m = ua.match(/Chrome\/([\d.]+)/);
        return `Chrome ${m?.[1] ?? ''}`.trim();
    }
    if (/Firefox\//i.test(ua)) {
        const m = ua.match(/Firefox\/([\d.]+)/);
        return `Firefox ${m?.[1] ?? ''}`.trim();
    }
    if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) {
        const m = ua.match(/Version\/([\d.]+)/);
        return `Safari ${m?.[1] ?? ''}`.trim();
    }
    return 'Desconhecido';
}

const STORAGE_KEY = 'dashboard_last_access';

/**
 * Hook that captures system information from the client:
 * - Operating system
 * - Browser name + version
 * - Current access timestamp
 * - Previous access timestamp (persisted in localStorage)
 */
export function useSystemInfo(): SystemInfo {
    const [info, setInfo] = useState<SystemInfo>({
        os: '',
        browser: '',
        currentAccess: '',
        lastAccess: null,
    });

    useEffect(() => {
        const ua = navigator.userAgent;
        const now = new Date();
        const formatted = now.toLocaleString('pt-BR', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });

        // Read previous access before overwriting
        const previous = localStorage.getItem(STORAGE_KEY);

        // Persist current access for next visit
        localStorage.setItem(STORAGE_KEY, formatted);

        setInfo({
            os: detectOS(ua),
            browser: detectBrowser(ua),
            currentAccess: formatted,
            lastAccess: previous,
        });
    }, []);

    return info;
}
