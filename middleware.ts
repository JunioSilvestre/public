/**
 * @fileoverview Next.js Middleware — Ponto de entrada para segurança em runtime.
 *
 * Aplica security headers e proteções básicas em todas as requisições.
 * Integra-se com os módulos em src/security/ que estiverem implementados.
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/middleware
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// ─────────────────────────────────────────────────────────────────────────────
// Configuração
// ─────────────────────────────────────────────────────────────────────────────

/** Rotas que não precisam de middleware (assets estáticos, etc). */
const EXCLUDED_PATHS = [
    '/_next/static',
    '/_next/image',
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
];

/** Rate limit simples em memória (por IP, por minuto). */
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 100;
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

// ─────────────────────────────────────────────────────────────────────────────
// Middleware principal
// ─────────────────────────────────────────────────────────────────────────────

export function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Ignora assets estáticos
    if (EXCLUDED_PATHS.some((p) => pathname.startsWith(p))) {
        return NextResponse.next();
    }

    const response = NextResponse.next();
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
        ?? request.headers.get('x-real-ip')
        ?? '0.0.0.0';

    // ── Rate Limiting simples ────────────────────────────────────────────────
    const now = Date.now();
    const entry = rateLimitMap.get(ip);

    if (entry && entry.resetAt > now) {
        entry.count++;
        if (entry.count > RATE_LIMIT_MAX_REQUESTS) {
            return new NextResponse('Too Many Requests', {
                status: 429,
                headers: {
                    'Retry-After': String(Math.ceil((entry.resetAt - now) / 1000)),
                    'Content-Type': 'text/plain',
                },
            });
        }
    } else {
        rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    }

    // Limpeza periódica do mapa de rate limit (a cada ~1000 requests)
    if (Math.random() < 0.001) {
        Array.from(rateLimitMap.entries()).forEach(([key, val]) => {
            if (val.resetAt < now) rateLimitMap.delete(key);
        });
    }

    // ── Security Headers adicionais (reforço) ────────────────────────────────
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-XSS-Protection', '0');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

    // ── Proteção de rotas de API ─────────────────────────────────────────────
    if (pathname.startsWith('/api/')) {
        // Remove headers que expõem informação
        response.headers.delete('X-Powered-By');
        response.headers.delete('Server');

        // CORS restritivo para APIs
        const origin = request.headers.get('origin') ?? '';
        const allowedOrigins = [
            process.env.NEXT_PUBLIC_APP_URL ?? '',
            'http://localhost:3000',
        ].filter(Boolean);

        if (allowedOrigins.includes(origin)) {
            response.headers.set('Access-Control-Allow-Origin', origin);
            response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
            response.headers.set('Access-Control-Max-Age', '86400');
            response.headers.set('Access-Control-Allow-Credentials', 'true');
        }

        // Preflight
        if (request.method === 'OPTIONS') {
            return new NextResponse(null, { status: 204, headers: response.headers });
        }
    }

    // ── Proteção contra scanner de vulnerabilidades ──────────────────────────
    const suspiciousPaths = [
        /\/\.env/i,
        /\/wp-(?:admin|login|config)/i,
        /\/phpmy?admin/i,
        /\/\.git\//i,
        /\/config\.(?:json|yml|yaml|xml)/i,
        /\/(?:server-status|server-info)/i,
        /\/actuator(?:\/|$)/i,
        /\/_(?:profiler|debug|console)/i,
    ];

    if (suspiciousPaths.some((pattern) => pattern.test(pathname))) {
        // Retorna 404 silencioso — não revela detecção
        return new NextResponse('Not Found', { status: 404 });
    }

    return response;
}

// Configuração de paths que ativam o middleware
export const config = {
    matcher: [
        /*
         * Match all request paths except:
         * - _next/static (static files)
         * - _next/image (image optimization files)
         * - favicon.ico (favicon file)
         */
        '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
};
