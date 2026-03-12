# Módulo de Middlewares de Segurança

## 1. Propósito

Este módulo contém uma série de middlewares que interceptam as requisições recebidas pela aplicação (no Edge ou no próprio servidor Next.js) para aplicar diversas camadas de segurança antes que a requisição chegue à lógica da aplicação. Eles são a nossa primeira linha de defesa.

## 2. Estrutura

- **`botProtection.ts`**: Middleware que integra as lógicas do módulo `anti-bot` para bloquear requisições suspeitas.
- **`cors.ts`**: Aplica a política de CORS definida em `config/cors.config.ts`.
- **`csrfProtection.ts`**: Implementa a proteção contra Cross-Site Request Forgery (CSRF), geralmente usando o padrão de Double Submit Cookie ou Synchronizer Token.
- **`ddosProtection.ts`**: Conecta-se a um serviço de mitigação de DDoS (Distributed Denial of Service) ou aplica lógicas de rate limiting mais agressivas.
- **`geoBlock.ts`**: Bloqueia ou permite requisições com base na localização geográfica do IP de origem.
- **`ipFilter.ts`**: Filtra requisições com base em listas de IPs permitidos (allowlists) ou bloqueados (blocklists).
- **`rateLimit.ts`**: Aplica as políticas de limite de taxa definidas em `config/rateLimit.config.ts`.
- **`requestSanitizer.ts`**: Limpa a requisição recebida (query params, body, headers) de caracteres maliciosos.
- **`securityHeaders.ts`**: Adiciona um conjunto de cabeçalhos de segurança às respostas, como CSP, HSTS, X-Frame-Options, etc.
- **`sessionGuard.ts`**: Protege endpoints que exigem uma sessão de usuário válida.
- **`tenantIsolationMiddleware.ts`**: Em um sistema multi-tenant, garante que uma requisição só possa acessar os dados do seu próprio tenant.
- **`userAgentFilter.ts`**: Bloqueia requisições de User-Agents conhecidos por serem maliciosos.