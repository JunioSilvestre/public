# Módulo de Cache Seguro

## 1. Propósito

O módulo `cache` define políticas e implementa mecanismos para o armazenamento em cache seguro no lado do cliente. Embora o cache seja ótimo para a performance, ele pode introduzir vulnerabilidades se dados sensíveis forem armazenados de forma inadequada e acessados por scripts maliciosos (XSS).

## 2. Estrutura

- **`cacheEncryption.ts`**: Fornece funções para criptografar e descriptografar dados antes de armazená-los no `localStorage` ou `sessionStorage`. Isso adiciona uma camada de proteção para que, mesmo que um script consiga ler o cache, os dados não estarão em texto plano.

- **`cacheIsolation.ts`**: Implementa estratégias para isolar o cache de diferentes contextos da aplicação, como entre tenants em um ambiente multi-tenant, para prevenir vazamento de dados.

- **`cachePolicies.ts`**: Define políticas claras sobre o que pode e o que não pode ser armazenado em cache no cliente. Por exemplo, informações de sessão ou tokens nunca devem ser cacheados no `localStorage`. Este arquivo pode exportar constantes e funções de validação para aplicar essas políticas.