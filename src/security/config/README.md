# Módulo de Configuração de Segurança

## 1. Propósito

O módulo `config` centraliza todas as configurações relacionadas à segurança da aplicação em um único lugar. Em vez de ter valores de configuração espalhados por vários arquivos e middlewares, este módulo os organiza e os torna facilmente auditáveis e gerenciáveis.

## 2. Estrutura

- **`auth.config.ts`**: Configurações para autenticação, como o tempo de expiração de tokens, a força da criptografia, ou configurações do provedor OAuth.
- **`cors.config.ts`**: Define a política de Cross-Origin Resource Sharing (CORS), especificando quais origens (domínios) têm permissão para fazer requisições à nossa API.
- **`csp.config.ts`**: Contém a configuração detalhada para a Content Security Policy, listando as fontes confiáveis para scripts, estilos, imagens, etc.
- **`encryption.config.ts`**: Define os algoritmos e a força das chaves usadas para criptografia na aplicação (ex: no cache seguro).
- **`hsts.config.ts`**: Configuração para o cabeçalho HTTP Strict Transport Security (HSTS), que força a comunicação via HTTPS.
- **`rateLimit.config.ts`**: Define os limites de taxa para diferentes endpoints (ex: 10 tentativas de login por minuto por IP).