# Módulo de Tipos de Segurança

## 1. Propósito

O módulo `types` define as interfaces e tipos TypeScript customizados para todos os objetos e estruturas de dados relacionados à segurança. Usar tipos fortes e claros é uma forma de segurança em si, pois previne uma classe inteira de bugs em tempo de desenvolvimento.

## 2. Estrutura

- **`audit.types.ts`**: Define a estrutura para logs de auditoria. Ex: quem fez o quê, quando e de qual IP.

- **`auth.types.ts`**: Tipos para objetos de autenticação, como o payload de um JWT, o objeto de usuário, ou as permissões de uma role.

- **`security.types.ts`**: Tipos genéricos de segurança, como a estrutura de uma configuração de CSP ou de uma política de CORS.

- **`tenant.types.ts`**: Tipos relacionados ao multi-tenancy, definindo o que é um tenant e como ele se relaciona com usuários e dados.