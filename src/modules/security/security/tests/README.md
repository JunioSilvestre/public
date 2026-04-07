# Módulo de Testes de Segurança

## 1. Propósito

Esta pasta contém todos os testes automatizados focados especificamente em encontrar vulnerabilidades de segurança na aplicação. Diferente dos testes unitários ou E2E que validam a funcionalidade, estes testes tentam ativamente "quebrar" a aplicação usando vetores de ataque conhecidos.

## 2. Estrutura

- **`/fuzzing`**: Testes de Fuzzing, que enviam uma grande quantidade de dados aleatórios e malformados para as entradas da aplicação (APIs, formulários) na esperança de causar um erro inesperado que possa revelar uma vulnerabilidade.

- **`/penetration`**: Simula testes de penetração automatizados, focando em explorar vulnerabilidades específicas como XSS, SQL Injection, e falhas de autenticação.

- **`/securityRegression`**: Testes de regressão de segurança. Após uma vulnerabilidade ser encontrada e corrigida, um teste que explora especificamente essa falha é adicionado aqui para garantir que ela nunca retorne em futuras atualizações.