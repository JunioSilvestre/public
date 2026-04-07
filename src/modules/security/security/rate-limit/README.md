# Módulo de Rate Limit (Limite de Taxa)

## 1. Propósito

Este módulo define as lógicas específicas de limite de taxa para diferentes tipos de ações na aplicação. Enquanto o `config/rateLimit.config.ts` define os números brutos, este módulo aplica esses números a contextos de negócio específicos. Isso ajuda a prevenir abuso, spam e ataques de força bruta de forma granular.

## 2. Estrutura

- **`api-calls.ts`**: Lógica de rate limit para chamadas de API genéricas. Pode definir um limite global para proteger os recursos do backend.

- **`form-submit.ts`**: Lógica de rate limit específica para o envio de formulários. Por exemplo, um usuário só pode tentar enviar o formulário de contato 3 vezes por minuto para evitar spam.

- **`index.ts`**: Exporta as diferentes lógicas para serem usadas pelos middlewares ou diretamente nos endpoints da API.