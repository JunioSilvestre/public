# Módulo de Validadores de Segurança

## 1. Propósito

Enquanto o `sanitize` limpa os dados, o `validators` verifica se os dados recebidos estão em conformidade com as regras de negócio e de segurança. A validação acontece antes da sanitização e pode rejeitar uma requisição ou entrada imediatamente se ela for inválida.

## 2. Estrutura

- **`apiKeyValidator.ts`**: Valida se uma chave de API tem o formato correto e se ela existe e está ativa.
- **`fileUploadValidator.ts`**: Valida arquivos enviados pelo usuário, checando o tipo (MIME type), o tamanho e, se possível, escaneando por malware.
- **`headerValidator.ts`**: Valida os cabeçalhos de uma requisição, garantindo que os headers esperados estão presentes e corretos.
- **`inputValidator.ts`**: Usa schemas (com `zod` ou `yup`) para validar de forma complexa os dados de entrada em formulários.
- **`payloadValidator.ts`**: Valida o corpo (payload) de requisições `POST` ou `PUT` contra um schema definido.
- **`queryParamValidator.ts`**: Valida os parâmetros de query de uma URL.
- **`routeAccessValidator.ts`**: Valida se o usuário atual tem permissão para acessar uma determinada rota ou recurso.
- **`schemaValidator.ts`**: Fornece um invólucro (wrapper) genérico para a biblioteca de validação de schemas (como `zod`), facilitando seu uso em toda a aplicação.