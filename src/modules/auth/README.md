# Módulo de Autenticação (Get Started)

Este módulo é responsável por gerenciar toda a jornada de autenticação e identificação de usuários no portal.

## Arquitetura Circular (Hub & Spoke)

O `AuthModal.tsx` atua como o ponto central, roteando os estados de autenticação:

### Fluxos Principais
1. **Login Flow**: Validação de e-mail/senha.
2. **Registration Flow**: Coleta de dados básicos + aceitação de cookies/termos.
3. **Recovery Flow**: Solicitação de reset e aplicação do novo token.
4. **Social Flow**: OAuth2 com provedores terceiros.

## Manutenibilidade

- **Hooks isolados**: Toda a lógica de estado e chamadas de API deve residir na pasta `hooks/`.
- **Componentes Atômicos**: Botões, inputs e cabeçalhos devem ser reutilizáveis dentro do módulo.
- **Tokens e Constantes**: Mensagens de erro e limites de segurança estão centralizados em `auth.constants.ts`.

## Segurança

- Implementar validação de input local antes do envio.
- Tratamento rigoroso de erros de API para evitar exposição de bugs internos.
- Uso de padrões seguros para armazenamento de token (HttpOnly Cookies ou similar).
