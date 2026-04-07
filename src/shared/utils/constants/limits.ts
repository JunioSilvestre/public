/**
 * @arquivo    constants/limits.ts
 * @modulo     Utilitários / Constantes
 * @descricao  Define os limites (mínimos e máximos) aceitos pelos campos e
 *             operações da aplicação. Centraliza regras de negócio relacionadas
 *             a tamanhos, quantidades e faixas de valores, garantindo que as
 *             validações de formulários, inputs e chamadas de API sejam
 *             consistentes em toda a base de código.
 *
 * @exemplos_de_uso
 *   - Comprimento mínimo de senha: 8 caracteres
 *   - Comprimento máximo de senha: 128 caracteres
 *   - Comprimento mínimo de nome de usuário: 3 caracteres
 *   - Comprimento máximo de nome de usuário: 50 caracteres
 *   - Tamanho máximo de arquivo para upload (em bytes): 5 * 1024 * 1024 (5 MB)
 *   - Número máximo de itens por página (paginação): 100
 *   - Número padrão de itens por página: 10
 *   - Valor mínimo permitido para transações financeiras: 0.01
 *   - Valor máximo permitido para transações financeiras: 999999.99
 *   - Timeout padrão de requisição HTTP (em milissegundos): 30000
 *
 * @responsabilidade
 *   Centralizar todos os limiares e restrições de negócio para evitar
 *   duplicação e divergência entre as camadas de validação (UI, API, banco).
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
