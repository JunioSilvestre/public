/**
 * @arquivo    guards/isString.ts
 * @modulo     Utilitários / Guards (Guardas de Tipo)
 * @descricao  Type guard TypeScript que verifica em tempo de execução se um
 *             valor desconhecido é do tipo string. Utilizado para estreitar
 *             tipos (type narrowing) de dados vindos de APIs, formulários ou
 *             parâmetros de rota, onde o tipo exato pode não ser garantido.
 *             Suporta variante opcional que também verifica se a string
 *             não está vazia.
 *
 * @exemplos_de_uso
 *   - isString("hello")        → true
 *   - isString("")             → true   (string vazia é string)
 *   - isString("  ")           → true   (string com espaços é string)
 *   - isString(42)             → false
 *   - isString(null)           → false
 *   - isString(undefined)      → false
 *   - isString(true)           → false
 *   - isString([])             → false
 *   - isString({})             → false
 *   - isStringNaoVazia("")     → false  (variante que rejeita string vazia)
 *   - isStringNaoVazia("ok")   → true
 *
 * @uso_tipico
 *   if (isString(query.id)) {
 *     // TypeScript sabe que query.id é string
 *     buscarPorId(query.id.trim());
 *   }
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
