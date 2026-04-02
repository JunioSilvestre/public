/**
 * @arquivo    guards/isObject.ts
 * @modulo     Utilitários / Guards (Guardas de Tipo)
 * @descricao  Type guard TypeScript que verifica em tempo de execução se um
 *             valor desconhecido é um objeto simples (plain object), ou seja,
 *             um valor que possui typeof "object", não é nulo, não é um Array
 *             e não é uma instância de classe especial (Date, Map, Set, etc.).
 *             Essencial para validar payloads de API, parâmetros de funções
 *             e dados vindos de fontes externas antes de acessar suas propriedades.
 *
 * @exemplos_de_uso
 *   - isObject({})                    → true
 *   - isObject({ nome: "João" })      → true
 *   - isObject(null)                  → false  (null tem typeof "object" mas não é objeto)
 *   - isObject([])                    → false  (arrays não são plain objects)
 *   - isObject(new Date())            → false  (instância de classe)
 *   - isObject(42)                    → false
 *   - isObject("texto")               → false
 *   - isObject(undefined)             → false
 *   - isObject(new Map())             → false
 *
 * @uso_tipico
 *   if (isObject(resposta)) {
 *     // TypeScript sabe que "resposta" é Record<string, unknown>
 *     const id = resposta['id'];
 *   }
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
