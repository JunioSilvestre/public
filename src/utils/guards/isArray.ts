/**
 * @arquivo    guards/isArray.ts
 * @modulo     Utilitários / Guards (Guardas de Tipo)
 * @descricao  Type guard TypeScript que verifica em tempo de execução se um
 *             valor desconhecido é um Array JavaScript válido. Suporta variante
 *             tipada que também verifica se todos os elementos do array são
 *             de um tipo específico, usando um guard de elemento passado
 *             como parâmetro.
 *
 * @exemplos_de_uso
 *   - isArray([])                    → true   (array vazio é array)
 *   - isArray([1, 2, 3])             → true
 *   - isArray(["a", "b"])            → true
 *   - isArray({})                    → false  (objeto não é array)
 *   - isArray(null)                  → false
 *   - isArray("abc")                 → false
 *   - isArray(new Set([1,2]))        → false  (Set não é Array)
 *
 *   Variante tipada:
 *   - isArrayOf(valor, isString)     → true se todos elementos são strings
 *   - isArrayOf([1, "a"], isNumber)  → false (nem todos são number)
 *
 *   Variante com tamanho:
 *   - isArrayNaoVazio([])            → false
 *   - isArrayNaoVazio([1])           → true
 *
 * @uso_tipico
 *   if (isArrayOf(resposta.items, isString)) {
 *     // TypeScript sabe que resposta.items é string[]
 *     resposta.items.forEach(item => processar(item));
 *   }
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
