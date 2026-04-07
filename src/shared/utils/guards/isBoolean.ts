/**
 * @arquivo    guards/isBoolean.ts
 * @modulo     Utilitários / Guards (Guardas de Tipo)
 * @descricao  Type guard TypeScript que verifica em tempo de execução se um
 *             valor desconhecido é estritamente um booleano (true ou false).
 *             Complementa os outros guards de tipo, sendo especialmente útil
 *             para processar flags de feature toggles, configurações e respostas
 *             de APIs que podem retornar booleanos como 0/1 ou "true"/"false".
 *
 * @exemplos_de_uso
 *   - isBoolean(true)         → true
 *   - isBoolean(false)        → true
 *   - isBoolean(0)            → false  (inteiro 0 não é boolean)
 *   - isBoolean(1)            → false  (inteiro 1 não é boolean)
 *   - isBoolean("true")       → false  (string não é boolean)
 *   - isBoolean(null)         → false
 *   - isBoolean(undefined)    → false
 *
 *   Variantes:
 *   - isTruthy(valor):        true para qualquer valor "verdadeiro" (|| operator)
 *   - isFalsy(valor):         true para null, undefined, 0, "", NaN, false
 *   - parsearBooleano("true") → true (converte strings para booleano)
 *   - parsearBooleano("1")    → true
 *   - parsearBooleano("0")    → false
 *
 * @uso_tipico
 *   if (isBoolean(config.ativo)) {
 *     // TypeScript sabe que config.ativo é boolean
 *     exibirComponente(config.ativo);
 *   }
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
