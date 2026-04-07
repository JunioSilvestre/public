/**
 * @arquivo    guards/isNumber.ts
 * @modulo     Utilitários / Guards (Guardas de Tipo)
 * @descricao  Type guard TypeScript que verifica em tempo de execução se um
 *             valor desconhecido é do tipo número (number) e é finito (não NaN,
 *             não Infinity). Utilizado para estreitar tipos (type narrowing) em
 *             blocos condicionais, garantindo segurança de tipo sem necessidade
 *             de asserções manuais com "as number".
 *
 * @exemplos_de_uso
 *   - isNumber(42)          → true
 *   - isNumber(3.14)        → true
 *   - isNumber(0)           → true
 *   - isNumber(-100)        → true
 *   - isNumber(NaN)         → false  (NaN não é considerado número válido)
 *   - isNumber(Infinity)    → false  (Infinity não é número finito)
 *   - isNumber("42")        → false  (string numérica não é number)
 *   - isNumber(null)        → false
 *   - isNumber(undefined)   → false
 *   - isNumber({})          → false
 *
 * @uso_tipico
 *   if (isNumber(valor)) {
 *     // Aqui TypeScript sabe que "valor" é number
 *     resultado = valor * 2;
 *   }
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
