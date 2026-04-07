/**
 * @arquivo    guards/isDate.ts
 * @modulo     Utilitários / Guards (Guardas de Tipo)
 * @descricao  Type guard TypeScript que verifica em tempo de execução se um
 *             valor é um objeto Date JavaScript válido (instância de Date e
 *             não "Invalid Date"). Essencial para tratar dados de APIs que
 *             podem retornar datas como string, timestamp ou Date, garantindo
 *             segurança antes de chamar métodos de Date.
 *
 * @exemplos_de_uso
 *   - isDate(new Date())              → true
 *   - isDate(new Date("2026-04-02"))  → true
 *   - isDate(new Date("invalido"))    → false  (Invalid Date)
 *   - isDate("2026-04-02")           → false  (string, não Date)
 *   - isDate(1743572482314)          → false  (timestamp, não Date)
 *   - isDate(null)                   → false
 *   - isDate(undefined)              → false
 *   - isDate({})                     → false
 *
 *   Variante no futuro:
 *   - isDataNoFuturo(new Date(2099, 0, 1))  → true
 *   - isDataNoPassado(new Date(2000, 0, 1)) → true
 *
 * @uso_tipico
 *   if (isDate(item.dataExpiracao)) {
 *     // TypeScript sabe que é Date válido
 *     const diasRestantes = diferencaEmDias(item.dataExpiracao, new Date());
 *   }
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
