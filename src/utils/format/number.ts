/**
 * @arquivo    format/number.ts
 * @modulo     Utilitários / Formatação
 * @descricao  Fornece funções para formatação de números para exibição ao usuário,
 *             incluindo separadores de milhar, casas decimais, percentuais,
 *             notação científica e valores compactos (K, M, B). Utiliza a API
 *             Intl.NumberFormat para respeitar as convenções da localidade
 *             configurada (padrão pt-BR).
 *
 * @exemplos_de_uso
 *   - formatarNumero(1500000)           → "1.500.000"
 *   - formatarDecimal(3.14159, 2)       → "3,14"
 *   - formatarPercentual(0.856)         → "85,6%"
 *   - formatarPercentual(0.856, 2)      → "85,60%"
 *   - formatarCompacto(1500000)         → "1,5 mi"
 *   - formatarCompacto(1500000000)      → "1,5 bi"
 *   - formatarOrdinario(1)             → "1º"
 *   - formatarNotacaoCientifica(0.0004) → "4 × 10⁻⁴"
 *   - arredondar(1.2345, 2)            → 1.23
 *   - truncar(1.9999, 2)               → 1.99
 *
 * @tratamentos_especiais
 *   - Valor Infinity → retorna "∞"
 *   - Valor -Infinity → retorna "-∞"
 *   - Valor NaN → retorna "-" ou string vazia conforme configuração
 *   - Valor nulo ou undefined → retorna "0" ou string vazia
 *   - Precisão negativa → lança erro descritivo
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
