/**
 * @arquivo    parse/number.ts
 * @modulo     Utilitários / Parseamento
 * @descricao  Converte strings numéricas formatadas (com separadores de milhar,
 *             vírgula decimal, símbolo de moeda, símbolo de percentual etc.)
 *             em números JavaScript primitivos para processamento e cálculo.
 *             Opera no sentido inverso de format/number.ts e format/currency.ts,
 *             transformando a representação visual de volta em valor numérico.
 *
 * @exemplos_de_uso
 *   - parsearNumero("1.500.000")         → 1500000
 *   - parsearNumero("3,14")              → 3.14
 *   - parsearMoeda("R$ 1.500,00")        → 1500.00
 *   - parsearMoeda("US$ 1,500.00")       → 1500.00
 *   - parsearPercentual("85,60%")        → 0.856
 *   - parsearPercentual("85.6%")         → 0.856
 *   - parsearNumeroSeguro("abc")         → null (não lança exceção)
 *   - parsearNumeroSeguro("1.500")       → 1500
 *   - parsearInteiro("42.9")             → 42 (descarta decimais)
 *
 * @tratamentos_especiais
 *   - String vazia ou somente espaços → retorna null ou 0 conforme configuração
 *   - String com apenas símbolo ("R$", "%") → retorna 0 ou null
 *   - Valor "NaN" como string → retorna null
 *   - Overflow numérico → retorna Infinity com aviso no console
 *   - Vírgula e ponto tanto como separador decimal quanto de milhar →
 *     detecta automaticamente com base no último separador da string
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
