/**
 * @arquivo    format/currency.ts
 * @modulo     Utilitários / Formatação
 * @descricao  Fornece funções para formatação de valores monetários conforme
 *             as convenções brasileiras (pt-BR / BRL) e internacionais.
 *             Transforma números brutos em strings prontas para exibição ao
 *             usuário, incluindo símbolo de moeda, separadores e casas decimais.
 *             Utiliza a API nativa Intl.NumberFormat para garantir precisão
 *             e compatibilidade com diferentes localidades.
 *
 * @exemplos_de_uso
 *   - formatarMoeda(1500)           → "R$ 1.500,00"
 *   - formatarMoeda(1500, 'USD')    → "US$ 1,500.00"
 *   - formatarMoedaCompacta(1500000)→ "R$ 1,5 mi"
 *   - removerSimboloMoeda("R$ 1.500,00") → "1500.00"
 *   - converterCentavosParaReais(150000) → 1500.00
 *   - converterReaisParaCentavos(15.99)  → 1599
 *
 * @tratamentos_especiais
 *   - Valor nulo ou undefined → retorna "R$ 0,00"
 *   - Valor negativo → exibe com sinal negativo antes do símbolo: "-R$ 50,00"
 *   - Valor NaN → retorna string vazia ou valor padrão configurável
 *   - Overflow de float → arredonda para 2 casas decimais antes de formatar
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
