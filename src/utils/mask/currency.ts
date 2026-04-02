/**
 * @arquivo    mask/currency.ts
 * @modulo     Utilitários / Máscaras de Input
 * @descricao  Aplica máscara monetária progressiva em tempo real a campos de
 *             input de valores financeiros. Formata o valor automaticamente
 *             no padrão brasileiro (R$ X.XXX,XX) enquanto o usuário digita,
 *             garantindo que apenas valores numéricos válidos sejam inseridos
 *             e fornecendo feedback visual imediato sobre o valor.
 *
 * @comportamento_progressivo
 *   Durante a digitação:
 *   - "1"       → "R$ 0,01"  (valores crescem da direita para a esquerda)
 *   - "12"      → "R$ 0,12"
 *   - "1234"    → "R$ 12,34"
 *   - "123456"  → "R$ 1.234,56"
 *   - "12345678"→ "R$ 123.456,78"
 *
 * @funcionalidades
 *   - mascaraMoeda(valor):          aplica máscara BRL com símbolo "R$"
 *   - mascaraMoedaSemSimbolo(valor):aplica apenas a formatação numérica
 *   - mascaraDolar(valor):          aplica máscara USD com símbolo "US$"
 *   - removerMascaraMoeda(valor):   retorna o float correspondente ("R$ 12,34" → 12.34)
 *
 * @tratamentos_especiais
 *   - Backspace → recalcula valor removendo último dígito
 *   - Colar valor já formatado → remove formatação e reaplica
 *   - Valor zerado → exibe "R$ 0,00"
 *   - Valor negativo → exibe "-R$ X,XX" (modo balanço financeiro)
 *   - Limite máximo de valor → configurable via parâmetro
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
