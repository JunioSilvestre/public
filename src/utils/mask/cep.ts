/**
 * @arquivo    mask/cep.ts
 * @modulo     Utilitários / Máscaras de Input
 * @descricao  Aplica máscara progressiva em tempo real para campos de CEP
 *             (Código de Endereçamento Postal) brasileiro. Formata o valor
 *             no padrão "XXXXX-XXX" enquanto o usuário digita, facilitando
 *             a entrada de endereços em formulários de cadastro, checkout
 *             e qualquer outro contexto que exija CEP.
 *
 * @comportamento_progressivo
 *   Durante a digitação de um CEP:
 *   - "0"         → "0"
 *   - "01310"     → "01310"
 *   - "013101"    → "01310-1"
 *   - "01310100"  → "01310-100"
 *
 * @funcionalidades
 *   - mascaraCEP(valor):    aplica máscara "XXXXX-XXX" progressivamente
 *   - removerMascara(valor):retorna apenas os 8 dígitos numéricos
 *   - ehCEPCompleto(valor): retorna true se tiver todos os 8 dígitos preenchidos
 *
 * @tratamentos_especiais
 *   - Caracteres não numéricos → removidos automaticamente
 *   - Backspace sobre o hífen → remove o dígito anterior ao hífen
 *   - Valor vazio → retorna string vazia
 *   - Comprimento além de 8 dígitos → trunca no máximo permitido
 *   - CEP com zeros à esquerda → preservados (ex: "01310-100")
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
