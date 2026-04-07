/**
 * @arquivo    mask/phone.ts
 * @modulo     Utilitários / Máscaras de Input
 * @descricao  Aplica máscara progressiva em tempo real a campos de input
 *             para números de telefone brasileiros (fixo e celular).
 *             Detecta automaticamente se é telefone fixo (8 dígitos) ou
 *             celular (9 dígitos) e aplica o formato correto conforme
 *             o usuário digita. Suporta também o código de área (DDD).
 *
 * @formatos_suportados
 *   - Fixo sem DDD:   "XXXX-XXXX"           (8 dígitos)
 *   - Celular sem DDD:"9XXXX-XXXX"           (9 dígitos)
 *   - Fixo com DDD:   "(XX) XXXX-XXXX"       (10 dígitos)
 *   - Celular com DDD:"(XX) 9XXXX-XXXX"      (11 dígitos)
 *   - Linha 0800:     "0800 XXX XXXX"
 *
 * @comportamento_progressivo
 *   Durante a digitação de celular com DDD:
 *   - "11"       → "(11"
 *   - "119"      → "(11) 9"
 *   - "11987654" → "(11) 9876-54"
 *   - "11987654321"→ "(11) 98765-4321"
 *
 * @funcionalidades
 *   - mascaraTelefone(valor):     detecta e aplica formato automaticamente
 *   - mascaraTelefoneFixo(valor): força formato de telefone fixo
 *   - mascaraCelular(valor):      força formato de celular
 *   - removerMascara(valor):      retorna apenas os dígitos
 *   - extrairDDD(valor):          retorna os 2 primeiros dígitos
 *
 * @tratamentos_especiais
 *   - Caracteres não numéricos → removidos automaticamente antes de mascarar
 *   - DDD inválido (< 11 ou > 99) → ainda aplica a máscara sem validação
 *   - Valor vazio → retorna string vazia
 *   - Comprimento além do máximo → trunca nos 11 dígitos
 *   - Telefones internacionais → não suportados (usar lib especializada)
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
