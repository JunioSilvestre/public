/**
 * @arquivo    mask/document.ts
 * @modulo     Utilitários / Máscaras de Input
 * @descricao  Aplica máscara progressiva em tempo real a campos de input
 *             para documentos brasileiros (CPF e CNPJ). Diferente da formatação
 *             estática (ver format/document.ts), esta função é projetada para
 *             ser chamada no evento onChange do input, formatando o valor
 *             caractere a caractere conforme o usuário digita, provendo
 *             uma experiência de digitação fluída e intuitiva.
 *
 * @comportamento_progressivo
 *   Durante a digitação de um CPF (11 dígitos):
 *   - "1"         → "1"
 *   - "123"       → "123"
 *   - "1234"      → "123.4"
 *   - "12345678"  → "123.456.78"
 *   - "12345678901"→ "123.456.789-01"
 *
 *   Durante a digitação de um CNPJ (14 dígitos):
 *   - "12345678" → "12.345.678"
 *   - "12345678000195" → "12.345.678/0001-95"
 *
 * @funcionalidades
 *   - mascaraDocumento(valor):     aplica CPF ou CNPJ automaticamente
 *   - mascaraCPF(valor):           aplica somente máscara de CPF
 *   - mascaraCNPJ(valor):          aplica somente máscara de CNPJ
 *   - removerMascara(valor):       retorna apenas os dígitos
 *
 * @tratamentos_especiais
 *   - Caracteres não numéricos durante digitação → ignorados automaticamente
 *   - Backspace / deleção → máscara se ajusta ao comprimento atual
 *   - Valor vazio → retorna string vazia
 *   - Comprimento maior que 14 dígitos → trunca ao máximo permitido
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
