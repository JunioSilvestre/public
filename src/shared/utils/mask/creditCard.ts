/**
 * @arquivo    mask/creditCard.ts
 * @modulo     Utilitários / Máscaras de Input
 * @descricao  Aplica máscara progressiva em tempo real para campos de número
 *             de cartão de crédito e débito, detectando automaticamente a
 *             bandeira do cartão (Visa, Mastercard, Amex, Elo, Hipercard)
 *             a partir dos primeiros dígitos e aplicando o formato correto
 *             de cada bandeira.
 *
 * @formatos_por_bandeira
 *   - Visa/Mastercard/Elo: "XXXX XXXX XXXX XXXX" (16 dígitos, grupos de 4)
 *   - American Express:    "XXXX XXXXXX XXXXX"    (15 dígitos, grupos 4-6-5)
 *   - Diners Club:         "XXXX XXXXXX XXXX"     (14 dígitos)
 *   - Hipercard:           "XXXX XXXX XXXX XXXX"  (16-19 dígitos)
 *
 * @deteccao_de_bandeira
 *   - Visa:       começa com "4"
 *   - Mastercard: começa com "51"-"55" ou "2221"-"2720"
 *   - Amex:       começa com "34" ou "37"
 *   - Elo:        começa com intervalos específicos (431274, 438935, ...)
 *   - Hipercard:  começa com "6062"
 *   - Desconhecido: formata em grupos de 4
 *
 * @funcionalidades
 *   - mascaraCartao(valor):          aplica máscara detectando bandeira
 *   - detectarBandeira(numero):      retorna nome da bandeira ou "desconhecido"
 *   - mascaraValidadeCartao(valor):  "MM/AA" progressivo
 *   - mascaraCVV(valor, bandeira):   3 dígitos (Amex: 4 dígitos)
 *   - removerMascara(valor):         retorna apenas os dígitos
 *
 * @tratamentos_especiais
 *   - Colar número com espaços/hífens → remove e reaplica máscara correta
 *   - Comprimento além do máximo da bandeira → trunca
 *   - Validade cartão: mês 13+ → inválido durante digitação
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
