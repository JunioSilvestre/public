/**
 * @arquivo    validation/phone.ts
 * @modulo     Utilitários / Validação
 * @descricao  Valida números de telefone brasileiros verificando comprimento,
 *             DDD válido e formato conforme as regras da ANATEL. Suporta
 *             telefones fixos, celulares (com prefixo 9), linhas 0800 e
 *             números com ou sem máscara aplicada.
 *
 * @funcionalidades
 *   - validarTelefone(tel):          validação geral (fixo ou celular)
 *   - validarTelefoneFixo(tel):      valida somente telefone fixo (8 dígitos)
 *   - validarCelular(tel):           valida somente celular (9 dígitos, começa com 9)
 *   - validarDDD(ddd):               valida se DDD existe no Brasil
 *   - validar0800(tel):              valida linhas gratuitas 0800
 *
 * @ddds_validos_brasil
 *   11-19, 21, 22, 24, 27, 28, 31-35, 37, 38, 41-49, 51, 53-55, 61, 62,
 *   63, 64, 65, 66, 67, 68, 69, 71, 73-75, 77, 79, 81-89, 91-99
 *
 * @exemplos_de_uso
 *   - validarTelefone("(11) 98765-4321")  → true  (celular com DDD)
 *   - validarTelefone("11987654321")      → true  (sem formatação)
 *   - validarTelefone("(11) 3333-4444")   → true  (fixo com DDD)
 *   - validarTelefone("(00) 98765-4321")  → false (DDD 00 inválido)
 *   - validarCelular("(11) 8765-4321")    → false (celular sem prefixo 9)
 *   - validarDDD("11")                    → true
 *   - validarDDD("10")                    → false
 *
 * @tratamentos_especiais
 *   - Telefone com máscara → remove caracteres não numéricos antes de validar
 *   - Telefone sem DDD (apenas 8 ou 9 dígitos) → validado sem verificar DDD
 *   - Valor nulo ou undefined → retorna false
 *   - String vazia → retorna false
 *   - Telefones internacionais (+55, 0055) → strip do código país antes de validar
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
