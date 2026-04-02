/**
 * @arquivo    format/document.ts
 * @modulo     Utilitários / Formatação
 * @descricao  Funções para formatação visual de documentos brasileiros para
 *             exibição na interface. Recebe strings com apenas dígitos e
 *             insere os pontos, traços e barras conforme o padrão oficial
 *             de cada documento. Não realiza validação de dígitos verificadores
 *             (ver utils/validation/document.ts para isso).
 *
 * @exemplos_de_uso
 *   - formatarCPF("12345678901")        → "123.456.789-01"
 *   - formatarCNPJ("12345678000195")    → "12.345.678/0001-95"
 *   - formatarRG("123456789")          → "12.345.678-9"
 *   - formatarPIS("12345678901")       → "123.45678.90-1"
 *   - formatarCNH("12345678901")       → "123456789  01" (formato padrão DETRAN)
 *   - removerMascaraDocumento("123.456.789-01") → "12345678901"
 *   - detectarTipoDocumento("12345678901")       → "CPF"
 *   - detectarTipoDocumento("12345678000195")    → "CNPJ"
 *
 * @tratamentos_especiais
 *   - String com caracteres não numéricos → remove antes de formatar
 *   - Comprimento incorreto → retorna a string original sem formatação
 *   - Valor nulo ou undefined → retorna string vazia
 *   - Documento já formatado → reformata sem duplicar máscaras
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
