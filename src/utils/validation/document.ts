/**
 * @arquivo    validation/document.ts
 * @modulo     Utilitários / Validação
 * @descricao  Valida documentos brasileiros verificando os dígitos verificadores
 *             conforme os algoritmos oficiais. Diferente da formatação (format/document.ts)
 *             e da máscara (mask/document.ts), este arquivo garante que o documento
 *             informado é matematicamente válido, não apenas bem formatado.
 *
 * @funcionalidades
 *   - validarCPF(cpf):   verifica os 2 dígitos verificadores do CPF (módulo 11)
 *   - validarCNPJ(cnpj): verifica os 2 dígitos verificadores do CNPJ (módulo 11)
 *   - validarRG(rg):     valida RG conforme regras do estado (quando aplicável)
 *   - detectarDocumento(valor): retorna "CPF" | "CNPJ" | "inválido"
 *
 * @algoritmo_cpf
 *   1. Remove pontos e traços
 *   2. Rejeita sequências iguais (000.000.000-00 a 999.999.999-99)
 *   3. Calcula 1º dígito verificador: soma ponderada dos 9 primeiros × (10..2), mod 11
 *   4. Calcula 2º dígito verificador: soma ponderada dos 10 primeiros × (11..2), mod 11
 *   5. Compara dígitos calculados com os informados
 *
 * @exemplos_de_uso
 *   - validarCPF("529.982.247-25")  → true  (CPF válido)
 *   - validarCPF("111.111.111-11")  → false (sequência repetida)
 *   - validarCPF("529.982.247-26")  → false (dígito verificador errado)
 *   - validarCNPJ("11.222.333/0001-81") → true
 *   - validarCNPJ("00.000.000/0000-00") → false
 *
 * @tratamentos_especiais
 *   - Documento já formatado (com pontos e traços) → remove máscara antes de validar
 *   - Valor nulo ou undefined → retorna false
 *   - String vazia → retorna false
 *   - Comprimento incorreto → retorna false imediatamente (sem calcular)
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
