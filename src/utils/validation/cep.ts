/**
 * @arquivo    validation/cep.ts
 * @modulo     Utilitários / Validação
 * @descricao  Valida e consulta CEPs (Código de Endereçamento Postal) brasileiros.
 *             Além da validação de formato e comprimento, fornece integração
 *             com a API pública ViaCEP para busca de endereço completo a partir
 *             do CEP informado pelo usuário.
 *
 * @funcionalidades
 *   - validarFormatoCEP(cep):     verifica se tem 8 dígitos numéricos
 *   - buscarEnderecoPorCEP(cep):  consulta ViaCEP e retorna objeto de endereço
 *   - ehCEPValido(cep):           valida formato sem consultar API
 *
 * @estrutura_retorno_busca
 *   {
 *     cep: "01310-100",
 *     logradouro: "Avenida Paulista",
 *     complemento: "até 610",
 *     bairro: "Bela Vista",
 *     cidade: "São Paulo",
 *     estado: "SP",
 *     ibge: "3550308",
 *     gia: "1004"
 *   }
 *
 * @exemplos_de_uso
 *   - validarFormatoCEP("01310-100")   → true
 *   - validarFormatoCEP("00000000")    → false (CEP inexistente, mas formato válido)
 *   - validarFormatoCEP("1234")        → false
 *   - buscarEnderecoPorCEP("01310100") → Promise<EnderecoDTO | null>
 *
 * @tratamentos_especiais
 *   - CEP com hífen ou sem → normaliza antes de validar
 *   - CEP inexistente (ViaCEP retorna erro) → retorna null sem lançar exceção
 *   - Falha de rede → retorna null com log de aviso
 *   - Timeout de requisição → configurável, padrão 5000ms
 *   - CEP de teste (00000-000) → retorna null imediatamente sem consultar API
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
