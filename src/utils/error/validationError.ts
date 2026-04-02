/**
 * @arquivo    error/validationError.ts
 * @modulo     Utilitários / Tratamento de Erros
 * @descricao  Define a classe customizada ValidationError e tipos relacionados
 *             para representar erros de validação de formulários e dados de
 *             entrada. Padroniza a estrutura de erros de validação retornados
 *             tanto pelo frontend (validação local) quanto pelo backend (422),
 *             facilitando a exibição de mensagens de erro por campo.
 *
 * @estrutura_do_erro
 *   ValidationError {
 *     message: "Dados inválidos",
 *     campos: {
 *       email:  ["E-mail obrigatório", "Formato inválido"],
 *       senha:  ["Mínimo 8 caracteres"],
 *       cpf:    ["CPF inválido"]
 *     }
 *   }
 *
 * @funcionalidades
 *   - ValidationError(campos):       instancia com mapa de erros por campo
 *   - obterErroCampo(campo):         retorna array de mensagens do campo
 *   - temErroCampo(campo):           retorna true se o campo tem erro
 *   - primeiroErroCampo(campo):     retorna somente o 1º erro (para exibição)
 *   - deHttpError(httpError):       cria ValidationError a partir de um HttpError 422
 *   - deZod(zodError):              cria ValidationError a partir de erro Zod
 *
 * @integracoes
 *   - React Hook Form: converte para formato { [campo]: { message: string } }
 *   - Zod: interpola erros de ZodError para ValidationError
 *   - API 422: mapeia payload do backend para campos do formulário
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
