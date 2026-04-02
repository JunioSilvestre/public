/**
 * @arquivo    error/httpError.ts
 * @modulo     Utilitários / Tratamento de Erros
 * @descricao  Define a classe customizada HttpError que estende o Error nativo
 *             do JavaScript para encapsular erros de requisições HTTP com
 *             código de status, corpo da resposta e metadados adicionais.
 *             Permite tratamento granular de diferentes tipos de falha de API
 *             (401 Não Autorizado, 403 Proibido, 404 Não Encontrado, 422 Validação,
 *             500 Erro Interno) em um único mecanismo padronizado.
 *
 * @propriedades_da_classe
 *   - status:     código HTTP (ex: 404, 500)
 *   - message:    mensagem legível do erro
 *   - data:       corpo da resposta (payload de erro da API)
 *   - url:        endpoint que gerou o erro
 *   - timestamp:  momento em que o erro ocorreu
 *
 * @exemplos_de_uso
 *   throw new HttpError(404, "Recurso não encontrado", { id: 123 });
 *   throw new HttpError(401, "Sessão expirada");
 *   throw new HttpError(422, "Dados inválidos", camposComErro);
 *
 *   Tratamento:
 *   try {
 *     await buscarUsuario(id);
 *   } catch (erro) {
 *     if (erro instanceof HttpError) {
 *       if (erro.status === 401) redirecionarParaLogin();
 *       if (erro.status === 404) mostrarPaginaNaoEncontrada();
 *     }
 *   }
 *
 * @codigos_http_tratados
 *   - 400: Requisição malformada (dados inválidos no cliente)
 *   - 401: Não autenticado (sem token ou token inválido)
 *   - 403: Não autorizado (sem permissão para o recurso)
 *   - 404: Recurso não encontrado
 *   - 409: Conflito (ex: e-mail já cadastrado)
 *   - 422: Entidade não processável (falha de validação)
 *   - 429: Muitas requisições (rate limit atingido)
 *   - 500: Erro interno do servidor
 *   - 503: Serviço indisponível
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
