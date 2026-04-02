/**
 * @arquivo    helpers/storage.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Abstração segura sobre localStorage e sessionStorage para
 *             persistência de dados no navegador. Serializa e desserializa
 *             objetos automaticamente (JSON.parse/stringify), trata erros
 *             de armazenamento cheio (QuotaExceededError), prefixação de
 *             chaves por ambiente e expiração automática de itens.
 *
 * @funcionalidades
 *   - salvar(chave, valor, opcoes):     armazena valor serializado
 *   - obter<T>(chave, padrao?):         recupera e desserializa valor
 *   - remover(chave):                  remove item específico
 *   - limpar(prefixo?):               remove todos os itens (ou só os prefixados)
 *   - existe(chave):                   verifica se chave existe e não expirou
 *   - obterOuDefinir(chave, fn):       retorna existente ou executa fn e salva
 *
 * @opcoes_de_armazenamento
 *   - tipo: "local" (permanente) | "session" (fecha aba = apaga)
 *   - expiracao: duração em milissegundos após a qual o item é considerado inválido
 *   - prefixo: namespace para evitar colisão com outras libs ("app_")
 *
 * @exemplos_de_uso
 *   - salvar("usuario", { id: 1, nome: "João" }, { expiracao: 3600000 })
 *   - obter<Usuario>("usuario")           → { id: 1, nome: "João" } ou null
 *   - obter<string>("tema", "escuro")     → "escuro" (padrão se não existir)
 *   - existe("token_acesso")              → true | false
 *   - salvar("prefs", dados, { tipo: "session" }) → salvo só na sessão atual
 *
 * @tratamentos_especiais
 *   - JSON.parse falha (dado corrompido) → retorna null + limpa item inválido
 *   - QuotaExceededError (storage cheio) → loga erro, não lança exceção
 *   - localStorage indisponível (SSR, modo privado restrito) → fallback in-memory
 *   - Item expirado → removido automaticamente ao ser lido
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
