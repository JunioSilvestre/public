/**
 * @arquivo    helpers/retry.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Implementa a estratégia de nova tentativa automática (retry)
 *             com backoff exponencial para operações assíncronas que podem
 *             falhar transitoriamente (chamadas de API, conexões de banco,
 *             uploads de arquivo). Aumenta progressivamente o intervalo
 *             entre tentativas para não sobrecarregar o servidor.
 *
 * @estrategia_backoff_exponencial
 *   Tentativa 1: imediata
 *   Tentativa 2: aguarda 1s
 *   Tentativa 3: aguarda 2s
 *   Tentativa 4: aguarda 4s
 *   Tentativa N: aguarda min(2^(N-1) * baseMs, maxMs)
 *   + jitter aleatório para evitar thundering herd
 *
 * @funcionalidades
 *   - retry(fn, opcoes):          executa função assíncrona com retentativas
 *   - retryFetch(url, opcoes):    wrapper especializado para fetch com retry
 *
 * @opcoes_configuracao
 *   - tentativas:    número máximo de tentativas (padrão: 3)
 *   - baseMs:        intervalo base em ms (padrão: 1000)
 *   - maxMs:         intervalo máximo em ms (padrão: 30000)
 *   - jitter:        adicionar aleatoriedade (padrão: true)
 *   - deveRetentar:  função (erro) => boolean que decide se retenta
 *
 * @exemplos_de_uso
 *   - await retry(() => buscarDados(), { tentativas: 3 })
 *   - await retry(() => uploadArquivo(file), {
 *       tentativas: 5,
 *       deveRetentar: (err) => err.status !== 400 // não retenta erros de validação
 *     })
 *
 * @tratamentos_especiais
 *   - Erro 4xx (cliente) → não retenta por padrão (configurável)
 *   - Erro de rede → retenta com backoff
 *   - AbortError (timeout do usuário) → não retenta
 *   - Todas as tentativas esgotadas → relança o último erro recebido
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
