/**
 * @arquivo    helpers/clipboard.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Fornece funções para interação com a API de Clipboard do navegador,
 *             permitindo copiar texto, HTML e imagens para a área de transferência
 *             do sistema com feedback de sucesso/erro. Suporta tanto a API moderna
 *             (navigator.clipboard) quanto o fallback via execCommand para
 *             navegadores mais antigos.
 *
 * @funcionalidades
 *   - copiarTexto(texto):     copia string simples para o clipboard
 *   - copiarHTML(html):       copia conteúdo HTML preservando formatação
 *   - lerClipboard():         lê o conteúdo atual do clipboard (requer permissão)
 *   - verificarPermissao():   verifica se a permissão de clipboard está concedida
 *
 * @exemplos_de_uso
 *   - await copiarTexto("Texto copiado!") → true (sucesso) | false (falha)
 *   - await copiarTexto(linkCompartilhamento)
 *     .then(() => mostrarToast("Link copiado!"))
 *     .catch(() => mostrarErro("Falha ao copiar"))
 *
 * @tratamentos_especiais
 *   - navigator.clipboard não disponível (HTTP, iframe) → fallback execCommand
 *   - Permissão negada pelo usuário → retorna false com mensagem descritiva
 *   - Texto vazio ou undefined → retorna false sem tentar copiar
 *   - Clipboard com conteúdo anterior → sobrescreve sem aviso
 *   - Ambiente SSR → retorna false imediatamente
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
