/**
 * @arquivo    helpers/cookie.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Abstração para leitura, escrita e remoção de cookies HTTP no
 *             navegador com suporte a opções de segurança (HttpOnly via backend,
 *             SameSite, Secure, Path, Domain e expiração). Centraliza o
 *             gerenciamento de cookies de autenticação, preferências e
 *             rastreamento de sessão, evitando manipulação direta de
 *             document.cookie ao longo da base de código.
 *
 * @funcionalidades
 *   - definirCookie(nome, valor, opcoes): cria ou atualiza um cookie
 *   - obterCookie(nome):                retorna o valor do cookie ou null
 *   - removerCookie(nome, opcoes):      expira o cookie imediatamente
 *   - existeCookie(nome):              retorna true se o cookie existe
 *   - listarCookies():                returns Record<string, string> de todos
 *
 * @opcoes_seguranca
 *   - expires:  Date ou dias até expirar (padrão: sessão)
 *   - path:     "/" (padrão) — escopo do cookie
 *   - domain:   domínio onde o cookie é válido
 *   - secure:   true = somente HTTPS
 *   - sameSite: "Strict" | "Lax" | "None" (padrão: "Lax")
 *
 * @exemplos_de_uso
 *   - definirCookie("tema", "escuro", { expires: 365, sameSite: "Strict" })
 *   - obterCookie("tema")           → "escuro"
 *   - removerCookie("session_id")
 *   - existeCookie("aceite_lgpd")   → true | false
 *
 * @tratamentos_especiais
 *   - Valor com caracteres especiais → encodado com encodeURIComponent
 *   - Cookie não encontrado → retorna null (não lança exceção)
 *   - Ambiente SSR (sem window/document) → retorna null sem erro
 *   - Cookies de terceiros bloqueados → detecta e retorna fallback
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
