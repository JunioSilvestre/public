/**
 * @arquivo    sanitize/html.ts
 * @modulo     Utilitários / Sanitização
 * @descricao  Responsável pela sanitização de strings HTML para prevenir
 *             ataques de Cross-Site Scripting (XSS). Remove ou escapa tags
 *             e atributos HTML potencialmente perigosos antes de renderizar
 *             conteúdo dinâmico recebido de usuários ou APIs externas.
 *             Imprescindível quando se usa dangerouslySetInnerHTML no React
 *             ou qualquer renderização de HTML bruto.
 *
 * @exemplos_de_uso
 *   - sanitizarHTML("<b>olá</b>")                    → "<b>olá</b>" (permitido)
 *   - sanitizarHTML("<script>alert(1)</script>")      → "" (removido)
 *   - sanitizarHTML('<a href="javascript:void">x</a>')→ "<a>x</a>" (href removido)
 *   - sanitizarHTML('<img src=x onerror=alert(1)>')   → "<img src=x>" (onerror removido)
 *   - escaparHTML("<b>texto</b>")                     → "&lt;b&gt;texto&lt;/b&gt;"
 *   - desescaparHTML("&lt;b&gt;texto&lt;/b&gt;")      → "<b>texto</b>"
 *   - removerTagsHTML("<p>conteúdo <br> texto</p>")   → "conteúdo  texto"
 *   - extrairTextoHTML("<p style='color:red'>Olá</p>")→ "Olá"
 *
 * @tags_permitidas_padrao
 *   b, i, em, strong, u, br, p, ul, ol, li, h1-h6, a (sem href perigoso),
 *   blockquote, code, pre
 *
 * @atributos_bloqueados
 *   on* (onclick, onerror, onload...), style, javascript:, data:
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
