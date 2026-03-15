/**
 * @fileoverview Ponto de entrada para o módulo de segurança XSS.
 *
 * @description
 * Exporta todas as funções públicas dos três módulos de proteção contra XSS.
 * Use sempre este arquivo como ponto de importação — nunca importe diretamente
 * dos módulos internos, pois a API pública pode ser reorganizada sem aviso.
 *
 * ── Módulos ────────────────────────────────────────────────────────────────
 *
 *  html-sanitizer   — Sanitização de HTML com DOMPurify + defesa em profundidade.
 *                     Use quando precisar renderizar HTML de fontes externas.
 *
 *  xss-protection   — Escape contextual para 9 destinos de inserção diferentes.
 *                     Use quando precisar inserir dados em HTML, atributos,
 *                     URLs, JavaScript, CSS, JSON, SVG ou template literals.
 *
 *  dom-xss-guard    — Wrappers seguros para APIs do DOM (innerHTML, setAttribute,
 *                     style, createElement, window.open, location).
 *                     Use como substituto direto das APIs nativas do browser.
 *
 * ── Guia de escolha rápida ─────────────────────────────────────────────────
 *
 *  Preciso renderizar HTML externo/do usuário        → sanitizeHtml()
 *  Preciso inserir texto em element.innerHTML        → safeSetInnerHTML()
 *  Preciso exibir texto puro (sem HTML)              → safeSetTextContent() ou escapeHtml()
 *  Preciso definir href/src/action                   → safeSetURLAttribute()
 *  Preciso definir um atributo qualquer              → safeSetAttribute()
 *  Preciso definir style inline                      → safeSetStyle() / safeSetStyleProperty()
 *  Preciso criar um elemento                         → safeCreateElement()
 *  Preciso abrir uma nova aba                        → safeOpenWindow()
 *  Preciso redirecionar a página                     → safeNavigate()
 *  Preciso escapar para template SSR (HTML)          → escapeHtml() / safeHtml``
 *  Preciso escapar para atributo HTML                → escapeHtmlAttr() / safeAttr``
 *  Preciso escapar uma URL                           → escapeUrl()
 *  Preciso escapar para bloco <script>               → escapeJs()
 *  Preciso escapar para CSS inline                   → escapeCss() / escapeCssUrl()
 *  Preciso serializar JSON seguro em <script>        → escapeJsonForHtml()
 *  Preciso escapar atributo SVG                      → escapeSvgAttr()
 *  Contexto dinâmico (runtime)                       → escapeForContext()
 *  Auditoria de um DOM existente                     → auditDOMForXSS()
 *  Diagnóstico de payload em string                  → detectXSSSignals()
 *  Verificação de ambiente no startup                → runSanityCheck()
 */

// ─────────────────────────────────────────────────────────────────────────────
// html-sanitizer
// ─────────────────────────────────────────────────────────────────────────────

export {
  /** Sanitiza HTML com DOMPurify + múltiplas camadas de defesa. Perfil padrão: 'content'. */
  sanitizeHtml,
  /** Variante que retorna DocumentFragment — elimina vetor de mXSS na re-serialização. */
  sanitizeHtmlToFragment,
  /** Remove todo markup e retorna texto puro com entidades HTML. */
  sanitizeTextOnly,
  /** Retorna versão e suporte do DOMPurify — útil para CI/CD. */
  getDOMPurifyInfo,
  /** Verifica a configuração do ambiente e retorna lista de avisos. */
  runSanityCheck,
} from './html-sanitizer';

export type {
  /** Perfis de sanitização: 'strict' | 'content' | 'richText' | 'inlineOnly' | 'svgSafe' */
  SanitizeProfile,
} from './html-sanitizer';

// ─────────────────────────────────────────────────────────────────────────────
// xss-protection
// ─────────────────────────────────────────────────────────────────────────────

export {
  /** Escapa para conteúdo de elemento HTML (innerHTML SSR / templates). */
  escapeHtml,
  /** @alias escapeHtml — compatibilidade com código legado. */
  escapeText,
  /** Escapa para valor de atributo HTML (title, alt, class, data-*). */
  escapeHtmlAttr,
  /** Valida e codifica URL para href, src, action, etc. Bloqueia protocolos perigosos. */
  escapeUrl,
  /** Escapa para string dentro de bloco <script> ou event handler inline. */
  escapeJs,
  /** Escapa para interpolação em template literal JS (`Hello ${name}`). */
  escapeJsTemplate,
  /** Escapa para valor de propriedade CSS inline. */
  escapeCss,
  /** Escapa e valida URL para uso dentro de url() em CSS. */
  escapeCssUrl,
  /** Serializa dados para JSON seguro embutido em <script type="application/json">. */
  escapeJsonForHtml,
  /** Escapa valor de atributo SVG, com validação extra para atributos de URL. */
  escapeSvgAttr,
  /** Roteador contextual — aplica o escape correto para cada destino. */
  escapeForContext,
  /** Tagged template literal: escapa automaticamente todos os valores interpolados como HTML. */
  safeHtml,
  /** Tagged template literal: escapa automaticamente todos os valores interpolados como atributo. */
  safeAttr,
  /** Detecta sinais de payload XSS em uma string — para logging e auditoria. */
  detectXSSSignals,
  /** Roda vetores de teste conhecidos contra todas as funções de escape. Use em CI. */
  runEscapeTests,
} from './xss-protection';

export type {
  /** Contextos de inserção: 'html' | 'htmlAttr' | 'url' | 'js' | 'css' | 'jsonInHtml' | ... */
  EscapeContext,
} from './xss-protection';

// ─────────────────────────────────────────────────────────────────────────────
// dom-xss-guard
// ─────────────────────────────────────────────────────────────────────────────

export {
  /** Substituto seguro de element.innerHTML = html. Sanitiza antes de inserir. */
  safeSetInnerHTML,
  /** Substituto seguro de element.insertAdjacentHTML(). */
  safeInsertAdjacentHTML,
  /** Define textContent de forma explícita e segura (não interpreta HTML). */
  safeSetTextContent,
  /** Valida e define atributos de URL (href, src, action, etc.). Bloqueia protocolos perigosos. */
  safeSetURLAttribute,
  /** Define qualquer atributo de forma segura — bloqueia event handlers e redireciona URLs/style. */
  safeSetAttribute,
  /** Define o atributo style inspecionando padrões CSS perigosos. */
  safeSetStyle,
  /** Define uma propriedade CSS individual de forma segura. */
  safeSetStyleProperty,
  /** Cria elemento DOM bloqueando tags intrinsecamente perigosas (script, iframe, etc.). */
  safeCreateElement,
  /** Abre URL em nova aba com noopener/noreferrer obrigatório. */
  safeOpenWindow,
  /** Redireciona a página validando a URL antes de tocar em window.location. */
  safeNavigate,
  /** Sempre lança erro — document.write é proibido sem exceção. */
  safeDocumentWrite,
  /** Audita um elemento e seus filhos em busca de atributos e URLs perigosos já no DOM. */
  auditDOMForXSS,
} from './dom-xss-guard';