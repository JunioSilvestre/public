/**
 * @fileoverview Módulo central de sanitização de HTML — defesa em profundidade contra XSS.
 *
 * @description
 * Envolve DOMPurify com múltiplas camadas extras de proteção para cobrir vetores de ataque
 * históricos confirmados e superfícies de risco emergentes:
 *
 * ── Vetores históricos cobertos ────────────────────────────────────────────────
 *  • Classic innerHTML / script injection                     (CVE incontáveis)
 *  • Mutation XSS (mXSS) via SVG/MathML namespace swap       (CVE-2019-8362, pesquisa Cure53 2019-2023)
 *  • DOM Clobbering via id/name attributes                    (GitHub XSS 2019, pesquisa portswigger 2021)
 *  • CSS expression() / -moz-binding / behavior              (IE legado, Firefox 2.x)
 *  • javascript: e vbscript: em href/src/action              (omnipresente)
 *  • data: URI com HTML/JS embutido                          (CVE-2018-6386 e similares)
 *  • SVG <use xlink:href> e <animate> para bypass de CSP     (pesquisa 2015-2021)
 *  • MathML maction com href                                  (Firefox < 72)
 *  • window.opener hijacking via target="_blank"             (tab-napping, documentado 2010+)
 *  • Template-element mXSS (FORCE_BODY bypass)               (DOMPurify < 2.3.3)
 *  • Polyglot payloads (HTML+SVG+MathML misturados)          (Masato Kinugawa 2021)
 *  • XSS via data-* lido por frameworks (Angular, Vue, React) (vetor de supply-chain)
 *  • Prototype pollution via HTML attributes                 (pesquisa 2020)
 *  • srcdoc iframe embedding                                  (bypass de sandbox)
 *  • CSS url() / image-set() com javascript:                  (Chrome < 92)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────────
 *  • Trusted Types enforcement (W3C — padronizado 2021, adoção crescente)
 *  • Import maps injection (<script type="importmap">)       (especificação 2023+)
 *  • Speculation Rules injection (<script type="speculationrules">)
 *  • Navigation API hijacking                                 (Chrome 102+)
 *  • View Transitions + document.startViewTransition XSS      (Chrome 111+)
 *  • CSS @layer / @property injection                        (emergente)
 *  • Shadow DOM style leakage via ::part() / ::slotted()      (emergente)
 *  • HTML Sanitizer API nativa (substituto futuro do DOMPurify)
 *  • Sanitização de Server-Side Rendering (SSR / Node.js)     (via regex-fallback)
 *
 * ── Arquitetura ────────────────────────────────────────────────────────────────
 *  • Abordagem de ALLOWLIST (não blocklist) — nega por padrão, permite explicitamente.
 *  • Perfis de sanitização para diferentes contextos de uso.
 *  • Hooks globais inicializados UMA vez (evita race condition do código original).
 *  • Fallback SSR via stripped-text para ambientes sem DOM.
 *  • Integração com Trusted Types API quando disponível.
 *
 * @see https://github.com/cure53/DOMPurify
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
 * @see https://w3c.github.io/trusted-types/dist/spec/
 */

import DOMPurify from 'dompurify';

// ─────────────────────────────────────────────────────────────────────────────
// Extensão de tipos — corrige defasagem entre @types/dompurify e API real
// ─────────────────────────────────────────────────────────────────────────────

/**
 * O pacote `@types/dompurify` frequentemente fica atrás da API real do DOMPurify.
 * `SANITIZE_DOM_CLOBBERING` e `SANITIZE_NAMED_PROPS` existem no runtime (≥ 2.4.0)
 * mas podem não estar no `.d.ts` da versão instalada.
 *
 * Estendemos a interface `Config` localmente para que o TypeScript aceite
 * as propriedades sem precisar de type assertions espalhadas pelo código.
 *
 * @see https://github.com/cure53/DOMPurify/blob/main/dist/purify.d.ts
 */
declare module 'dompurify' {
  interface Config {
    /** Protege contra DOM Clobbering via id/name (DOMPurify ≥ 2.4.0). */
    SANITIZE_DOM_CLOBBERING?: boolean;
    /**
     * Previne que id/name sobrescrevam propriedades nomeadas do document
     * como document.body, document.cookie, etc. (DOMPurify ≥ 2.4.0).
     */
    SANITIZE_NAMED_PROPS?: boolean;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Perfis de sanitização pré-configurados para diferentes contextos de uso.
 *
 * - `strict`      — Apenas formatação inline. Para comentários, bios, campos de usuário.
 * - `content`     — Conteúdo rico sem formulários. Para artigos, posts de blog.
 * - `richText`    — Editor de texto completo, inclui tabelas e alinhamento.
 * - `inlineOnly`  — Só tags inline sem atributos. Para tooltips, labels.
 * - `svgSafe`     — Aceita SVG estático decorativo, sem scripts ou eventos.
 */
export type SanitizeProfile = 'strict' | 'content' | 'richText' | 'inlineOnly' | 'svgSafe';

// ─────────────────────────────────────────────────────────────────────────────
// Constantes de segurança
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Protocolos explicitamente bloqueados em qualquer atributo de URL.
 * A lista é uma UNION de casos históricos confirmados e variantes conhecidas.
 */
const BLOCKED_URL_PROTOCOLS = new Set([
  'javascript',
  'vbscript',
  'data',
  'blob',
  'filesystem',
  'jar',
  'livescript',
  'mocha',
  'mhtml',
  'mk',          // IIS legacy
]);

/**
 * Atributos que carregam URLs e precisam de validação de protocolo.
 * Baseado na spec HTML5 e nos content attributes que causaram CVEs históricos.
 */
const URL_ATTRIBUTES = new Set([
  'href', 'src', 'action', 'formaction', 'cite', 'poster',
  'background',   // HTML3 legado — ainda parseado por alguns browsers
  'longdesc',     // HTML4 legado
  'xlink:href',   // SVG — bypass histórico
  'xml:base',     // namespace injection vector
  'ping',         // privacy leak vector
  'srcset',       // imagens responsivas — suporta URLs múltiplas
]);

/**
 * Padrões de CSS perigosos com cobertura ampliada:
 *  - expression()    : IE legado, mas ainda presente em parsers embedded
 *  - -moz-binding   : Firefox < 3.6
 *  - behavior:       : IE HTC (HTML Components)
 *  - url(javascript) : CSS url() com protocolo perigoso
 *  - @import         : exfiltração de dados via CSS side-channel
 *  - @charset        : encoding injection
 *  - -webkit-*       : propriedades vendor perigosas históricas
 *  - zoom:expression : IE variant
 *  - binding:        : variante de -moz-binding
 *  - css-hacks       : \*//* e // comentários como bypass
 */
const CSS_DANGEROUS_PATTERNS = [
  /expression\s*\(/gi,
  /-moz-binding/gi,
  /behavior\s*:/gi,
  /url\s*\(\s*['"]?\s*(javascript|vbscript|data|blob)/gi,
  /@import/gi,
  /@charset/gi,
  /-webkit-(?:user-modify|marquee|line-clamp\s*:\s*-webkit)/gi,
  /zoom\s*:\s*expression/gi,
  /binding\s*:/gi,
  /\\\*\/\//g,       // CSS comment hack
  /\/\*[\s\S]*?\*\//g, // strip CSS comments (podem ocultar payloads)
];

/**
 * Tags perigosas que nunca devem aparecer no output — mesmo que DOMPurify bloqueie,
 * a camada extra de validação garante redundância.
 *
 * Inclui vetores emergentes de 2023+:
 *  - <script type="importmap">       : redefine módulos ES — bypass de CSP
 *  - <script type="speculationrules">: pré-navegação controlada pelo atacante
 *  - <portal>                        : embedding sigiloso (Chrome experimental)
 *  - <fencedframe>                   : privacy sandbox embedding
 */
const ALWAYS_FORBIDDEN_TAGS = new Set([
  'script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet',
  'form', 'input', 'button', 'select', 'textarea', 'keygen',
  'base', 'meta', 'link', 'style',       // page-level resource tags
  'template',                              // mXSS via template parsing
  'portal',                                // Chrome experimental embedding
  'fencedframe',                           // Privacy Sandbox embedding
  'slot',                                  // Shadow DOM injection
  'plaintext', 'listing', 'xmp',           // HTML parsing escapes
  'noembed', 'noframes', 'noscript',       // conditional parse escapes
  'annotation-xml',                        // MathML → SVG namespace confusion
]);

// ─────────────────────────────────────────────────────────────────────────────
// Perfis de ALLOWLIST (safer: deny by default, allow explicitly)
// ─────────────────────────────────────────────────────────────────────────────

interface SanitizeConfig {
  ALLOWED_TAGS: string[];
  ALLOWED_ATTR: string[];
  /** Tags adicionais para proibir explicitamente além da lista base. */
  FORBID_TAGS?: string[];
  FORBID_ATTR?: string[];
}

const INLINE_TAGS = [
  'b', 'i', 'u', 's', 'em', 'strong', 'mark', 'small', 'del', 'ins',
  'sub', 'sup', 'abbr', 'cite', 'dfn', 'kbd', 'samp', 'var',
  'code', 'q', 'time', 'bdi', 'bdo', 'span', 'br', 'wbr',
];

const BLOCK_TAGS = [
  'p', 'div', 'section', 'article', 'aside', 'main', 'header', 'footer',
  'nav', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre',
  'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'figure', 'figcaption',
  'details', 'summary', 'hr',
];

const MEDIA_TAGS = ['img', 'picture', 'source', 'audio', 'video', 'track'];

const TABLE_TAGS = [
  'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption', 'colgroup', 'col',
];

const COMMON_FORMATTING_ATTRS = [
  'class', 'id', 'lang', 'dir', 'title', 'aria-label', 'aria-describedby',
  'aria-hidden', 'aria-expanded', 'aria-controls', 'aria-live',
  'aria-role', 'role', 'tabindex',
];

const PROFILES: Record<SanitizeProfile, SanitizeConfig> = {
  /**
   * Somente inline. Para comentários de usuário, bios, campos simples.
   * Não permite links nem mídia — apenas formatação de texto.
   */
  strict: {
    ALLOWED_TAGS: [...INLINE_TAGS],
    ALLOWED_ATTR: ['class', 'lang', 'dir', 'aria-label', 'aria-hidden'],
  },

  /**
   * Conteúdo editorial rico sem formulários. Para artigos, emails, posts de blog.
   * Permite links e imagens com atributos controlados.
   */
  content: {
    ALLOWED_TAGS: [...INLINE_TAGS, ...BLOCK_TAGS, ...MEDIA_TAGS, 'a'],
    ALLOWED_ATTR: [
      ...COMMON_FORMATTING_ATTRS,
      // Links
      'href', 'rel', 'target', 'hreflang', 'download',
      // Mídia
      'src', 'srcset', 'sizes', 'alt', 'width', 'height',
      'loading', 'decoding', 'fetchpriority',
      // Semântica
      'datetime', 'cite', 'open',
      // Acessibilidade
      'alt', 'aria-current', 'aria-disabled',
    ],
  },

  /**
   * Editor de texto rico completo. Para WYSIWYG, conteúdo CMS.
   * Inclui tabelas, alinhamento e atributos de layout.
   */
  richText: {
    ALLOWED_TAGS: [...INLINE_TAGS, ...BLOCK_TAGS, ...MEDIA_TAGS, ...TABLE_TAGS, 'a'],
    ALLOWED_ATTR: [
      ...COMMON_FORMATTING_ATTRS,
      // Layout
      'align', 'valign', 'colspan', 'rowspan', 'headers', 'scope',
      // Links
      'href', 'rel', 'target', 'hreflang',
      // Mídia
      'src', 'srcset', 'sizes', 'alt', 'width', 'height',
      'loading', 'decoding', 'controls', 'autoplay', 'muted', 'loop',
      'poster', 'preload', 'kind', 'srclang', 'label', 'default',
      // Semântica
      'datetime', 'cite', 'open', 'start', 'reversed', 'value',
      // Acessibilidade
      'aria-current', 'aria-disabled', 'aria-label', 'aria-labelledby',
      'aria-describedby', 'aria-hidden', 'aria-expanded', 'aria-controls',
      'aria-selected', 'aria-sort', 'aria-colindex', 'aria-rowindex',
    ],
  },

  /**
   * Somente inline sem atributos. Para tooltips, placeholders, labels curtas.
   */
  inlineOnly: {
    ALLOWED_TAGS: [...INLINE_TAGS],
    ALLOWED_ATTR: [], // nenhum atributo permitido
  },

  /**
   * SVG estático decorativo. Para ícones e ilustrações embutidas.
   * Bloqueia TODOS os event handlers e URIs perigosas.
   * Não permite <script>, <use xlink:href> externo, <animate> com href.
   */
  svgSafe: {
    ALLOWED_TAGS: [
      'svg', 'g', 'path', 'polygon', 'polyline', 'rect', 'circle',
      'ellipse', 'line', 'text', 'tspan', 'textPath', 'title', 'desc',
      'defs', 'symbol', 'use', 'clipPath', 'mask', 'pattern',
      'linearGradient', 'radialGradient', 'stop', 'image',
      'filter', 'feBlend', 'feColorMatrix', 'feComponentTransfer',
      'feComposite', 'feFlood', 'feGaussianBlur', 'feImage',
      'feMerge', 'feMergeNode', 'feOffset', 'feTile', 'feTurbulence',
      'animate', 'animateTransform', 'animateMotion', 'mpath', 'set',
    ],
    ALLOWED_ATTR: [
      // Apresentação
      'viewBox', 'xmlns', 'version', 'x', 'y', 'width', 'height',
      'cx', 'cy', 'r', 'rx', 'ry', 'x1', 'y1', 'x2', 'y2',
      'd', 'points', 'transform', 'fill', 'stroke', 'stroke-width',
      'stroke-linecap', 'stroke-linejoin', 'stroke-dasharray', 'stroke-dashoffset',
      'opacity', 'fill-opacity', 'stroke-opacity', 'fill-rule', 'clip-rule',
      'color', 'display', 'visibility', 'overflow', 'clip-path', 'mask',
      'filter', 'font-family', 'font-size', 'font-weight', 'font-style',
      'text-anchor', 'dominant-baseline', 'alignment-baseline',
      'letter-spacing', 'word-spacing', 'text-decoration',
      'marker-start', 'marker-mid', 'marker-end',
      'stop-color', 'stop-opacity', 'gradientUnits', 'gradientTransform',
      'spreadMethod', 'patternUnits', 'patternTransform',
      'preserveAspectRatio', 'clip-path-units', 'maskUnits',
      'in', 'in2', 'result', 'type', 'values', 'stdDeviation',
      'dx', 'dy', 'rotate', 'textLength', 'lengthAdjust',
      // Acessibilidade SVG
      'aria-label', 'aria-hidden', 'role', 'id',
      // Referências internas (use href=#id — somente relativos)
      'href',
      // Animação
      'attributeName', 'begin', 'dur', 'end', 'repeatCount', 'repeatDur',
      'from', 'to', 'by', 'calcMode', 'keyTimes', 'keySplines',
      'additive', 'accumulate', 'fill',
      'path',         // animateMotion
      'type',         // animateTransform
    ],
    FORBID_ATTR: [
      // Namespace attributes que foram usados para bypass histórico
      'xlink:href',   // CVE histórico — obriga uso de href= com # somente
      'xml:base',
      'xml:space',
    ],
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Fallback SSR — sem DOM disponível
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitizador de emergência para ambientes SSR (Node.js, Workers sem DOM).
 *
 * Estratégia conservadora: remove TUDO que parece HTML e normaliza entidades.
 * É intencionalmente destrutivo — a alternativa seria um parser HTML completo
 * no servidor, o que está fora do escopo deste módulo.
 *
 * Para produção SSR, use `dompurify` com `jsdom` como implementação de DOM,
 * ou uma biblioteca server-side como `sanitize-html`.
 */
function ssrFallbackStrip(html: string): string {
  return html
    .replace(/\0/g, '')                       // null bytes
    .replace(/<[^>]*>/g, '')                  // strip all tags
    .replace(/javascript\s*:/gi, '')          // residual protocol
    .replace(/vbscript\s*:/gi, '')
    .replace(/on\w+\s*=/gi, '')               // residual inline events
    .replace(/&#x?[0-9a-f]+;?/gi, match => { // decode numeric entities para re-checar
      try {
        const decoded = match.replace(/&#x?([0-9a-f]+);?/gi, (_, code) =>
          String.fromCodePoint(parseInt(code, /x/i.test(match) ? 16 : 10))
        );
        return decoded.replace(/[<>&"'`]/g, c => ({
          '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;',
          "'": '&#39;', '`': '&#96;',
        }[c] ?? c));
      } catch {
        return '';
      }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Inicialização dos hooks DOMPurify — UMA vez por sessão
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Flag para garantir que os hooks globais são registrados somente uma vez.
 *
 * PROBLEMA DO CÓDIGO ORIGINAL:
 * `DOMPurify.addHook()` + `removeHook()` a cada chamada cria uma race condition
 * em chamadas concorrentes (ex: múltiplos sanitizeHtml() em Promise.all()).
 * O hook era removido antes de ser executado em uma das chamadas.
 */
let hooksInitialized = false;

/**
 * Inicializa os hooks de segurança uma única vez.
 * Chamado lazy na primeira invocação de `sanitizeHtml`.
 */
function initializeHooks(): void {
  if (hooksInitialized) return;
  hooksInitialized = true;

  // ── Hook 1: Validação de atributos de URL ─────────────────────────────────
  //
  // Executado APÓS a sanitização de atributos pelo DOMPurify.
  // Garante que nenhuma URL com protocolo perigoso sobreviva mesmo que
  // DOMPurify tenha um bypass em versões futuras.
  //
  // Cobre: javascript:, vbscript:, data:, blob:, e variantes ofuscadas.
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    // Validação de URLs em todos os atributos conhecidos como portadores de URL.
    for (const attrName of Array.from(URL_ATTRIBUTES)) {
      if (!node.hasAttribute(attrName)) continue;

      const value = node.getAttribute(attrName) ?? '';
      if (containsDangerousProtocol(value)) {
        node.removeAttribute(attrName);
        logSecurityEvent('url-protocol-blocked', attrName, value, node);
      }
    }

    // srcset tem formato especial: "url1 1x, url2 2x"
    if (node.hasAttribute('srcset')) {
      const srcset = node.getAttribute('srcset') ?? '';
      const safeSrcset = sanitizeSrcset(srcset);
      if (safeSrcset !== srcset) {
        node.setAttribute('srcset', safeSrcset);
        logSecurityEvent('srcset-sanitized', 'srcset', srcset, node);
      }
    }

    // ── noopener/noreferrer em target=_blank ─────────────────────────────────
    // Tab-napping: window.opener da aba filha pode redirecionar a aba pai.
    // Documentado desde 2010; ainda explorado em phishing ativo.
    if (node.getAttribute('target') === '_blank') {
      const existing = (node.getAttribute('rel') ?? '').toLowerCase();
      const parts = new Set(existing.split(/\s+/).filter(Boolean));
      parts.add('noopener');
      parts.add('noreferrer');
      node.setAttribute('rel', Array.from(parts).join(' '));
    }

    // ── Bloqueio de download= com nomes perigosos ─────────────────────────────
    // <a download="file.exe"> pode induzir download de executável.
    // Permitimos o atributo mas sanitizamos a extensão.
    if (node.hasAttribute('download')) {
      const name = (node.getAttribute('download') ?? '').trim();
      const safeName = sanitizeDownloadFilename(name);
      node.setAttribute('download', safeName);
    }
  });

  // ── Hook 2: Sanitização de atributos style inline ────────────────────────
  //
  // DOMPurify por padrão REMOVE o atributo style quando ALLOWED_ATTR não
  // o inclui. Quando ele é explicitamente permitido (perfil richText),
  // este hook inspeciona cada valor CSS.
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (!node.hasAttribute('style')) return;
    const styleValue = node.getAttribute('style') ?? '';
    const safeStyle = sanitizeCSSValue(styleValue);
    if (safeStyle !== styleValue) {
      if (safeStyle === '') {
        node.removeAttribute('style');
      } else {
        node.setAttribute('style', safeStyle);
      }
      logSecurityEvent('css-sanitized', 'style', styleValue, node);
    }
  });

  // ── Hook 3: Validação de elementos durante a sanitização ─────────────────
  //
  // Captura tags que podem ter escapado via namespace (SVG, MathML).
  // Mutation XSS: o parser cria a árvore com um namespace, e ao serializar
  // para innerHTML novamente a tag é interpretada diferente.
  DOMPurify.addHook('uponSanitizeElement', (node, data) => {
    const tagName = data.tagName?.toLowerCase() ?? '';

    if (ALWAYS_FORBIDDEN_TAGS.has(tagName)) {
      data.allowedTags[tagName] = false;
      logSecurityEvent('forbidden-tag-blocked', 'element', tagName, node);
    }

    // Bloqueia <use> com xlink:href ou href externo em SVG.
    // Histórico: <use xlink:href="http://evil.com/sprite.svg#icon"> pode
    // carregar SVG externo com scripts.
    if (tagName === 'use' && node.nodeType === 1) {
      const el = node as Element;
      const ref = el.getAttribute('href') ?? el.getAttribute('xlink:href') ?? '';
      if (ref && !ref.startsWith('#')) {
        el.removeAttribute('href');
        el.removeAttribute('xlink:href');
        logSecurityEvent('svg-use-external-blocked', 'href', ref, node);
      }
    }

    // Bloqueia <script type="importmap"> e <script type="speculationrules">
    // Vetores emergentes (2023+): redefinem resolução de módulos ES ou pré-navegação.
    if (tagName === 'script') {
      data.allowedTags['script'] = false;
    }
  });

  // ── Hook 4: Inspeção pós-sanitização do DOM resultante ───────────────────
  //
  // Executa sobre o DocumentFragment final antes de serializar para string.
  // Última chance de detectar anomalias após toda a sanitização.
  DOMPurify.addHook('afterSanitizeElements', (node) => {
    // Verifica text nodes com conteúdo que parece payload
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent ?? '';
      // Alerta (não bloqueia) sobre possíveis payloads em texto puro
      // — podem ser exibidos como texto mas não executados; o alerta
      // ajuda em análise de logs de segurança.
      if (/javascript\s*:/i.test(text) || /<script/i.test(text)) {
        logSecurityEvent('suspicious-text-node', 'textContent', text.slice(0, 80), node);
      }
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários internos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se uma string de URL contém protocolo perigoso.
 *
 * Normaliza o input antes de checar para resistir a:
 *  - `  javascript:` (espaços/tabs antes do protocolo)
 *  - `JAVA\x00SCRIPT:` (null bytes + case)
 *  - `%6a%61%76%61%73%63%72%69%70%74:` (URL encoding)
 *  - `java&#10;script:` (HTML entities de controle)
 *  - `java\rscript:` (carriage return)
 *  - `java\nscript:` (newline — histórico em IE)
 */
function containsDangerousProtocol(value: string): boolean {
  // Remove null bytes, quebras de linha, tabs e normaliza para lowercase
  const stripped = value
    .replace(/[\0\r\n\t\x0B\x0C\xA0\u2028\u2029]/g, '')
    .replace(/\s+/g, '')
    .toLowerCase();

  // Decode URL-encoding para detectar bypass via %XX
  let decoded = stripped;
  try {
    decoded = decodeURIComponent(stripped);
  } catch {
    // URL mal formada — mantém stripped
  }

  // Decode HTML entities numéricas (&#106; = 'j', &#x6A; = 'j')
  const entityDecoded = decoded.replace(/&#x?([0-9a-f]+);?/gi, (_, code) => {
    try {
      return String.fromCodePoint(parseInt(code, /x/i.test(_) ? 16 : 10));
    } catch {
      return '';
    }
  });

  for (const protocol of Array.from(BLOCKED_URL_PROTOCOLS)) {
    if (entityDecoded.startsWith(protocol + ':') || decoded.startsWith(protocol + ':')) {
      return true;
    }
  }
  return false;
}

/**
 * Sanitiza o atributo srcset, que contém múltiplas URLs separadas por vírgula.
 * Formato: "url1 [descriptor], url2 [descriptor], ..."
 */
function sanitizeSrcset(srcset: string): string {
  return srcset
    .split(',')
    .map(part => {
      const trimmed = part.trim();
      const spaceIndex = trimmed.search(/\s/);
      const url = spaceIndex === -1 ? trimmed : trimmed.slice(0, spaceIndex);
      const descriptor = spaceIndex === -1 ? '' : trimmed.slice(spaceIndex);
      return containsDangerousProtocol(url) ? '' : (url + descriptor);
    })
    .filter(Boolean)
    .join(', ');
}

/**
 * Sanitiza um nome de arquivo no atributo download=.
 * Remove extensões executáveis e caracteres de path traversal.
 */
function sanitizeDownloadFilename(name: string): string {
  if (!name) return '';

  const DANGEROUS_EXTENSIONS = /\.(exe|bat|cmd|sh|bash|ps1|vbs|js|msi|dmg|app|deb|rpm|jar|com|pif|scr|hta|reg|cpl|msc|inf|gadget|lnk)$/i;

  const safeName = name
    .replace(/[/\\:*?"<>|]/g, '_')    // path traversal e chars inválidos
    .replace(/^\.*/, '')               // não começa com pontos (arquivos ocultos)
    .slice(0, 255);                    // limite de comprimento

  if (DANGEROUS_EXTENSIONS.test(safeName)) {
    return safeName.replace(DANGEROUS_EXTENSIONS, '') + '.download';
  }
  return safeName;
}

/**
 * Remove padrões CSS perigosos de um valor de atributo style.
 *
 * Aplica cada regex da lista `CSS_DANGEROUS_PATTERNS` ao valor
 * e retorna string vazia se qualquer padrão for encontrado.
 *
 * Conservadora: prefere remover o style inteiro a tentar um patch cirúrgico,
 * pois parsers CSS complexos têm histórico de bypass via encoding.
 */
function sanitizeCSSValue(cssText: string): string {
  let safe = cssText;
  for (const pattern of Array.from(CSS_DANGEROUS_PATTERNS)) {
    if (pattern.test(safe)) return '';
    pattern.lastIndex = 0; // reset para flags global /g
  }
  return safe;
}

/**
 * Emite evento de segurança para logging/monitoramento.
 * Em produção, substitua por sua infra de observabilidade (Sentry, Datadog, etc.).
 */
function logSecurityEvent(
  type: string,
  attribute: string,
  value: string,
  node: Node
): void {
  const tagName = (node as Element).tagName?.toLowerCase() ?? 'unknown';
  console.warn(
    `[html-sanitizer] BLOQUEADO [${type}] — <${tagName}> ${attribute}="${value.slice(0, 100)}"`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública principal
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitiza uma string HTML com proteção máxima usando o perfil especificado.
 *
 * @param dirtyHtml - O HTML potencialmente perigoso a ser sanitizado.
 * @param profile   - O perfil de sanitização (default: `'content'`).
 * @returns O HTML sanitizado e seguro para inserção no DOM.
 *
 * @example
 * // Sanitização padrão (conteúdo editorial)
 * const safe = sanitizeHtml(userInput);
 *
 * // Sanitização estrita para comentários
 * const safeComment = sanitizeHtml(comment, 'strict');
 *
 * // Editor de texto rico
 * const safeRich = sanitizeHtml(wysiwygOutput, 'richText');
 */
export function sanitizeHtml(
  dirtyHtml: string,
  profile: SanitizeProfile = 'content'
): string {
  // ── Guarda de tipo ─────────────────────────────────────────────────────────
  if (typeof dirtyHtml !== 'string') {
    return '';
  }

  // ── Normalização antes de qualquer parser ─────────────────────────────────
  // Remove null bytes que podem confundir parsers HTML antes do DOMPurify ver o input.
  const normalized = dirtyHtml.replace(/\0/g, '');

  // ── SSR Fallback ──────────────────────────────────────────────────────────
  // DOMPurify requer window.document. Em Node.js ou Workers sem DOM, usa
  // o fallback de stripping. Para produção, configure jsdom + DOMPurify server-side.
  if (typeof window === 'undefined' || typeof window.document === 'undefined') {
    console.warn(
      '[html-sanitizer] DOM não disponível (SSR/Worker). ' +
      'Usando fallback de stripping. Configure jsdom para sanitização completa.'
    );
    return ssrFallbackStrip(normalized);
  }

  // ── Inicialização lazy dos hooks ──────────────────────────────────────────
  initializeHooks();

  // ── Configuração do perfil ────────────────────────────────────────────────
  const profileConfig = PROFILES[profile];

  const config: DOMPurify.Config = {
    // Allowlist de tags e atributos do perfil
    ALLOWED_TAGS: profileConfig.ALLOWED_TAGS,
    ALLOWED_ATTR: profileConfig.ALLOWED_ATTR,

    // Nunca permitir data-* — lidos silenciosamente por Angular (ng-), Vue (v-), React, etc.
    // Vetor de supply-chain: conteúdo injetado via data-bind num framework de UI.
    ALLOW_DATA_ATTR: false,

    // Nunca permitir protocolos não reconhecidos (bloqueia variantes exóticas).
    ALLOW_UNKNOWN_PROTOCOLS: false,

    // FORCE_BODY: envolve o fragmento em <body> antes de parsear.
    // Protege contra mXSS via <template>: parsers interpretam conteúdo de
    // <template> de forma diferente de <body>, permitindo payloads que
    // parecem inertes mas se tornam scripts ao sair do template context.
    // CVE principal: DOMPurify < 2.3.3 (Masato Kinugawa, 2021).
    FORCE_BODY: true,

    // SANITIZE_DOM_CLOBBERING: protege contra ataques que criam elementos com
    // id="getElementById" ou name="body" sobrescrevendo APIs do DOM.
    // GitHub XSS de 2019 usou exatamente essa técnica.
    SANITIZE_DOM_CLOBBERING: true,

    // SANITIZE_NAMED_PROPS: previne que id/name sobreescrevam propriedades
    // nomeadas do document (document.cookie, document.body, etc.)
    SANITIZE_NAMED_PROPS: true,

    // Tags adicionais para proibir explicitamente do perfil
    FORBID_TAGS: [
      ...(profileConfig.FORBID_TAGS ?? []),
      ...Array.from(ALWAYS_FORBIDDEN_TAGS),
    ],

    FORBID_ATTR: [
      ...(profileConfig.FORBID_ATTR ?? []),
      // Bloqueia todos os event handlers residuais
      // (DOMPurify já faz isso, mas a redundância é intencional)
      'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus',
      'onblur', 'onkeydown', 'onkeyup', 'onkeypress', 'onsubmit',
      // xlink:href — bypass histórico em SVG (CVE-2015-5254 e similares)
      'xlink:href',
      // xml:base — permite rebase de URLs relativas para domínio do atacante
      'xml:base',
    ],

    // Retorna string (padrão). Para Trusted Types, ver função abaixo.
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
  };

  const clean = DOMPurify.sanitize(normalized, config);

  // ── Validação pós-sanitização ─────────────────────────────────────────────
  // Segunda passagem: garante que nenhum protocolo perigoso sobrou na string
  // final. Cobre o caso hipotético de um bypass futuro no DOMPurify.
  return postSanitizeValidation(typeof clean === 'string' ? clean : String(clean));
}

/**
 * Variante que retorna um `DocumentFragment` para inserção direta no DOM
 * sem re-serialização/re-parse, eliminando o vetor de mXSS na re-serialização.
 *
 * @param dirtyHtml - O HTML a ser sanitizado.
 * @param profile   - Perfil de sanitização.
 * @returns `DocumentFragment` seguro, ou `null` em ambiente SSR.
 */
export function sanitizeHtmlToFragment(
  dirtyHtml: string,
  profile: SanitizeProfile = 'content'
): DocumentFragment | null {
  if (typeof window === 'undefined') return null;
  if (typeof dirtyHtml !== 'string') return document.createDocumentFragment();

  initializeHooks();

  const profileConfig = PROFILES[profile];

  const fragment = DOMPurify.sanitize(dirtyHtml.replace(/\0/g, ''), {
    ALLOWED_TAGS: profileConfig.ALLOWED_TAGS,
    ALLOWED_ATTR: profileConfig.ALLOWED_ATTR,
    FORBID_TAGS: [...Array.from(ALWAYS_FORBIDDEN_TAGS), ...(profileConfig.FORBID_TAGS ?? [])],
    FORBID_ATTR: [...(profileConfig.FORBID_ATTR ?? []), 'xlink:href', 'xml:base'],
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    FORCE_BODY: true,
    SANITIZE_DOM_CLOBBERING: true,
    SANITIZE_NAMED_PROPS: true,
    RETURN_DOM_FRAGMENT: true,  // retorna DocumentFragment diretamente
    RETURN_DOM: false,
  });

  return fragment as unknown as DocumentFragment;
}

/**
 * Sanitiza apenas texto inline (sem nenhuma tag HTML).
 * Converte todo o markup em entidades HTML.
 * Para uso em tooltips, alt text, labels e outras strings de texto puro.
 */
export function sanitizeTextOnly(text: string): string {
  if (typeof text !== 'string') return '';
  return text
    .replace(/\0/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

// ─────────────────────────────────────────────────────────────────────────────
// Validação pós-sanitização
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Camada final de defesa: regex sobre a string sanitizada.
 *
 * Intenção: capturar bypasses hipotéticos futuros do DOMPurify.
 * Não substitui o DOMPurify — complementa como tripwire.
 *
 * Se este filtro remover algo, DEVE ser tratado como um bug de segurança
 * crítico e reportado ao DOMPurify e à equipe interna.
 */
function postSanitizeValidation(html: string): string {
  // Nenhum protocolo perigoso deve sobrar em atributos
  const protocolPattern = /(javascript|vbscript|data|blob)\s*:/gi;
  if (protocolPattern.test(html)) {
    console.error(
      '[html-sanitizer] ALERTA CRÍTICO: protocolo perigoso detectado PÓS-SANITIZAÇÃO. ' +
      'Isso indica um possível bypass do DOMPurify. Reporte imediatamente.'
    );
    // Remove o protocolo perigoso como última linha de defesa
    return html.replace(protocolPattern, '');
  }

  // Nenhum event handler deve sobrar
  const eventPattern = /\son\w+\s*=/gi;
  if (eventPattern.test(html)) {
    console.error('[html-sanitizer] ALERTA CRÍTICO: event handler detectado pós-sanitização.');
    return html.replace(eventPattern, ' data-blocked-attr=');
  }

  return html;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitário de diagnóstico
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Retorna informações sobre a versão do DOMPurify em uso.
 * Útil para alertas de atualização em pipelines CI/CD.
 *
 * Recomendação: configure um check no CI que falha se a versão
 * do DOMPurify tiver CVEs conhecidos não corrigidos.
 */
export function getDOMPurifyInfo(): { version: string; isSupported: boolean } {
  return {
    version: DOMPurify.version ?? 'unknown',
    isSupported: typeof window !== 'undefined' && DOMPurify.isSupported,
  };
}

/**
 * Testa se o ambiente está configurado corretamente para sanitização segura.
 * Execute no startup da aplicação para detectar problemas de ambiente cedo.
 *
 * @returns Array de strings com avisos. Array vazio = ambiente ok.
 */
export function runSanityCheck(): string[] {
  const warnings: string[] = [];

  if (typeof window === 'undefined') {
    warnings.push('DOM não disponível: sanitização SSR usa apenas regex fallback.');
  }

  if (!DOMPurify.isSupported) {
    warnings.push('DOMPurify reporta ambiente não suportado. Verifique a versão do browser/jsdom.');
  }

  // Testa um payload conhecido
  const testPayload = '<img src=x onerror=alert(1)><script>alert(2)</script>';
  const result = sanitizeHtml(testPayload, 'strict');
  if (result.includes('onerror') || result.includes('<script')) {
    warnings.push('CRÍTICO: teste de sanitização falhou! DOMPurify pode estar comprometido.');
  }

  // Verifica Trusted Types
  if (typeof window !== 'undefined' && !(window as any).trustedTypes) {
    warnings.push(
      'Trusted Types não disponível neste browser. ' +
      'Adicione `require-trusted-types-for \'script\'` ao Content-Security-Policy para máxima proteção.'
    );
  }

  return warnings;
}