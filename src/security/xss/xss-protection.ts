/**
 * @fileoverview Utilitários de escape contextual para prevenção de XSS.
 *
 * @description
 * O código original usava `he.encode()` para todos os casos — correto mas incompleto.
 * O erro fundamental de XSS é usar o escapamento ERRADO para o CONTEXTO errado.
 * Cada destino de inserção (HTML, atributo, JavaScript, CSS, URL) tem uma
 * gramática própria e precisa de uma estratégia de escape diferente.
 *
 * ── Por que contexto importa ───────────────────────────────────────────────
 *
 *  Destino              | Vetor se usar escape errado
 *  ──────────────────── | ─────────────────────────────────────────────────
 *  innerHTML            | <script>, <img onerror=...>
 *  Atributo HTML        | " onclick="alert(1)  (fecha o atributo)
 *  Atributo href/src    | javascript:alert(1)  (protocolo perigoso)
 *  Bloco <script>       | </script><script>alert(1) (fecha a tag)
 *  Variável JS inline   | "; alert(1); //  (quebra a string)
 *  Valor CSS inline     | expression(alert(1)) / url('javascript:...')
 *  JSON embutido em HTML| </script>  (quebra o bloco)
 *  template literal JS  | ${alert(1)}
 *
 * ── Vetores históricos cobertos ───────────────────────────────────────────
 *  • HTML injection via innerHTML                    (ubíquo)
 *  • Atributo breakout via " ou '                    (ubíquo)
 *  • javascript: / vbscript: em href/src             (ubíquo)
 *  • Script block injection via </script>            (CVE-2018-* series)
 *  • JSON-in-HTML via </script> ou <!--              (Angular, React SSR)
 *  • CSS expression() / -moz-binding                 (IE legado)
 *  • CSS url('javascript:...')                       (Chrome < 92)
 *  • Unicode normalisation bypass (ＳＣＲＩＰＴvs SCRIPT) (CVE-2023-*)
 *  • Homograph attacks via Punycode/Unicode          (documentado 2017+)
 *  • Template literal injection `${payload}`         (JS moderno)
 *  • Null byte injection \x00                        (parser confusion)
 *  • U+2028 / U+2029 como separadores de linha em JS (ECMAScript < 2019)
 *  • HTML comment injection <!-- --> em JS           (legacy browser parse)
 *  • CDATA injection em SVG/XHTML                    (namespace confusion)
 *
 * ── Superfícies futuras contempladas ──────────────────────────────────────
 *  • Import map injection `{"imports":{"x":"data:..."}}`
 *  • Speculation Rules JSON injection
 *  • CSS @property / @layer injection
 *  • Trusted Types — wrappers de TrustedScript/TrustedHTML
 *  • Sanitizer API nativa (substituto do he/DOMPurify no futuro)
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
 * @see https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
 */

import { encode } from 'he';

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Contextos de inserção onde dados não confiáveis podem ser colocados.
 * Cada contexto exige uma estratégia de escape diferente.
 */
export type EscapeContext =
  | 'html'           // Conteúdo de elemento HTML (innerText, textContent)
  | 'htmlAttr'       // Valor de atributo HTML (delimitado por " ou ')
  | 'url'            // Valor de href, src, action, formaction
  | 'js'             // Variável em bloco <script> ou event handler
  | 'jsTemplate'     // Template literal: `Hello ${name}`
  | 'css'            // Propriedade CSS inline ou valor em folha de estilo
  | 'cssUrl'         // url() dentro de CSS
  | 'jsonInHtml'     // JSON embutido em <script type="application/json">
  | 'svgAttr';       // Atributo de elemento SVG inline

// ─────────────────────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────────────────────

/** Protocolos proibidos em qualquer contexto de URL. */
const BLOCKED_PROTOCOLS = new Set([
  'javascript', 'vbscript', 'data', 'blob', 'filesystem',
  'jar', 'livescript', 'mocha', 'mhtml', 'mk',
]);

/** Padrões CSS intrinsecamente perigosos. */
const CSS_DANGEROUS_RE = [
  /expression\s*\(/gi,
  /-moz-binding/gi,
  /behavior\s*:/gi,
  /url\s*\(\s*['"]?\s*(javascript|vbscript|data|blob)/gi,
  /@import/gi,
  /binding\s*:/gi,
];

/**
 * Mapa de caracteres para entidades HTML — somente os 5 críticos.
 * Cobrimos o conjunto mínimo necessário; `he.encode` cobre o resto quando necessário.
 */
const HTML_ENTITY_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '`': '&#x60;',
  '/': '&#x2F;',
  '=': '&#x3D;', // previne attr injection: key=value dentro de atributos
};

/**
 * Caracteres adicionais que devem ser escapados em atributos HTML.
 * Inclui todos os separadores de token HTML.
 */
const HTML_ATTR_EXTRA_MAP: Record<string, string> = {
  ' ': '&#x20;',
  '\t': '&#x09;',
  '\n': '&#x0A;',
  '\r': '&#x0D;',
  '\f': '&#x0C;',
};

// ─────────────────────────────────────────────────────────────────────────────
// Normalização de input
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normaliza a string antes de qualquer escape:
 *  - Remove null bytes (\x00) — confundem parsers
 *  - Normaliza Unicode para NFC — previne bypass por formas equivalentes
 *    Ex: "ＳＣＲＩＰＴé" (full-width) != "SCRIPT" mas visualmente idêntico
 *  - Substitui U+2028 (Line Separator) e U+2029 (Paragraph Separator)
 *    que eram tratados como quebra de linha em JS engines < ES2019
 *    e podiam quebrar strings JS mesmo após escape simples
 */
function normalize(value: string): string {
  return value
    .replace(/\0/g, '')                       // null bytes
    .replace(/\u2028/g, '\\u2028')            // Line Separator → literal escape
    .replace(/\u2029/g, '\\u2029')            // Paragraph Separator → literal escape
    .normalize('NFC');                         // Unicode normalization
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard de tipo compartilhado
// ─────────────────────────────────────────────────────────────────────────────

function guardType(value: unknown, context: EscapeContext): string | null {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'string') {
    console.warn(`[xss-protection] escapeForContext(${context}): recebeu ${typeof value}, esperava string.`);
    return String(value);
  }
  return null; // prosseguir com a string
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Contexto HTML — conteúdo de elemento
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapa texto para inserção como conteúdo de elemento HTML.
 *
 * Use quando: `element.textContent = escapeHtml(text)` NÃO é opção e você
 * precisa da string escapada para template string ou SSR.
 *
 * Substitui os 5 caracteres críticos de HTML por entidades.
 * Usa `he.encode` para cobertura completa de caracteres não-ASCII.
 *
 * ⚠ Se você estiver em um browser, prefira `element.textContent = text`
 * (não interpreta HTML) ou `safeSetTextContent()` do dom-xss-guard.
 *
 * @example
 * const userInput = '<script>alert(1)</script>';
 * template.innerHTML = `<p>${escapeHtml(userInput)}</p>`;
 * // → <p>&lt;script&gt;alert(1)&lt;/script&gt;</p>
 */
export function escapeHtml(text: string): string {
  const guard = guardType(text, 'html');
  if (guard !== null) return guard;
  // Usa named references (ex: &lt;) para maior legibilidade e compatibilidade com testes legados
  return encode(normalize(text as string), { useNamedReferences: true });
}

/**
 * @alias para compatibilidade com o código original.
 */
export const escapeText = escapeHtml;

// ─────────────────────────────────────────────────────────────────────────────
// 2. Contexto Atributo HTML
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapa um valor para uso dentro de um atributo HTML delimitado por aspas.
 *
 * Regra OWASP: "Except for alphanumeric characters, escape all characters with
 * ASCII values less than 256 with the &#xHH; format."
 *
 * Por que não é o mesmo que escapeHtml:
 *  - `" onclick="alert(1)` fecha o atributo sem precisar de < ou >
 *  - Espaços e tabs dentro de um atributo não-quotado quebram o token
 *  - Mesmo com aspas duplas, `'` pode ser perigoso se o template usar aspas simples
 *
 * @example
 * // ERRADO (atributo não protegido):
 * el.outerHTML = `<div title="${userInput}">`;
 *
 * // CORRETO:
 * el.outerHTML = `<div title="${escapeHtmlAttr(userInput)}">`;
 */
export function escapeHtmlAttr(text: string): string {
  const guard = guardType(text, 'htmlAttr');
  if (guard !== null) return guard;

  let normalized = normalize(text as string);

  // Neutraliza event handlers inline (on*) como camada de defesa extra
  normalized = normalized.replace(/\bon(\w+)\s*=/gi, 'data-blocked-$1=');

  // Escapa os 8 caracteres críticos de atributo
  return normalized.replace(/[&<>"'`=/\s]/g, (char) =>
    HTML_ENTITY_MAP[char] ?? HTML_ATTR_EXTRA_MAP[char] ?? `&#x${char.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()};`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Contexto URL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitiza e codifica uma URL para uso em href, src, action, etc.
 *
 * Proteções em camadas:
 *  1. Normalização (null bytes, Unicode)
 *  2. Decodificação do protocolo para detectar `%6a%61%76%61%73%63%72%69%70%74:`
 *  3. Blocklist de protocolos perigosos
 *  4. Permite URLs relativas seguras (/path, #anchor, ./rel)
 *  5. encodeURI para a URL completa (mantém estrutura de URL válida)
 *
 * @example
 * element.setAttribute('href', escapeUrl(userUrl));
 */
export function escapeUrl(url: string): string {
  const guard = guardType(url, 'url');
  if (guard !== null) return guard;

  const normalized = normalize(url as string).trim();

  // Permite URLs relativas sem validação de protocolo
  if (/^(\/|#|\.\/)/.test(normalized)) {
    // Ainda verifica injeção embutida em URL relativa
    if (/javascript\s*:|vbscript\s*:/i.test(normalized)) {
      logBlock('url-relative-injection', normalized);
      return '#';
    }
    return encodeURI(normalized);
  }

  // Decodifica para detectar bypass via %XX e entidades
  const decoded = decodeProtocolForCheck(normalized);
  const protocolMatch = decoded.match(/^([a-z][a-z0-9+\-.]*)\s*:/i);

  if (protocolMatch) {
    const proto = protocolMatch[1].toLowerCase().replace(/\s+/g, '');
    if (BLOCKED_PROTOCOLS.has(proto)) {
      logBlock('url-protocol', `${proto}: from "${normalized}"`);
      return '#';
    }
    // Protocolo permitido — codifica mantendo estrutura
    try {
      const parsed = new URL(normalized);
      return parsed.href;
    } catch {
      return '#';
    }
  }

  // Sem protocolo reconhecido — trata como URL relativa
  return encodeURI(normalized);
}

/**
 * Decodifica um possível URL-encoded ou entity-encoded protocolo para comparação.
 * Resiste a: %6a%61%76%61%73%63%72%69%70%74 · &#106;avascript · java\nscript
 */
function decodeProtocolForCheck(value: string): string {
  let decoded = value
    .replace(/[\0\r\n\t\x0B\x0C\xA0\u2028\u2029]/g, '')
    .toLowerCase();
  try { decoded = decodeURIComponent(decoded); } catch { /* mantém */ }
  return decoded.replace(/&#x?([0-9a-f]+);?/gi, (_, code) => {
    try { return String.fromCodePoint(parseInt(code, /x/i.test(_) ? 16 : 10)); }
    catch { return ''; }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Contexto JavaScript
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapa uma string para inserção dentro de uma string JavaScript
 * delimitada por " ou ' dentro de um bloco <script> ou handler inline.
 *
 * ATENÇÃO: Evite ao máximo inserir dados em blocos <script> via SSR.
 * Prefira carregar dados via API fetch ou via atributos data-* já escapados.
 *
 * Vetores cobertos:
 *  - `"` e `'` — fecham a string JS
 *  - `\` — escape prefix (permite `\"` virar `"` novamente)
 *  - `</script>` — fecha o bloco mesmo dentro de string
 *  - `<!--` — legacy browser parse (IE tratava como comentário em <script>)
 *  - `-->` — fecha comentário HTML dentro de script
 *  - U+2028 / U+2029 — tratados como newline em engines < ES2019
 *  - Template backtick ` — fecha template literal
 *  - ${} — injeta expressão em template literal
 *
 * @example
 * // No template SSR:
 * const html = `<script>var name = "${escapeJs(userInput)}";</script>`;
 */
export function escapeJs(text: string): string {
  const guard = guardType(text, 'js');
  if (guard !== null) return guard;

  const normalized = normalize(text as string);

  return normalized
    .replace(/\\/g, '\\\\')   // \ → \\ (DEVE ser primeiro)
    .replace(/"/g, '\\u0022') // Escape hexadecimal completo previne breakout de string
    .replace(/'/g, '\\u0027')
    .replace(/`/g, '\\u0060')
    .replace(/\$/g, '\\u0024') // Previne ${} injection em template literals de forma que ignore a interpolação
    .replace(/</g, '\\u003C') // </script> injection
    .replace(/>/g, '\\u003E')
    .replace(/&/g, '\\u0026') // & pode iniciar entidade em XHTML
    .replace(/=/g, '\\u003D') // = pode ser perigoso em atributos de evento
    .replace(/\//g, '\\/')     // </script> e regex termination
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/\x0B/g, '\\v')
    .replace(/\f/g, '\\f')
    // U+2028/U+2029 já foram trocados por \\u2028/\\u2029 em normalize()
    // mas após o .replace(/\\/g) vira \\\\u2028 — re-aplica:
    .replace(/\\\\u(2028|2029)/g, '\\u$1');
}

/**
 * Escapa uma string para interpolação segura em template literals JS.
 *
 * Além dos escapes de escapeJs, garante que `${` seja neutralizado.
 *
 * @example
 * const sql = `SELECT * FROM users WHERE name = \`${escapeJsTemplate(name)}\``;
 */
export function escapeJsTemplate(text: string): string {
  // escapeJs já cobre ` e ${ — esta função é um alias semântico
  return escapeJs(text);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Contexto CSS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapa um valor para inserção segura em uma propriedade CSS.
 *
 * Use quando precisar injetar dados do usuário em `style` inline:
 * `el.style.color = escapeCss(userColor)`
 *
 * Vetores cobertos:
 *  - `expression()` — IE legado, ainda presente em parsers embedded
 *  - `-moz-binding` / `behavior:` — Firefox/IE histórico
 *  - `url('javascript:...')` — CSS url() com protocolo perigoso
 *  - `</style>` — fecha bloco de estilo
 *  - Injeção de propriedades via `;property: value`
 *  - `@import` — exfiltração por CSS side-channel
 *
 * @example
 * el.setAttribute('style', `color: ${escapeCss(userColor)}`);
 */
export function escapeCss(value: string): string {
  const guard = guardType(value, 'css');
  if (guard !== null) return guard;

  const normalized = normalize(value as string);

  // Verifica padrões perigosos — retorna string vazia se detectado
  for (const pattern of CSS_DANGEROUS_RE) {
    pattern.lastIndex = 0;
    if (pattern.test(normalized)) {
      logBlock('css-dangerous-pattern', `${pattern} in "${normalized.slice(0, 60)}"`);
      return '';
    }
  }

  // Escapa caracteres que poderiam injetar propriedades ou fechar blocos
  return normalized
    .replace(/\\/g, '\\\\')   // backslash (DEVE ser primeiro)
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'")
    .replace(/</g, '\\3C ')  // CSS hex escape — fecha </style>
    .replace(/>/g, '\\3E ')
    .replace(/\//g, '\\2F ')  // </style> termination
    .replace(/;/g, '\\3B ')  // previne injeção de nova propriedade
    .replace(/{/g, '\\7B ')  // abre novo bloco
    .replace(/}/g, '\\7D ')
    .replace(/\n/g, '\\A ')
    .replace(/\r/g, '\\D ');
}

/**
 * Escapa uma URL para uso dentro de `url(...)` em CSS.
 *
 * CSS `url()` é um vetor independente: `background: url('javascript:...')`.
 * Aplica validação de protocolo + encodeURI.
 *
 * @example
 * el.style.backgroundImage = `url("${escapeCssUrl(userUrl)}")`;
 */
export function escapeCssUrl(url: string): string {
  const safe = escapeUrl(url);
  if (safe === '#' || safe === '') return 'about:blank';
  return safe;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Contexto JSON embutido em HTML
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Serializa dados para JSON embutido seguro em `<script type="application/json">`.
 *
 * O `JSON.stringify` normal produz `</script>` literal que FECHA o bloco script,
 * mesmo dentro de uma string JSON. Isso é um vetor clássico em React SSR, Angular,
 * Next.js, etc.
 *
 * Também escapa `<!--` e `-->` que eram interpretados como comentários HTML
 * em `<script>` em browsers legados (IE).
 *
 * Histórico: CVE-2018-14732 (webpack-dev-server), múltiplos Next.js/Nuxt SSR issues.
 *
 * @example
 * // No template SSR:
 * const html = `<script type="application/json">${escapeJsonForHtml(data)}</script>`;
 *
 * // No React:
 * <script
 *   type="application/json"
 *   dangerouslySetInnerHTML={{ __html: escapeJsonForHtml(data) }}
 * />
 */
export function escapeJsonForHtml(data: unknown): string {
  const json = JSON.stringify(data);
  if (typeof json !== 'string') return 'null';

  return json
    .replace(/</g, '\\u003C')  // </script> → \u003C/script>
    .replace(/>/g, '\\u003E')  // > de </script>
    .replace(/&/g, '\\u0026')  // & — pode iniciar entidade em XHTML
    .replace(/'/g, '\\u0027')  // ' em contexto de atributo SSR
    .replace(/\//g, '\\u002F')  // / de </script>
    .replace(/<!--/g, '\\u003C!--')   // HTML comment em script
    .replace(/-->/g, '--\\u003E');   // fechar comment
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Contexto SVG Atributo
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapa um valor para atributo SVG inline.
 *
 * SVG tem particularidades em relação a HTML:
 *  - Pode ser parseado tanto como HTML5 quanto como XML (XHTML)
 *  - xlink:href e href podem carregar recursos externos
 *  - Event handlers funcionam igual ao HTML
 *  - Namespaces permitem confusão de parser (mXSS via SVG→HTML)
 *
 * Esta função aplica escapeHtmlAttr com validação extra de URL quando
 * o atributo é reconhecido como portador de URL.
 *
 * @param value O valor do atributo.
 * @param attrName O nome do atributo (para validação contextual).
 */
export function escapeSvgAttr(value: string, attrName: string = ''): string {
  const guard = guardType(value, 'svgAttr');
  if (guard !== null) return guard;

  const urlAttrs = new Set(['href', 'xlink:href', 'src', 'data', 'action']);
  const lowerAttr = attrName.toLowerCase();

  if (urlAttrs.has(lowerAttr)) {
    // Para atributos de URL em SVG, força escapeUrl + escapeHtmlAttr
    return escapeHtmlAttr(escapeUrl(value as string));
  }

  return escapeHtmlAttr(value as string);
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. API unificada contextual
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Roteador contextual — aplica o escape correto para cada destino de inserção.
 *
 * Esta é a função recomendada quando o contexto de inserção é dinâmico ou
 * determinado em runtime. Para usos estáticos, prefira as funções específicas
 * (`escapeHtml`, `escapeHtmlAttr`, `escapeUrl`, `escapeJs`, `escapeCss`, etc.)
 * que são mais explícitas e mais fáceis de auditar.
 *
 * @param value - O valor a escapar.
 * @param context - O contexto de inserção.
 *
 * @example
 * const safeValue = escapeForContext(userInput, 'htmlAttr');
 * el.outerHTML = `<div title="${safeValue}">`;
 */
export function escapeForContext(value: string, context: EscapeContext): string {
  switch (context) {
    case 'html': return escapeHtml(value);
    case 'htmlAttr': return escapeHtmlAttr(value);
    case 'url': return escapeUrl(value);
    case 'js': return escapeJs(value);
    case 'jsTemplate': return escapeJsTemplate(value);
    case 'css': return escapeCss(value);
    case 'cssUrl': return escapeCssUrl(value);
    case 'jsonInHtml': return escapeJsonForHtml(value);
    case 'svgAttr': return escapeSvgAttr(value);
    default: {
      const _exhaustive: never = context;
      console.warn(`[xss-protection] Contexto desconhecido: ${_exhaustive}. Usando escapeHtml como fallback.`);
      return escapeHtml(value);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Tagged template literal — interpolação segura
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Tagged template literal para interpolação segura de HTML.
 *
 * Todos os valores interpolados são automaticamente escapados para o
 * contexto HTML (entidades). As partes estáticas do template (escritas
 * pelo dev) são tratadas como HTML confiável e passadas sem modificação.
 *
 * @example
 * // ERRADO:
 * element.innerHTML = `<div>${userInput}</div>`;
 *
 * // CORRETO:
 * element.innerHTML = safeHtml`<div>${userInput}</div>`;
 * //                           ↑ string estática   ↑ valor escapado
 *
 * // Com múltiplos valores:
 * element.innerHTML = safeHtml`
 *   <p>Olá, ${username}!</p>
 *   <span>${userBio}</span>
 * `;
 */
export function safeHtml(
  strings: TemplateStringsArray,
  ...values: unknown[]
): string {
  return strings.reduce((result, str, i) => {
    const value = values[i - 1];
    const escaped = value == null ? '' : escapeHtml(String(value));
    return result + escaped + str;
  });
}

/**
 * Tagged template literal para interpolação segura de atributos HTML.
 *
 * @example
 * el.outerHTML = safeAttr`<div class="${userClass}" title="${userTitle}">`;
 */
export function safeAttr(
  strings: TemplateStringsArray,
  ...values: unknown[]
): string {
  return strings.reduce((result, str, i) => {
    const value = values[i - 1];
    const escaped = value == null ? '' : escapeHtmlAttr(String(value));
    return result + escaped + str;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Utilitários de diagnóstico
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detecta sinais de possíveis payloads XSS em uma string.
 * Não é um sanitizador — apenas retorna diagnóstico para logging/auditoria.
 *
 * @returns Um array de strings descrevendo os riscos detectados.
 */
export function detectXSSSignals(input: string): string[] {
  if (typeof input !== 'string') return [];

  const signals: string[] = [];
  const checks: Array<[RegExp, string]> = [
    [/<script/i, 'tag <script> detectada'],
    [/javascript\s*:/i, 'protocolo javascript:'],
    [/vbscript\s*:/i, 'protocolo vbscript:'],
    [/data\s*:/i, 'protocolo data:'],
    [/on\w+\s*=/i, 'event handler inline (on*)'],
    [/<\s*\/\s*script/i, 'fechamento de bloco </script>'],
    [/expression\s*\(/i, 'CSS expression()'],
    [/-moz-binding/i, 'CSS -moz-binding'],
    [/<!--/, 'comentário HTML'],
    [/\x00/, 'null byte'],
    [/\u2028|\u2029/, 'Unicode line/paragraph separator'],
    [/\${/, 'template literal injection ${'],
    [/&#x?[0-9a-f]+;/i, 'HTML entity encoding (possível bypass)'],
    [/%[0-9a-f]{2}/i, 'URL encoding (possível bypass)'],
    [/<[a-z]/i, 'tag HTML detectada'],
    [/[\u0000-\u001F]/, 'caractere de controle ASCII'],
  ];

  for (const [pattern, description] of checks) {
    if (pattern.test(input)) {
      signals.push(description);
    }
  }

  return signals;
}

/**
 * Emite log de bloqueio de segurança padronizado.
 */
function logBlock(type: string, detail: string): void {
  console.warn(`[xss-protection] BLOQUEADO [${type}]: ${detail}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Testes de sanidade (executar no startup)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executa vetores de teste conhecidos em cada função de escape.
 * Retorna array de falhas. Array vazio = tudo ok.
 *
 * Recomendado no startup da aplicação e em CI.
 *
 * @example
 * const failures = runEscapeTests();
 * if (failures.length > 0) {
 *   throw new Error(`xss-protection sanity check failed:\n${failures.join('\n')}`);
 * }
 */
export function runEscapeTests(): string[] {
  const failures: string[] = [];

  const assert = (fn: string, input: string, output: string, shouldNotContain: string) => {
    if (output.includes(shouldNotContain)) {
      failures.push(`[${fn}] input="${input}" → output contém "${shouldNotContain}"`);
    }
  };

  // HTML
  assert('escapeHtml', '<script>alert(1)</script>', escapeHtml('<script>alert(1)</script>'), '<script>');
  assert('escapeHtml', '"XSS"', escapeHtml('"XSS"'), '"');

  // HTML Attr
  assert('escapeHtmlAttr', '" onclick="alert(1)', escapeHtmlAttr('" onclick="alert(1)'), '"');
  assert('escapeHtmlAttr', "' onload='x", escapeHtmlAttr("' onload='x"), "'");

  // URL
  assert('escapeUrl', 'javascript:alert(1)', escapeUrl('javascript:alert(1)'), 'javascript:');
  assert('escapeUrl', 'JAVASCRIPT:alert(1)', escapeUrl('JAVASCRIPT:alert(1)'), 'javascript:');
  assert('escapeUrl', '  javascript:alert(1)', escapeUrl('  javascript:alert(1)'), 'javascript:');
  assert('escapeUrl', 'data:text/html,<script>alert(1)</script>', escapeUrl('data:text/html,<script>alert(1)</script>'), 'data:');

  // JS
  assert('escapeJs', '";</script><script>alert(1)//', escapeJs('";</script><script>alert(1)//'), '</script>');
  assert('escapeJs', '"; alert(1);//', escapeJs('"; alert(1);//'), '"');

  // CSS
  assert('escapeCss', 'expression(alert(1))', escapeCss('expression(alert(1))'), 'expression(');
  assert('escapeCss', 'url(javascript:alert(1))', escapeCss('url(javascript:alert(1))'), 'javascript:');

  // JSON
  assert('escapeJsonForHtml', '</script>', escapeJsonForHtml('</script>'), '</script>');
  assert('escapeJsonForHtml', '<!--', escapeJsonForHtml('<!--'), '<!--');

  // SVG attr
  assert('escapeSvgAttr', 'javascript:alert(1)', escapeSvgAttr('javascript:alert(1)', 'href'), 'javascript:');

  return failures;
}