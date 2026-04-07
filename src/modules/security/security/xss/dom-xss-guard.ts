/**
 * @fileoverview Funções seguras para interagir com o DOM — proteção abrangente contra DOM-XSS.
 *
 * @description
 * Fornece abstrações para todas as operações de DOM que são vetores críticos de XSS:
 *  - Inserção de HTML dinâmico (innerHTML, insertAdjacentHTML)
 *  - Atributos de URL (href, src, action, formaction, ping, data)
 *  - Atributos de evento inline (onclick, onerror, onload, …)
 *  - Valores de CSS/style (expression(), url(), comportamentos CSS)
 *  - Criação de elementos perigosos (script, iframe, object, embed, …)
 *  - textContent / innerText (seguro por padrão, mas exposto para consistência de API)
 *  - window.open / location
 *  - Trusted Types (quando disponível no browser)
 *
 * NUNCA use `element.innerHTML = ...`, `element.setAttribute('href', ...)`,
 * `element.setAttribute('onclick', ...)` ou `document.write(...)` diretamente.
 * Use sempre as funções deste módulo.
 *
 * Referências:
 *  - OWASP DOM-based XSS Prevention Cheat Sheet
 *  - W3C Trusted Types specification
 *  - MDN Content Security Policy
 */

import { sanitizeHtml } from './html-sanitizer';

// ─────────────────────────────────────────────────────────────────────────────
// Constantes e tipos
// ─────────────────────────────────────────────────────────────────────────────

/** Protocolos permitidos para atributos de URL navegáveis. */
const SAFE_NAVIGABLE_PROTOCOLS = new Set(['http:', 'https:', 'mailto:', 'tel:', 'ftp:']);

/**
 * Protocolos SEMPRE bloqueados — independentemente de qualquer outra lógica.
 * Incluem variantes ofuscadas comuns.
 */
const BLOCKED_PROTOCOLS = new Set([
  'javascript:',
  'vbscript:',
  'data:',
  'blob:',
  'filesystem:',
  'jar:',
  'livescript:',
  'mocha:',
]);

/** Atributos de evento inline que nunca devem ser definidos via setAttribute. */
const DANGEROUS_EVENT_ATTRIBUTES = new Set([
  'onabort', 'onanimationend', 'onanimationiteration', 'onanimationstart',
  'onauxclick', 'onbeforecopy', 'onbeforecut', 'onbeforepaste',
  'onblur', 'oncancel', 'oncanplay', 'oncanplaythrough', 'onchange',
  'onclick', 'onclose', 'oncontextmenu', 'oncopy', 'oncuechange',
  'oncut', 'ondblclick', 'ondrag', 'ondragend', 'ondragenter',
  'ondragleave', 'ondragover', 'ondragstart', 'ondrop',
  'ondurationchange', 'onemptied', 'onended', 'onerror', 'onfocus',
  'onformdata', 'ongotpointercapture', 'oninput', 'oninvalid',
  'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onloadeddata',
  'onloadedmetadata', 'onloadstart', 'onlostpointercapture',
  'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove',
  'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel',
  'onpaste', 'onpause', 'onplay', 'onplaying', 'onpointercancel',
  'onpointerdown', 'onpointerenter', 'onpointerleave', 'onpointermove',
  'onpointerout', 'onpointerover', 'onpointerrawupdate', 'onpointerup',
  'onprogress', 'onratechange', 'onreset', 'onresize', 'onscroll',
  'onsecuritypolicyviolation', 'onseeked', 'onseeking', 'onselect',
  'onselectionchange', 'onselectstart', 'onstalled', 'onsubmit',
  'onsuspend', 'ontimeupdate', 'ontoggle', 'ontouchcancel',
  'ontouchend', 'ontouchmove', 'ontouchstart', 'ontransitioncancel',
  'ontransitionend', 'ontransitionrun', 'ontransitionstart',
  'onvolumechange', 'onwaiting', 'onwebkitanimationend',
  'onwebkitanimationiteration', 'onwebkitanimationstart',
  'onwebkittransitionend', 'onwheel',
  // Atributos especiais não-evento mas igualmente perigosos:
  'srcdoc', 'formaction', 'action',
]);

/** Elementos cuja criação é intrinsecamente perigosa. */
const DANGEROUS_ELEMENTS = new Set([
  'script', 'iframe', 'object', 'embed', 'applet',
  'base', 'form', 'meta', 'link',
]);

/** Padrões CSS que indicam possível injeção. */
const CSS_INJECTION_PATTERNS = [
  /expression\s*\(/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /-moz-binding/i,
  /behavior\s*:/i,
  /url\s*\(\s*['"]?\s*javascript/i,
  /url\s*\(\s*['"]?\s*data/i,
  /url\s*\(\s*['"]?\s*vbscript/i,
];

// ─────────────────────────────────────────────────────────────────────────────
// Utilitários internos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Remove null bytes e normaliza a string para evitar bypasses de parser.
 * Null bytes (\x00) podem confundir parsers e contornar validações baseadas em string.
 */
function normalizeString(value: string): string {
  return value
    .replace(/\0/g, '')            // remove null bytes
    .replace(/\r?\n|\r/g, ' ')     // normaliza quebras de linha
    .trim();
}

/**
 * Tenta parsear a URL usando o construtor nativo `URL`, que normaliza
 * encoding, remove espaços extras e resolve ambiguidades de protocolo.
 * Retorna null se a URL for inválida.
 *
 * Resistente a bypasses comuns:
 *  - `javascript:alert(1)`        → bloqueado (protocolo)
 *  - `  javascript:alert(1)`      → bloqueado (trim)
 *  - `jaVaScRiPt:alert(1)`        → bloqueado (lowercase)
 *  - `\tjavascript:alert(1)`      → bloqueado (normalizeString)
 *  - `%6a%61%76%61%73%63%72%69%70%74:` → bloqueado (decode via URL constructor)
 *  - `java\nscript:alert(1)`      → bloqueado (URL constructor rejeita)
 */
function parseAndValidateURL(url: string): URL | null {
  const normalized = normalizeString(url);

  // URLs relativas: testa contra uma base arbitrária para normalização.
  try {
    const parsed = new URL(normalized, 'https://safe-base.internal/');
    const protocol = parsed.protocol.toLowerCase();

    if (BLOCKED_PROTOCOLS.has(protocol)) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

/**
 * Verifica se um elemento existe e pertence a um Document válido.
 */
function isValidElement(element: unknown): element is HTMLElement {
  return (
    element instanceof HTMLElement &&
    element.ownerDocument != null
  );
}

/**
 * Emite aviso de segurança padronizado.
 */
function securityWarn(context: string, detail: string, blocked: string): void {
  console.warn(
    `[dom-xss-guard] BLOQUEADO — ${context}: ${detail} | valor: "${blocked}"`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trusted Types (suporte nativo do browser)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria uma TrustedTypePolicy se a API estiver disponível no browser.
 * A política é usada internamente para envolver saídas sanitizadas,
 * satisfazendo browsers com CSP `require-trusted-types-for 'script'`.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API
 */
let trustedHTMLPolicy: { createHTML: (s: string) => unknown } | null = null;

if (typeof window !== 'undefined' && (window as any).trustedTypes?.createPolicy) {
  try {
    trustedHTMLPolicy = (window as any).trustedTypes.createPolicy('dom-xss-guard#html', {
      // Esta é a única política de criação de HTML trusted no app.
      // O sanitizador JÁ foi aplicado antes de chegar aqui.
      createHTML: (s: string) => s,
    });
  } catch {
    // Política já registrada (hot-reload / múltiplos módulos). Ignora.
  }
}

/**
 * Envolve o HTML sanitizado em um TrustedHTML, se disponível.
 */
function toTrustedHTML(sanitized: string): string | unknown {
  return trustedHTMLPolicy ? trustedHTMLPolicy.createHTML(sanitized) : sanitized;
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — HTML
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Define o `innerHTML` de um elemento de forma segura.
 *
 * - Sanitiza o HTML com o sanitizador configurado.
 * - Aplica Trusted Types se o browser suportar.
 * - Garante que o elemento pertence a um Document válido.
 *
 * **Use sempre esta função em vez de `element.innerHTML = ...`**
 *
 * @param element - O elemento do DOM a ser modificado.
 * @param htmlString - O conteúdo HTML a ser inserido (pode vir de fonte externa).
 */
export function safeSetInnerHTML(element: HTMLElement, htmlString: string): void {
  if (!isValidElement(element)) {
    securityWarn('safeSetInnerHTML', 'elemento inválido ou nulo', String(element));
    return;
  }

  if (typeof htmlString !== 'string') {
    element.textContent = '';
    return;
  }

  const sanitized = sanitizeHtml(htmlString);
  // Usa TrustedHTML se disponível, caso contrário usa string diretamente.
  (element as any).innerHTML = toTrustedHTML(sanitized) as string;
}

/**
 * Versão segura de `element.insertAdjacentHTML()`.
 *
 * O conteúdo é sanitizado antes da inserção e envolto em TrustedHTML quando possível.
 *
 * @param element - Elemento alvo.
 * @param position - Posição de inserção (igual à API nativa).
 * @param htmlString - HTML a ser inserido.
 */
export function safeInsertAdjacentHTML(
  element: HTMLElement,
  position: InsertPosition,
  htmlString: string
): void {
  if (!isValidElement(element)) {
    securityWarn('safeInsertAdjacentHTML', 'elemento inválido', String(element));
    return;
  }

  if (typeof htmlString !== 'string') return;

  const sanitized = sanitizeHtml(htmlString);
  element.insertAdjacentHTML(position, toTrustedHTML(sanitized) as string);
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — Texto (seguro por natureza, mas exposto para consistência)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Define o conteúdo textual de um elemento de forma segura usando `textContent`.
 *
 * `textContent` não interpreta HTML — portanto é intrinsecamente seguro contra XSS.
 * Esta função existe para:
 *  1. Tornar a intenção explícita ("quero texto, não HTML").
 *  2. Evitar o uso acidental de `innerHTML` para conteúdo que é apenas texto.
 *
 * @param element - O elemento do DOM.
 * @param text - O texto a ser definido.
 */
export function safeSetTextContent(element: HTMLElement, text: string): void {
  if (!isValidElement(element)) return;
  element.textContent = typeof text === 'string' ? text : '';
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — URLs
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Atributos de URL suportados por esta função, mapeados para seus elementos válidos.
 */
type URLAttribute = 'href' | 'src' | 'action' | 'formaction' | 'ping' | 'data' | 'poster';

/**
 * Valida e define um atributo de URL de forma segura.
 *
 * Proteções:
 *  - Bloqueia protocolos perigosos: `javascript:`, `vbscript:`, `data:`, `blob:`, …
 *  - Usa o parser nativo `URL` para normalizar antes de validar
 *    (resiste a bypasses com encoding, null bytes, tabs, newlines).
 *  - Permite apenas protocolos seguros ou URLs relativas (`/path`, `#anchor`, `./rel`).
 *  - Emite aviso de segurança e define valor inofensivo (`#`) quando bloqueado.
 *
 * @param element - O elemento do DOM.
 * @param attribute - O nome do atributo de URL.
 * @param url - A URL a ser validada e definida.
 */
export function safeSetURLAttribute(
  element: HTMLElement,
  attribute: URLAttribute,
  url: string
): void {
  if (!isValidElement(element)) return;

  if (typeof url !== 'string' || url === '') {
    element.setAttribute(attribute, '#');
    return;
  }

  const normalized = normalizeString(url);

  // Permite URLs relativas sem protocolo: /, #, ./, ../
  const isRelative = /^(\/|#|\.|\.\.\/)/i.test(normalized);

  if (isRelative) {
    // Mesmo para URLs relativas, verificar se não há injeção de protocolo embutida.
    if (/javascript\s*:/i.test(normalized) || /vbscript\s*:/i.test(normalized)) {
      securityWarn('safeSetURLAttribute', `injeção em URL relativa para [${attribute}]`, url);
      element.setAttribute(attribute, '#');
      return;
    }
    element.setAttribute(attribute, normalized);
    return;
  }

  const parsed = parseAndValidateURL(normalized);

  if (!parsed) {
    securityWarn('safeSetURLAttribute', `URL inválida ou protocolo bloqueado para [${attribute}]`, url);
    element.setAttribute(attribute, '#');
    return;
  }

  if (!SAFE_NAVIGABLE_PROTOCOLS.has(parsed.protocol.toLowerCase())) {
    securityWarn('safeSetURLAttribute', `protocolo não permitido "${parsed.protocol}" para [${attribute}]`, url);
    element.setAttribute(attribute, '#');
    return;
  }

  element.setAttribute(attribute, parsed.href);
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — Atributos genéricos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Define um atributo genérico de forma segura, impedindo a injeção de
 * atributos de evento (`onclick`, `onerror`, etc.) e atributos de URL perigosos.
 *
 * @param element - O elemento do DOM.
 * @param attribute - O nome do atributo.
 * @param value - O valor do atributo.
 */
export function safeSetAttribute(
  element: HTMLElement,
  attribute: string,
  value: string
): void {
  if (!isValidElement(element)) return;

  const attrLower = attribute.toLowerCase().trim();

  // Bloqueia atributos de evento e atributos perigosos especiais.
  if (DANGEROUS_EVENT_ATTRIBUTES.has(attrLower) || attrLower.startsWith('on')) {
    securityWarn('safeSetAttribute', `atributo de evento bloqueado`, attribute);
    return;
  }

  // Redireciona atributos de URL para a função especializada.
  const urlAttributes: URLAttribute[] = ['href', 'src', 'action', 'formaction', 'ping', 'data', 'poster'];
  if (urlAttributes.includes(attrLower as URLAttribute)) {
    safeSetURLAttribute(element, attrLower as URLAttribute, value);
    return;
  }

  // Bloqueia o atributo `style` inline (use safeSetStyle).
  if (attrLower === 'style') {
    securityWarn('safeSetAttribute', 'use safeSetStyle() para atributos de estilo', value);
    safeSetStyle(element, value);
    return;
  }

  element.setAttribute(attribute, value);
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — CSS / Style
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Define o atributo `style` de um elemento de forma segura.
 *
 * Detecta e bloqueia padrões de injeção CSS conhecidos:
 *  - `expression(...)` (IE legado)
 *  - `url('javascript:...')`
 *  - `-moz-binding`
 *  - `behavior:`
 *
 * @param element - O elemento do DOM.
 * @param cssText - O texto CSS a ser aplicado.
 */
export function safeSetStyle(element: HTMLElement, cssText: string): void {
  if (!isValidElement(element)) return;

  if (typeof cssText !== 'string') return;

  for (const pattern of CSS_INJECTION_PATTERNS) {
    if (pattern.test(cssText)) {
      securityWarn('safeSetStyle', `padrão CSS perigoso detectado: ${pattern}`, cssText);
      return;
    }
  }

  element.setAttribute('style', cssText);
}

/**
 * Define uma propriedade CSS individual de forma segura.
 *
 * Prefira esta função a `safeSetStyle` quando estiver definindo propriedades individuais,
 * pois o browser isola cada propriedade no `CSSStyleDeclaration`.
 *
 * @param element - O elemento do DOM.
 * @param property - Propriedade CSS (ex: 'color', 'background-image').
 * @param value - Valor da propriedade CSS.
 */
export function safeSetStyleProperty(
  element: HTMLElement,
  property: string,
  value: string
): void {
  if (!isValidElement(element)) return;

  if (typeof value !== 'string') return;

  for (const pattern of CSS_INJECTION_PATTERNS) {
    if (pattern.test(value)) {
      securityWarn('safeSetStyleProperty', `valor CSS perigoso em "${property}"`, value);
      return;
    }
  }

  element.style.setProperty(property, value);
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — Criação de elementos
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cria um elemento DOM de forma segura, impedindo a criação de elementos
 * intrinsecamente perigosos (`script`, `iframe`, `object`, `embed`, etc.).
 *
 * @param tagName - Nome da tag HTML.
 * @param options - Opções de criação (opcional).
 * @returns O elemento criado, ou null se o elemento for considerado perigoso.
 */
export function safeCreateElement<K extends keyof HTMLElementTagNameMap>(
  tagName: K,
  options?: ElementCreationOptions
): HTMLElementTagNameMap[K] | null {
  const tagLower = String(tagName).toLowerCase().trim();

  if (DANGEROUS_ELEMENTS.has(tagLower)) {
    securityWarn('safeCreateElement', `criação de <${tagLower}> bloqueada`, tagLower);
    return null;
  }

  return document.createElement(tagName, options);
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — Navegação (window / location)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Abre uma URL em nova aba/janela de forma segura.
 *
 * Proteções:
 *  - Valida a URL com as mesmas regras de `safeSetURLAttribute`.
 *  - Sempre adiciona `rel="noopener noreferrer"` para evitar `window.opener` hijacking.
 *
 * @param url - A URL a ser aberta.
 * @param target - O alvo da janela (default: '_blank').
 * @returns A referência à janela aberta, ou null se bloqueado.
 */
export function safeOpenWindow(
  url: string,
  target: string = '_blank'
): Window | null {
  const normalized = normalizeString(url);
  const parsed = parseAndValidateURL(normalized);

  if (!parsed || !SAFE_NAVIGABLE_PROTOCOLS.has(parsed.protocol.toLowerCase())) {
    securityWarn('safeOpenWindow', 'URL bloqueada para window.open', url);
    return null;
  }

  // 'noopener' impede que a nova aba acesse `window.opener`.
  // 'noreferrer' impede o envio do Referer header e também implica noopener.
  return window.open(parsed.href, target, 'noopener,noreferrer');
}

/**
 * Redireciona a página atual de forma segura.
 *
 * Bloqueia redirecionamentos para `javascript:`, `data:`, e outros protocolos perigosos.
 *
 * @param url - A URL de destino.
 */
export function safeNavigate(url: string): void {
  const normalized = normalizeString(url);

  // Permite URLs relativas diretamente.
  const isRelative = /^(\/|#|\.|\.\.\/)/i.test(normalized);
  if (isRelative) {
    window.location.href = normalized;
    return;
  }

  const parsed = parseAndValidateURL(normalized);

  if (!parsed || !SAFE_NAVIGABLE_PROTOCOLS.has(parsed.protocol.toLowerCase())) {
    securityWarn('safeNavigate', 'navegação bloqueada para URL insegura', url);
    return;
  }

  window.location.href = parsed.href;
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — document.write (bloqueio total)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * **Proibido.** `document.write` nunca deve ser usado.
 *
 * Esta função existe apenas para capturar chamadas acidentais e emitir um aviso claro.
 * Não existe versão "segura" de `document.write` — use `safeSetInnerHTML` ou
 * `safeInsertAdjacentHTML` com um elemento de destino explícito.
 *
 * @deprecated Nunca use document.write. Esta função sempre lança um erro.
 */
export function safeDocumentWrite(_html: string): never {
  const message =
    '[dom-xss-guard] document.write() é proibido. ' +
    'Use safeSetInnerHTML() ou safeInsertAdjacentHTML() com um elemento alvo.';
  console.error(message);
  throw new Error(message);
}

// ─────────────────────────────────────────────────────────────────────────────
// API pública — Utilitário de auditoria
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Audita um elemento e seus filhos em busca de atributos perigosos já presentes no DOM.
 * Útil para varredura de SSR / conteúdo legado injetado por terceiros.
 *
 * @param root - O elemento raiz a partir do qual a auditoria começa.
 * @returns Array de strings descrevendo cada problema encontrado.
 */
export function auditDOMForXSS(root: HTMLElement): string[] {
  const findings: string[] = [];

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
  let node: Node | null = walker.currentNode;

  while (node) {
    if (node instanceof Element) {
      // Verifica atributos perigosos.
      for (const attr of Array.from(node.attributes)) {
        const name = attr.name.toLowerCase();

        if (name.startsWith('on') || DANGEROUS_EVENT_ATTRIBUTES.has(name)) {
          findings.push(
            `<${node.tagName.toLowerCase()}> possui atributo de evento: ${attr.name}="${attr.value}"`
          );
        }

        // Verifica URLs perigosas em atributos de URL.
        if (['href', 'src', 'action', 'formaction', 'data', 'poster'].includes(name)) {
          const val = normalizeString(attr.value);
          const parsed = parseAndValidateURL(val);
          if (!parsed && !/^(\/|#|\.|\.\.\/)/i.test(val)) {
            findings.push(
              `<${node.tagName.toLowerCase()}> possui URL suspeita em [${name}]: "${attr.value}"`
            );
          } else if (parsed && BLOCKED_PROTOCOLS.has(parsed.protocol.toLowerCase())) {
            findings.push(
              `<${node.tagName.toLowerCase()}> possui protocolo bloqueado em [${name}]: "${attr.value}"`
            );
          }
        }
      }

      // Verifica elementos intrinsecamente perigosos.
      const tag = node.tagName.toLowerCase();
      if (DANGEROUS_ELEMENTS.has(tag) && tag !== 'form') {
        findings.push(`Elemento perigoso encontrado: <${tag}>`);
      }
    }
    node = walker.nextNode();
  }

  return findings;
}