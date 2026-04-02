/**
 * @fileoverview Testes abrangentes para o módulo de escape contextual XSS.
 *
 * @description
 * Cada função de escape tem seu próprio `describe` com:
 *  - Guards de tipo (null, undefined, number, object)
 *  - Comportamento happy path (strings legítimas preservadas)
 *  - Vetores de ataque reais para o contexto específico
 *  - Normalização de input (null bytes, U+2028/U+2029, Unicode)
 *
 * Estrutura dos grupos:
 *  1.  escapeHtml / escapeText (alias)
 *  2.  escapeHtmlAttr
 *  3.  escapeUrl
 *  4.  escapeJs / escapeJsTemplate
 *  5.  escapeCss
 *  6.  escapeCssUrl
 *  7.  escapeJsonForHtml
 *  8.  escapeSvgAttr
 *  9.  escapeForContext (roteador)
 *  10. safeHtml / safeAttr (tagged templates)
 *  11. detectXSSSignals
 *  12. runEscapeTests
 */

import {
  escapeHtml,
  escapeText,
  escapeHtmlAttr,
  escapeUrl,
  escapeJs,
  escapeJsTemplate,
  escapeCss,
  escapeCssUrl,
  escapeJsonForHtml,
  escapeSvgAttr,
  escapeForContext,
  safeHtml,
  safeAttr,
  detectXSSSignals,
  runEscapeTests,
} from '../xss-protection';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Garante que o resultado não contém nenhum dos tokens proibidos. */
function expectNone(result: string, forbidden: string[]): void {
  for (const token of forbidden) {
    expect(result).not.toContain(token);
  }
}

beforeEach(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => { });
  jest.spyOn(console, 'error').mockImplementation(() => { });
});
afterEach(() => jest.restoreAllMocks());

// ─────────────────────────────────────────────────────────────────────────────
// 1. escapeHtml / escapeText
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeHtml', () => {
  describe('guards de tipo', () => {
    it('deve retornar string vazia para null', () => {
      expect(escapeHtml(null as unknown as string)).toBe('');
    });
    it('deve retornar string vazia para undefined', () => {
      expect(escapeHtml(undefined as unknown as string)).toBe('');
    });
    it('deve converter número em string escapada', () => {
      // guardType converte via String(value) para não-strings
      expect(typeof escapeHtml(42 as unknown as string)).toBe('string');
    });
    it('deve retornar string vazia para string vazia', () => {
      expect(escapeHtml('')).toBe('');
    });
  });

  describe('happy path', () => {
    it('deve preservar texto alfanumérico sem alteração', () => {
      expect(escapeHtml('Hello World 123')).toBe('Hello World 123');
    });
    it('deve preservar acentos e caracteres UTF-8 normais', () => {
      const result = escapeHtml('Olá, João! Ação: café');
      // he.encode codifica não-ASCII como entidades — o resultado deve ser seguro
      expect(result).not.toContain('<');
      expect(result).not.toContain('>');
    });
  });

  describe('escape de caracteres críticos', () => {
    it('deve escapar < para entidade', () => {
      expect(escapeHtml('<')).not.toContain('<');
    });
    it('deve escapar > para entidade', () => {
      expect(escapeHtml('>')).not.toContain('>');
    });
    it('deve escapar & para entidade', () => {
      const result = escapeHtml('&');
      expect(result).not.toBe('&');
      expect(result).toMatch(/&amp;|&#x26;|&#38;/);
    });
    it('deve escapar aspas duplas', () => {
      expect(escapeHtml('"Citação"')).not.toContain('"');
    });
    it('deve escapar aspas simples', () => {
      expect(escapeHtml("it's")).not.toContain("'");
    });
  });

  describe('vetores de ataque HTML', () => {
    it('deve bloquear tag <script>', () => {
      const result = escapeHtml('<script>alert(1)</script>');
      expectNone(result, ['<script', '<Script', '</script>']);
    });
    it('deve bloquear <img onerror>', () => {
      const result = escapeHtml('<img src=x onerror=alert(1)>');
      expect(result).not.toContain('<img');
      // Sendo um escape funcional (não um sanitizador), ele deve neutralizar a tag.
      // A palavra 'onerror' como texto plano é inofensiva.
      expect(result).toMatch(/&lt;img|&#x3C;img/);
    });
    it('deve bloquear injeção de tag aninhada', () => {
      const result = escapeHtml('<<SCRIPT>alert(1)//<</SCRIPT>');
      expect(result).not.toContain('<SCRIPT');
      expect(result).not.toContain('</SCRIPT>');
    });
    it('deve remover null bytes antes de escapar', () => {
      const result = escapeHtml('a\x00<script>b');
      expectNone(result, ['\x00', '<script']);
    });
    it('deve escapar U+2028 (Line Separator) que quebra parsers JS', () => {
      const result = escapeHtml('linha1\u2028linha2');
      // U+2028 deve ter sido normalizado — não deve aparecer literal
      expect(result).not.toContain('\u2028');
    });
    it('deve escapar U+2029 (Paragraph Separator)', () => {
      const result = escapeHtml('linha1\u2029linha2');
      expect(result).not.toContain('\u2029');
    });
  });

  describe('escapeText — alias de compatibilidade', () => {
    it('deve ser idêntico a escapeHtml', () => {
      const payload = '<script>alert("XSS")</script>';
      expect(escapeText(payload)).toBe(escapeHtml(payload));
    });
    it('deve retornar string vazia para null', () => {
      expect(escapeText(null as unknown as string)).toBe('');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. escapeHtmlAttr
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeHtmlAttr', () => {
  describe('guards de tipo', () => {
    it('deve retornar string vazia para null', () => {
      expect(escapeHtmlAttr(null as unknown as string)).toBe('');
    });
    it('deve retornar string vazia para undefined', () => {
      expect(escapeHtmlAttr(undefined as unknown as string)).toBe('');
    });
  });

  describe('happy path', () => {
    it('deve preservar texto alfanumérico puro', () => {
      expect(escapeHtmlAttr('hello123')).toBe('hello123');
    });
  });

  describe('breakout de atributo via aspas', () => {
    it('deve escapar aspas duplas que fechariam o atributo', () => {
      const payload = '" onclick="alert(1)';
      const result = escapeHtmlAttr(payload);
      expect(result).not.toContain('" ');
      expect(result).not.toContain('onclick');
    });
    it('deve escapar aspas simples que fechariam atributo com quotes simples', () => {
      const payload = "' onload='alert(1)";
      const result = escapeHtmlAttr(payload);
      expect(result).not.toContain("' ");
      expect(result).not.toContain('onload');
    });
    it('deve escapar backtick (fecha template literal em contexto de attr)', () => {
      const result = escapeHtmlAttr('`xss`');
      expect(result).not.toContain('`');
    });
  });

  describe('breakout de atributo não-quotado via espaço', () => {
    it('deve escapar espaços que separariam tokens HTML', () => {
      const result = escapeHtmlAttr('value onclick=alert(1)');
      expect(result).not.toContain(' ');
    });
    it('deve escapar tabs', () => {
      const result = escapeHtmlAttr('a\tb');
      expect(result).not.toContain('\t');
    });
    it('deve escapar newline', () => {
      const result = escapeHtmlAttr('a\nb');
      expect(result).not.toContain('\n');
    });
  });

  describe('injeção de atributo via = e /', () => {
    it('deve escapar = que permitiria injetar key=value', () => {
      const result = escapeHtmlAttr('a=b');
      expect(result).not.toContain('=');
    });
    it('deve escapar / que poderia fechar a tag', () => {
      const result = escapeHtmlAttr('a/b');
      expect(result).not.toContain('/');
    });
  });

  describe('vetores clássicos', () => {
    it('deve neutralizar payload completo de breakout', () => {
      const payload = '"><img src=x onerror=alert(1)><"';
      const result = escapeHtmlAttr(payload);
      expect(result).not.toContain('">');
      expect(result).not.toContain('<img');
      expect(result).not.toContain('onerror');
    });
    it('deve escapar null bytes', () => {
      const result = escapeHtmlAttr('a\x00b');
      expect(result).not.toContain('\x00');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. escapeUrl
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeUrl', () => {
  describe('guards de tipo', () => {
    it('deve retornar string vazia para null', () => {
      expect(escapeUrl(null as unknown as string)).toBe('');
    });
    it('deve retornar string vazia para undefined', () => {
      expect(escapeUrl(undefined as unknown as string)).toBe('');
    });
  });

  describe('URLs legítimas preservadas', () => {
    it('deve preservar URL https completa', () => {
      const url = 'https://exemplo.com/path?q=1&r=2#section';
      expect(escapeUrl(url)).toContain('https://exemplo.com');
    });
    it('deve preservar URL http', () => {
      expect(escapeUrl('http://example.com')).toContain('http://example.com');
    });
    it('deve preservar URL relativa /path', () => {
      expect(escapeUrl('/path/to/page')).toContain('/path/to/page');
    });
    it('deve preservar âncora #section', () => {
      expect(escapeUrl('#section')).toContain('#section');
    });
    it('deve preservar URL relativa ./arquivo', () => {
      expect(escapeUrl('./arquivo')).toContain('./arquivo');
    });
    it('deve preservar mailto:', () => {
      expect(escapeUrl('mailto:user@exemplo.com')).toContain('mailto:');
    });
    it('deve preservar tel:', () => {
      expect(escapeUrl('tel:+5511999999999')).toContain('tel:');
    });
  });

  describe('bloqueio de protocolos perigosos', () => {
    const blocked: Array<[string, string]> = [
      ['javascript:alert(1)', 'javascript:'],
      ['JAVASCRIPT:alert(1)', 'javascript:'],
      ['JavaScript:alert(1)', 'javascript:'],
      ['vbscript:msgbox(1)', 'vbscript:'],
      ['data:text/html,<script>alert(1)</script>', 'data:'],
      ['data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', 'data:'],
      ['blob:https://evil.com/uuid', 'blob:'],
      ['filesystem:https://evil.com/file', 'filesystem:'],
    ];

    it.each(blocked)('deve bloquear "%s"', (url, token) => {
      expect(escapeUrl(url)).not.toContain(token);
      expect(escapeUrl(url)).toBe('#');
    });
  });

  describe('bypasses de encoding', () => {
    it('deve bloquear javascript: URL-encoded (%6a%61...)', () => {
      expect(escapeUrl('%6a%61%76%61%73%63%72%69%70%74:alert(1)')).toBe('#');
    });
    it('deve bloquear javascript: com espaços antes', () => {
      expect(escapeUrl('   javascript:alert(1)')).toBe('#');
    });
    it('deve bloquear javascript: com \\n embutido (bypass IE)', () => {
      expect(escapeUrl('java\nscript:alert(1)')).toBe('#');
    });
    it('deve bloquear javascript: via entidade numérica &#106;', () => {
      expect(escapeUrl('&#106;avascript:alert(1)')).toBe('#');
    });
    it('deve bloquear javascript: uppercase com null byte', () => {
      expect(escapeUrl('java\x00script:alert(1)')).toBe('#');
    });
  });

  describe('injeção embutida em URL relativa', () => {
    it('deve bloquear /path/javascript:alert embutido', () => {
      // URL relativa que contém javascript: no interior
      const result = escapeUrl('/path?url=javascript:alert(1)');
      // Deve codificar ou bloquear
      expect(result).not.toContain('javascript:alert');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. escapeJs / escapeJsTemplate
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeJs', () => {
  describe('guards de tipo', () => {
    it('deve retornar string vazia para null', () => {
      expect(escapeJs(null as unknown as string)).toBe('');
    });
    it('deve retornar string vazia para undefined', () => {
      expect(escapeJs(undefined as unknown as string)).toBe('');
    });
  });

  describe('happy path', () => {
    it('deve preservar texto alfanumérico', () => {
      expect(escapeJs('hello123')).toBe('hello123');
    });
  });

  describe('breakout de string JS via aspas', () => {
    it('deve escapar aspas duplas que fechariam a string', () => {
      const result = escapeJs('"; alert(1); //');
      expect(result).not.toContain('"');
    });
    it('deve escapar aspas simples', () => {
      const result = escapeJs("'; alert(1); //");
      expect(result).not.toContain("'");
    });
    it('deve escapar backslash ANTES de outros escapes (ordem crítica)', () => {
      // Se \ não for escapado primeiro, \\" se torna \" após re-escape
      const result = escapeJs('\\');
      expect(result).toBe('\\\\');
    });
  });

  describe('fechamento de bloco <script>', () => {
    it('deve bloquear </script> que fecha o bloco mesmo dentro de string', () => {
      const result = escapeJs('</script><script>alert(1)//');
      expectNone(result, ['</script>', '<script']);
    });
    it('deve bloquear < e > via \\u003C/\\u003E', () => {
      const result = escapeJs('<tag>');
      expect(result).not.toContain('<');
      expect(result).not.toContain('>');
      expect(result).toContain('\\u003C');
      expect(result).toContain('\\u003E');
    });
  });

  describe('HTML comment injection em <script>', () => {
    it('deve neutralizar <!-- que IE tratava como comentário em <script>', () => {
      const result = escapeJs('<!-- comment -->');
      expectNone(result, ['<!--', '-->']);
    });
  });

  describe('template literal injection', () => {
    it('deve escapar backtick que fecha template literal', () => {
      const result = escapeJs('`alert(1)`');
      expect(result).not.toContain('`');
    });
    it('deve escapar ${ que injeta expressão em template literal', () => {
      const result = escapeJs('${alert(1)}');
      expect(result).not.toContain('${');
    });
  });

  describe('U+2028 / U+2029 — line terminators em JS < ES2019', () => {
    it('deve converter U+2028 em escape literal \\u2028', () => {
      const result = escapeJs('linha1\u2028linha2');
      expect(result).not.toContain('\u2028');
      expect(result).toContain('\\u2028');
    });
    it('deve converter U+2029 em escape literal \\u2029', () => {
      const result = escapeJs('linha1\u2029linha2');
      expect(result).not.toContain('\u2029');
      expect(result).toContain('\\u2029');
    });
  });

  describe('quebras de linha e caracteres de controle', () => {
    it('deve escapar \\n em \\n literal', () => {
      expect(escapeJs('a\nb')).toBe('a\\nb');
    });
    it('deve escapar \\r em \\r literal', () => {
      expect(escapeJs('a\rb')).toBe('a\\rb');
    });
    it('deve escapar \\t em \\t literal', () => {
      expect(escapeJs('a\tb')).toBe('a\\tb');
    });
    it('deve remover null bytes', () => {
      expect(escapeJs('a\x00b')).not.toContain('\x00');
    });
  });

  describe('escapeJsTemplate — alias semântico', () => {
    it('deve produzir output idêntico ao escapeJs', () => {
      const payload = '`${alert(1)}` </script>';
      expect(escapeJsTemplate(payload)).toBe(escapeJs(payload));
    });
    it('deve escapar ${ em template literal', () => {
      const result = escapeJsTemplate('${process.env.SECRET}');
      expect(result).not.toContain('${');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. escapeCss
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeCss', () => {
  describe('guards de tipo', () => {
    it('deve retornar string vazia para null', () => {
      expect(escapeCss(null as unknown as string)).toBe('');
    });
    it('deve retornar string vazia para undefined', () => {
      expect(escapeCss(undefined as unknown as string)).toBe('');
    });
  });

  describe('happy path', () => {
    it('deve preservar valor CSS seguro (cor)', () => {
      // Valores sem padrões perigosos passam pelo escape de caracteres
      const result = escapeCss('red');
      expect(result).toBe('red');
    });
    it('deve preservar valor hex de cor', () => {
      const result = escapeCss('#ff0000');
      // # não é escapado, / e outros sim
      expect(result).toContain('ff0000');
    });
  });

  describe('bloqueio de padrões CSS perigosos', () => {
    const dangerous: Array<[string, string]> = [
      ['expression(alert(1))', 'expression('],
      ['EXPRESSION(alert(1))', 'EXPRESSION('],
      ['-moz-binding:url(http://evil.com/xss.xml#xss)', '-moz-binding'],
      ['behavior: url(evil.htc)', 'behavior:'],
      ['url(javascript:alert(1))', 'javascript:'],
      ["url('javascript:alert(1)')", 'javascript:'],
      ['@import url(http://evil.com/steal.css)', '@import'],
      ['binding: url(evil.htc)', 'binding:'],
    ];

    it.each(dangerous)('deve retornar string vazia para "%s"', (input) => {
      expect(escapeCss(input)).toBe('');
    });
  });

  describe('escape de caracteres de injeção CSS', () => {
    it('deve escapar ; que injetaria nova propriedade', () => {
      const result = escapeCss('red; color: blue');
      expect(result).not.toContain(';');
    });
    it('deve escapar { que abriria novo bloco CSS', () => {
      const result = escapeCss('x { color: red }');
      expect(result).not.toContain('{');
    });
    it('deve escapar } que fecharia bloco CSS', () => {
      const result = escapeCss('x } .evil { color: red');
      expect(result).not.toContain('}');
    });
    it('deve escapar < que fecharia bloco </style>', () => {
      const result = escapeCss('</style><script>alert(1)</script>');
      expect(result).not.toContain('<');
    });
    it('deve escapar backslash antes dos outros (ordem crítica)', () => {
      const result = escapeCss('\\');
      expect(result).toBe('\\\\');
    });
    it('deve escapar \\n em escape CSS', () => {
      const result = escapeCss('red\nblue');
      expect(result).not.toContain('\n');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. escapeCssUrl
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeCssUrl', () => {
  it('deve bloquear javascript: em url()', () => {
    expect(escapeCssUrl('javascript:alert(1)')).toBe('about:blank');
  });
  it('deve bloquear data: em url()', () => {
    expect(escapeCssUrl('data:image/svg+xml,<svg><script>alert(1)</script></svg>')).toBe('about:blank');
  });
  it('deve permitir URL https válida', () => {
    const result = escapeCssUrl('https://exemplo.com/img.png');
    expect(result).toContain('https://exemplo.com');
    expect(result).not.toBe('about:blank');
  });
  it('deve retornar about:blank para URL bloqueada (# → about:blank)', () => {
    expect(escapeCssUrl('vbscript:msgbox(1)')).toBe('about:blank');
  });
  it('deve retornar string vazia para null → about:blank', () => {
    expect(escapeCssUrl(null as unknown as string)).toBe('about:blank');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. escapeJsonForHtml
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeJsonForHtml', () => {
  describe('happy path', () => {
    it('deve serializar objeto simples', () => {
      const result = escapeJsonForHtml({ a: 1, b: 'texto' });
      expect(result).toContain('"a"');
      expect(result).toContain('"b"');
      expect(result).toContain('1');
      expect(result).toContain('texto');
    });
    it('deve serializar array', () => {
      const result = escapeJsonForHtml([1, 2, 3]);
      expect(result).toContain('1');
      expect(result).toContain('2');
    });
    it('deve retornar "null" para undefined (JSON.stringify behavior)', () => {
      expect(escapeJsonForHtml(undefined)).toBe('null');
    });
  });

  describe('fechamento de bloco </script> — CVE-2018-14732 pattern', () => {
    it('deve escapar </script> que fecha o bloco script no browser', () => {
      const result = escapeJsonForHtml({ msg: '</script><script>alert(1)</script>' });
      expectNone(result, ['</script>', '<script']);
      expect(result).toContain('\\u003C');
    });
    it('deve escapar / de </script> como \\u002F', () => {
      const result = escapeJsonForHtml('</script>');
      expect(result).not.toContain('/');
    });
    it('deve escapar < como \\u003C', () => {
      const result = escapeJsonForHtml('<b>texto</b>');
      expect(result).not.toContain('<');
      expect(result).toContain('\\u003C');
    });
    it('deve escapar > como \\u003E', () => {
      const result = escapeJsonForHtml('<b>');
      expect(result).not.toContain('>');
    });
  });

  describe('HTML comment injection em <script>', () => {
    it('deve escapar <!-- que IE interpretava como comentário em script', () => {
      const result = escapeJsonForHtml('<!-- comentário -->');
      expect(result).not.toContain('<!--');
    });
    it('deve escapar --> que fecha comentário HTML em script', () => {
      const result = escapeJsonForHtml('-->');
      expect(result).not.toContain('-->');
    });
  });

  describe('& e \' em contexto XHTML', () => {
    it('deve escapar & como \\u0026', () => {
      const result = escapeJsonForHtml('a & b');
      expect(result).not.toContain(' & ');
      expect(result).toContain('\\u0026');
    });
    it('deve escapar aspas simples como \\u0027', () => {
      const result = escapeJsonForHtml("it's");
      expect(result).not.toContain("'");
      expect(result).toContain('\\u0027');
    });
  });

  describe('estruturas complexas', () => {
    it('deve escapar payload em array aninhado', () => {
      const result = escapeJsonForHtml(['safe', '</script>', '<!--']);
      expectNone(result, ['</script>', '<!--']);
    });
    it('deve escapar payload em objeto aninhado', () => {
      const result = escapeJsonForHtml({ nested: { evil: '</script>' } });
      expect(result).not.toContain('</script>');
    });
    it('deve manter booleanos e números intactos', () => {
      const result = escapeJsonForHtml({ ok: true, n: 42 });
      expect(result).toContain('true');
      expect(result).toContain('42');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. escapeSvgAttr
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeSvgAttr', () => {
  describe('guards de tipo', () => {
    it('deve retornar string vazia para null', () => {
      expect(escapeSvgAttr(null as unknown as string)).toBe('');
    });
    it('deve retornar string vazia para undefined', () => {
      expect(escapeSvgAttr(undefined as unknown as string)).toBe('');
    });
  });

  describe('atributos não-URL — aplica escapeHtmlAttr', () => {
    it('deve escapar aspas em atributo fill', () => {
      const result = escapeSvgAttr('"red"', 'fill');
      expect(result).not.toContain('"');
    });
    it('deve escapar < em atributo qualquer', () => {
      const result = escapeSvgAttr('<value>', 'd');
      expect(result).not.toContain('<');
    });
  });

  describe('atributos de URL — aplica validação de protocolo', () => {
    it('deve bloquear javascript: em href', () => {
      const result = escapeSvgAttr('javascript:alert(1)', 'href');
      expect(result).not.toContain('javascript:');
    });
    it('deve bloquear javascript: em xlink:href (bypass histórico)', () => {
      const result = escapeSvgAttr('javascript:alert(1)', 'xlink:href');
      expect(result).not.toContain('javascript:');
    });
    it('deve bloquear javascript: em src', () => {
      const result = escapeSvgAttr('javascript:alert(1)', 'src');
      expect(result).not.toContain('javascript:');
    });
    it('deve bloquear data: em data', () => {
      const result = escapeSvgAttr('data:text/html,<script>alert(1)</script>', 'data');
      expect(result).not.toContain('data:');
    });
    it('deve permitir URL https em href', () => {
      const result = escapeSvgAttr('https://exemplo.com/sprite.svg#icon', 'href');
      expect(result).toContain('https');
    });
    it('deve permitir href interno (#id) — uso legítimo de <use>', () => {
      const result = escapeSvgAttr('#meu-icone', 'href');
      expect(result).toContain('#meu-icone');
    });
  });

  describe('sem attrName — comportamento default', () => {
    it('deve aplicar escapeHtmlAttr para atributo sem nome', () => {
      const result = escapeSvgAttr('" onclick="alert(1)');
      expect(result).not.toContain('"');
      expect(result).not.toContain('onclick');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. escapeForContext — roteador
// ─────────────────────────────────────────────────────────────────────────────

describe('escapeForContext', () => {
  const contexts = [
    ['html', '<script>', '<'],
    ['htmlAttr', '" onclick="x', '"'],
    ['js', '</script>', '</'],
    ['jsTemplate', '`${alert}', '`'],
    ['css', 'expression(1)', 'expression('],
    ['jsonInHtml', '</script>', '</script>'],
    ['svgAttr', '" onload="x', '"'],
  ] as const;

  it.each(contexts)(
    'contexto "%s" deve bloquear payload perigoso',
    (context, payload, token) => {
      const result = escapeForContext(payload as string, context);
      expect(result).not.toContain(token);
    }
  );

  it('contexto "url" deve bloquear javascript:', () => {
    expect(escapeForContext('javascript:alert(1)', 'url')).toBe('#');
  });

  it('contexto "cssUrl" deve bloquear javascript:', () => {
    expect(escapeForContext('javascript:alert(1)', 'cssUrl')).toBe('about:blank');
  });

  it('deve delegar corretamente cada contexto à função especializada', () => {
    const input = 'safe_value_123';
    expect(escapeForContext(input, 'html')).toBe(escapeHtml(input));
    expect(escapeForContext(input, 'htmlAttr')).toBe(escapeHtmlAttr(input));
    expect(escapeForContext(input, 'js')).toBe(escapeJs(input));
    expect(escapeForContext(input, 'css')).toBe(escapeCss(input));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. safeHtml / safeAttr — tagged templates
// ─────────────────────────────────────────────────────────────────────────────

describe('safeHtml', () => {
  it('deve escapar valores interpolados mas preservar HTML estático', () => {
    const userInput = '<script>alert(1)</script>';
    const result = safeHtml`<p>${userInput}</p>`;
    expect(result).toContain('<p>');
    expect(result).toContain('</p>');
    expect(result).not.toContain('<script');
  });

  it('deve escapar múltiplos valores na mesma template', () => {
    const name = '<b>Bob</b>';
    const bio = '"; alert(1); //"';
    const result = safeHtml`<div>${name} — ${bio}</div>`;
    expect(result).not.toContain('<b>');
    expect(result).not.toContain(' — "');
    expect(result).toContain('<div>');
  });

  it('deve tratar null como string vazia', () => {
    const result = safeHtml`<span>${null}</span>`;
    expect(result).toBe('<span></span>');
  });

  it('deve tratar undefined como string vazia', () => {
    const result = safeHtml`<span>${undefined}</span>`;
    expect(result).toBe('<span></span>');
  });

  it('deve converter número em string escapada', () => {
    const result = safeHtml`<span>${42}</span>`;
    expect(result).toBe('<span>42</span>');
  });

  it('deve produzir template sem interpolações idêntica à string estática', () => {
    const result = safeHtml`<p>Texto estático</p>`;
    expect(result).toBe('<p>Texto estático</p>');
  });
});

describe('safeAttr', () => {
  it('deve escapar valores interpolados em atributos', () => {
    const value = '" onclick="alert(1)';
    const result = safeAttr`<div title="${value}">`;
    expect(result).not.toContain('" onclick');
    expect(result).toContain('<div title=');
  });

  it('deve escapar múltiplos atributos na mesma template', () => {
    const cls = 'x" onmouseover="evil()';
    const title = "' onfocus='evil()";
    const result = safeAttr`<div class="${cls}" title="${title}">`;
    expect(result).not.toContain('" onmouseover');
    expect(result).not.toContain("' onfocus");
  });

  it('deve tratar null como string vazia', () => {
    const result = safeAttr`<div id="${null}">`;
    expect(result).toBe('<div id="">');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. detectXSSSignals
// ─────────────────────────────────────────────────────────────────────────────

describe('detectXSSSignals', () => {
  it('deve retornar array vazio para string segura', () => {
    expect(detectXSSSignals('Texto normal sem risco.')).toHaveLength(0);
  });

  it('deve detectar tag <script>', () => {
    const signals = detectXSSSignals('<script>alert(1)</script>');
    expect(signals.some(s => s.includes('<script>'))).toBe(true);
  });

  it('deve detectar protocolo javascript:', () => {
    const signals = detectXSSSignals('javascript:alert(1)');
    expect(signals.some(s => s.includes('javascript:'))).toBe(true);
  });

  it('deve detectar event handler inline on*=', () => {
    const signals = detectXSSSignals('onclick=alert(1)');
    expect(signals.some(s => s.includes('on*'))).toBe(true);
  });

  it('deve detectar </script> (fechamento de bloco)', () => {
    const signals = detectXSSSignals('</script>');
    expect(signals.some(s => s.includes('</script>'))).toBe(true);
  });

  it('deve detectar expression() CSS', () => {
    const signals = detectXSSSignals('expression(alert(1))');
    expect(signals.some(s => s.includes('expression()'))).toBe(true);
  });

  it('deve detectar null byte', () => {
    const signals = detectXSSSignals('a\x00b');
    expect(signals.some(s => s.includes('null byte'))).toBe(true);
  });

  it('deve detectar U+2028/U+2029', () => {
    const signals = detectXSSSignals('a\u2028b');
    expect(signals.some(s => s.includes('separator'))).toBe(true);
  });

  it('deve detectar URL encoding %XX', () => {
    const signals = detectXSSSignals('%6a%61%76%61');
    expect(signals.some(s => s.includes('URL encoding'))).toBe(true);
  });

  it('deve detectar entity encoding &#', () => {
    const signals = detectXSSSignals('&#106;avascript:');
    expect(signals.some(s => s.includes('entity'))).toBe(true);
  });

  it('deve detectar template literal ${', () => {
    const signals = detectXSSSignals('${alert(1)}');
    expect(signals.some(s => s.includes('template literal'))).toBe(true);
  });

  it('deve retornar array vazio para input não-string', () => {
    expect(detectXSSSignals(null as unknown as string)).toHaveLength(0);
    expect(detectXSSSignals(undefined as unknown as string)).toHaveLength(0);
  });

  it('deve detectar múltiplos sinais no mesmo payload', () => {
    const payload = '<script>javascript:alert(1)</script>';
    const signals = detectXSSSignals(payload);
    expect(signals.length).toBeGreaterThan(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 12. runEscapeTests — suite de sanidade interna
// ─────────────────────────────────────────────────────────────────────────────

describe('runEscapeTests', () => {
  it('deve retornar array vazio em ambiente saudável (zero falhas)', () => {
    const failures = runEscapeTests();
    expect(failures).toHaveLength(0);
  });

  it('deve retornar array de strings quando há falhas simuladas', () => {
    // Verifica que o tipo de retorno é sempre string[]
    const result = runEscapeTests();
    expect(Array.isArray(result)).toBe(true);
    for (const item of result) {
      expect(typeof item).toBe('string');
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 13. Normalização Unicode — vetor de bypass por equivalência visual
// ─────────────────────────────────────────────────────────────────────────────

describe('Normalização Unicode (NFC)', () => {
  it('escapeHtml deve normalizar NFC antes de escapar', () => {
    // Full-width chars visualmente idênticos a ASCII mas com codepoints diferentes
    // Após NFC, o comportamento de encode é determinístico
    const fullWidth = '\uFF1C\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54\uFF1E'; // ＜ｓｃｒｉｐｔ＞
    const result = escapeHtml(fullWidth);
    // Não deve produzir <script> literal
    expect(result).not.toBe('<script>');
  });

  it('escapeJs deve normalizar NFC e remover U+2028/U+2029', () => {
    const result = escapeJs('a\u2028b\u2029c');
    expect(result).not.toContain('\u2028');
    expect(result).not.toContain('\u2029');
    expect(result).toContain('\\u2028');
    expect(result).toContain('\\u2029');
  });
});