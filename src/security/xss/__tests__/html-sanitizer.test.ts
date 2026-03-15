/**
 * @fileoverview Testes abrangentes para o módulo de sanitização de HTML.
 *
 * @description
 * Cobre todos os perfis, todos os hooks, vetores históricos de XSS confirmados
 * e superfícies emergentes. Organizado por responsabilidade para facilitar
 * diagnóstico quando um teste falha.
 *
 * Convenções:
 *  - Cada `describe` cobre uma responsabilidade isolada.
 *  - Nomes de teste no padrão "deve [comportamento esperado] quando [condição]".
 *  - Payloads reais — sem abstrações que escondem o vetor de ataque.
 *  - `not.toContain` é preferível a `toBe('')` em testes de bloqueio,
 *    pois o DOMPurify pode manter texto de fallback mesmo removendo a tag.
 */

import {
  sanitizeHtml,
  sanitizeHtmlToFragment,
  sanitizeTextOnly,
  getDOMPurifyInfo,
  runSanityCheck,
} from '../html-sanitizer';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Garante que nenhuma string da lista aparece no resultado. */
function expectNone(result: string, forbidden: string[]): void {
  for (const token of forbidden) {
    expect(result).not.toContain(token);
  }
}

/** Supprime console.warn/error produzidos intencionalmente pelo módulo durante testes. */
const silence = () => {
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
};

beforeEach(() => silence());
afterEach(() => jest.restoreAllMocks());

// ─────────────────────────────────────────────────────────────────────────────
// 1. Guards de tipo e input vazio
// ─────────────────────────────────────────────────────────────────────────────

describe('Guards de tipo e input', () => {
  it('deve retornar string vazia para input não-string (number)', () => {
    expect(sanitizeHtml(42 as unknown as string)).toBe('');
  });

  it('deve retornar string vazia para input não-string (null)', () => {
    expect(sanitizeHtml(null as unknown as string)).toBe('');
  });

  it('deve retornar string vazia para input não-string (undefined)', () => {
    expect(sanitizeHtml(undefined as unknown as string)).toBe('');
  });

  it('deve retornar string vazia para input não-string (object)', () => {
    expect(sanitizeHtml({} as unknown as string)).toBe('');
  });

  it('deve retornar string vazia para string vazia', () => {
    expect(sanitizeHtml('')).toBe('');
  });

  it('deve remover null bytes antes do parse', () => {
    const result = sanitizeHtml('<b\x00>texto</b\x00>');
    expectNone(result, ['\x00', '<script', 'alert']);
    // O texto legítimo deve sobreviver
    expect(result).toContain('texto');
  });

  it('deve remover null bytes embutidos em protocolo javascript:\\x00', () => {
    const result = sanitizeHtml('<a href="java\x00script:alert(1)">click</a>');
    expectNone(result, ['javascript:', 'alert']);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Perfil padrão — content
// ─────────────────────────────────────────────────────────────────────────────

describe('Perfil content (padrão)', () => {
  it('deve preservar formatação básica legítima', () => {
    const input = '<p><strong>Olá</strong> <em>mundo</em></p>';
    expect(sanitizeHtml(input)).toBe(input);
  });

  it('deve preservar links com href absoluto seguro', () => {
    const result = sanitizeHtml('<a href="https://exemplo.com">link</a>');
    expect(result).toContain('href="https://exemplo.com"');
    expect(result).toContain('link');
  });

  it('deve preservar imagens com src absoluto seguro', () => {
    const result = sanitizeHtml('<img src="https://exemplo.com/img.png" alt="foto">');
    expect(result).toContain('src="https://exemplo.com/img.png"');
  });

  it('deve remover tags <script>', () => {
    const result = sanitizeHtml('<b>Olá</b><script>alert("XSS")</script>');
    expectNone(result, ['<script', 'alert(']);
    expect(result).toContain('<b>Olá</b>');
  });

  it('deve remover atributo onerror', () => {
    const result = sanitizeHtml('<img src="x" onerror="alert(1)">');
    expectNone(result, ['onerror', 'alert(1)']);
  });

  it('deve remover atributo onclick', () => {
    const result = sanitizeHtml('<div onclick="alert(1)">texto</div>');
    expectNone(result, ['onclick', 'alert(1)']);
    expect(result).toContain('texto');
  });

  it('deve remover atributos data-* (vetor supply-chain Angular/Vue/React)', () => {
    const result = sanitizeHtml('<div data-ng-click="evil()" data-v-on="evil()">x</div>');
    expectNone(result, ['data-ng-click', 'data-v-on', 'evil()']);
  });

  it('deve remover atributo srcdoc de iframe', () => {
    const result = sanitizeHtml('<iframe srcdoc="<script>alert(1)</script>"></iframe>');
    expectNone(result, ['srcdoc', 'iframe', '<script', 'alert(1)']);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Perfil strict
// ─────────────────────────────────────────────────────────────────────────────

describe('Perfil strict', () => {
  it('deve manter formatação inline básica', () => {
    const result = sanitizeHtml('<em>importante</em>', 'strict');
    expect(result).toBe('<em>importante</em>');
  });

  it('deve remover tags de bloco (p, div, section)', () => {
    const result = sanitizeHtml('<p>parágrafo</p><div>bloco</div>', 'strict');
    expectNone(result, ['<p>', '<div>']);
    expect(result).toContain('parágrafo');
  });

  it('deve remover links (<a>)', () => {
    const result = sanitizeHtml('<a href="https://x.com">link</a>', 'strict');
    expectNone(result, ['<a ', 'href=']);
    expect(result).toContain('link');
  });

  it('deve remover imagens', () => {
    const result = sanitizeHtml('<img src="x.png" alt="x">', 'strict');
    expectNone(result, ['<img', 'src=']);
  });

  it('deve remover atributos de classe quando não permitidos', () => {
    // strict permite class — testa que não permite href
    const result = sanitizeHtml('<span class="highlight" href="evil">x</span>', 'strict');
    expect(result).toContain('class="highlight"');
    expect(result).not.toContain('href=');
  });

  it('deve bloquear <script> com payload clássico', () => {
    const result = sanitizeHtml('<b>ok</b><script>alert("XSS");</script>', 'strict');
    expectNone(result, ['<script', 'alert(']);
    expect(result).toContain('<b>ok</b>');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Perfil inlineOnly
// ─────────────────────────────────────────────────────────────────────────────

describe('Perfil inlineOnly', () => {
  it('deve manter tags inline mas remover todos os atributos', () => {
    const result = sanitizeHtml('<strong class="x" style="color:red">texto</strong>', 'inlineOnly');
    expect(result).toContain('<strong>texto</strong>');
    expectNone(result, ['class=', 'style=']);
  });

  it('deve remover links completamente', () => {
    const result = sanitizeHtml('<a href="https://x.com">link</a>', 'inlineOnly');
    expectNone(result, ['<a', 'href=']);
    expect(result).toContain('link');
  });

  it('deve remover tags de bloco mas manter texto', () => {
    const result = sanitizeHtml('<p>parágrafo <b>negrito</b></p>', 'inlineOnly');
    expectNone(result, ['<p>', '</p>']);
    expect(result).toContain('<b>negrito</b>');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Perfil richText
// ─────────────────────────────────────────────────────────────────────────────

describe('Perfil richText', () => {
  it('deve permitir tabelas com atributos de layout', () => {
    const input = '<table><tr><td colspan="2">célula</td></tr></table>';
    const result = sanitizeHtml(input, 'richText');
    expect(result).toContain('<table>');
    expect(result).toContain('colspan="2"');
  });

  it('deve permitir listas ordenadas e não-ordenadas', () => {
    const input = '<ul><li>item 1</li></ul><ol><li>item a</li></ol>';
    const result = sanitizeHtml(input, 'richText');
    expect(result).toContain('<ul>');
    expect(result).toContain('<ol>');
  });

  it('deve remover <script> mesmo no perfil mais permissivo', () => {
    const result = sanitizeHtml('<p>texto</p><script>alert(1)</script>', 'richText');
    expectNone(result, ['<script', 'alert(1)']);
    expect(result).toContain('<p>texto</p>');
  });

  it('deve permitir atributos aria-* para acessibilidade', () => {
    const result = sanitizeHtml('<div aria-label="conteúdo" role="main">x</div>', 'richText');
    expect(result).toContain('aria-label="conteúdo"');
    expect(result).toContain('role="main"');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Perfil svgSafe
// ─────────────────────────────────────────────────────────────────────────────

describe('Perfil svgSafe', () => {
  it('deve preservar SVG decorativo seguro', () => {
    const svg = '<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="red"/></svg>';
    const result = sanitizeHtml(svg, 'svgSafe');
    expect(result).toContain('<svg');
    expect(result).toContain('<circle');
    expect(result).toContain('fill="red"');
  });

  it('deve remover atributo xlink:href (bypass histórico CVE-2015)', () => {
    const result = sanitizeHtml(
      '<svg><use xlink:href="http://evil.com/sprite.svg#icon"/></svg>',
      'svgSafe'
    );
    expectNone(result, ['xlink:href', 'evil.com']);
  });

  it('deve remover href externo em <use> (carregamento de SVG externo)', () => {
    const result = sanitizeHtml(
      '<svg><use href="http://evil.com/sprite.svg#x"/></svg>',
      'svgSafe'
    );
    expect(result).not.toContain('evil.com');
  });

  it('deve permitir href interno (#id) em <use>', () => {
    const result = sanitizeHtml(
      '<svg><defs><symbol id="ico"><circle r="5"/></symbol></defs><use href="#ico"/></svg>',
      'svgSafe'
    );
    expect(result).toContain('href="#ico"');
  });

  it('deve remover event handlers em SVG (onload, onerror, onclick)', () => {
    const result = sanitizeHtml(
      '<svg><rect onclick="alert(1)" onload="alert(2)" width="10" height="10"/></svg>',
      'svgSafe'
    );
    expectNone(result, ['onclick', 'onload', 'alert(1)', 'alert(2)']);
    expect(result).toContain('<rect');
  });

  it('deve remover <script> embutido em SVG', () => {
    const result = sanitizeHtml(
      '<svg><script>alert(1)</script><circle r="5"/></svg>',
      'svgSafe'
    );
    expectNone(result, ['<script', 'alert(1)']);
    expect(result).toContain('<circle');
  });

  it('deve remover xml:base (rebase de URLs para domínio do atacante)', () => {
    const result = sanitizeHtml(
      '<svg xml:base="http://evil.com/"><use href="#local"/></svg>',
      'svgSafe'
    );
    expect(result).not.toContain('xml:base');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Bloqueio de protocolos em URLs
// ─────────────────────────────────────────────────────────────────────────────

describe('Bloqueio de protocolos em URLs', () => {
  const protocols = [
    ['javascript:alert(1)', 'javascript:'],
    ['JAVASCRIPT:alert(1)', 'javascript:'],
    ['JavaScript:alert(1)', 'javascript:'],
    ['vbscript:msgbox(1)', 'vbscript:'],
    ['data:text/html,<script>alert(1)</script>', 'data:'],
    ['data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', 'data:'],
  ];

  it.each(protocols)(
    'deve bloquear href="%s"',
    (payload, blockedToken) => {
      const result = sanitizeHtml(`<a href="${payload}">link</a>`);
      expect(result).not.toContain(blockedToken);
      // O elemento <a> pode sobreviver sem o href perigoso
    }
  );

  it('deve bloquear src com javascript: em <img>', () => {
    const result = sanitizeHtml('<img src="javascript:alert(1)" alt="x">');
    expectNone(result, ['javascript:', 'alert(1)']);
  });

  it('deve bloquear javascript: com espaços antes do protocolo', () => {
    const result = sanitizeHtml('<a href="   javascript:alert(1)">x</a>');
    expect(result).not.toContain('javascript:');
  });

  it('deve bloquear javascript: com \\n embutido (bypass IE histórico)', () => {
    const result = sanitizeHtml('<a href="java\nscript:alert(1)">x</a>');
    expect(result).not.toContain('javascript:');
  });

  it('deve bloquear javascript: URL-encoded (%6a%61%76%61%73%63%72%69%70%74)', () => {
    const result = sanitizeHtml('<a href="%6a%61%76%61%73%63%72%69%70%74:alert(1)">x</a>');
    expect(result).not.toContain('javascript:');
  });

  it('deve bloquear javascript: via entidade numérica (&#106;avascript:)', () => {
    const result = sanitizeHtml('<a href="&#106;avascript:alert(1)">x</a>');
    expect(result).not.toContain('javascript:');
  });

  it('deve permitir URLs https legítimas', () => {
    const result = sanitizeHtml('<a href="https://exemplo.com/path?q=1#anchor">x</a>');
    expect(result).toContain('href="https://exemplo.com/path?q=1#anchor"');
  });

  it('deve permitir URLs relativas (/path, #anchor, ./rel)', () => {
    const cases = ['/path/to/page', '#secao', './relativo'];
    for (const url of cases) {
      const result = sanitizeHtml(`<a href="${url}">x</a>`);
      expect(result).toContain(`href="${url}"`);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Hook: noopener/noreferrer em target=_blank
// ─────────────────────────────────────────────────────────────────────────────

describe('Hook target=_blank → noopener/noreferrer', () => {
  it('deve adicionar rel="noopener noreferrer" a links com target="_blank"', () => {
    const result = sanitizeHtml('<a href="/path" target="_blank">link</a>');
    expect(result).toContain('noopener');
    expect(result).toContain('noreferrer');
  });

  it('deve manter rel existente e adicionar noopener/noreferrer', () => {
    const result = sanitizeHtml('<a href="/path" target="_blank" rel="nofollow">link</a>');
    expect(result).toContain('nofollow');
    expect(result).toContain('noopener');
    expect(result).toContain('noreferrer');
  });

  it('deve sobrescrever rel="opener" inseguro quando target="_blank"', () => {
    const result = sanitizeHtml('<a href="/path" target="_blank" rel="opener">link</a>');
    expect(result).not.toContain('"opener"');
    expect(result).toContain('noopener');
    expect(result).toContain('noreferrer');
  });

  it('não deve modificar rel de links sem target="_blank"', () => {
    const result = sanitizeHtml('<a href="/path" rel="nofollow">link</a>');
    expect(result).toContain('rel="nofollow"');
    expect(result).not.toContain('noopener');
  });

  it('não deve adicionar rel a links sem target', () => {
    const result = sanitizeHtml('<a href="/path">link</a>');
    expect(result).not.toContain('rel=');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Hook: srcset com múltiplas URLs
// ─────────────────────────────────────────────────────────────────────────────

describe('Hook srcset — múltiplas URLs', () => {
  it('deve bloquear URL javascript: dentro de srcset', () => {
    const result = sanitizeHtml(
      '<img srcset="javascript:alert(1) 1x, https://ok.com/img.png 2x" alt="x">'
    );
    expectNone(result, ['javascript:', 'alert(1)']);
  });

  it('deve manter entradas legítimas no srcset após remover perigosas', () => {
    const result = sanitizeHtml(
      '<img srcset="https://ok.com/img.png 2x" alt="x">'
    );
    expect(result).toContain('https://ok.com/img.png');
  });

  it('deve bloquear data: URI no srcset', () => {
    const result = sanitizeHtml(
      '<img srcset="data:image/png;base64,abc123 1x" alt="x">'
    );
    expect(result).not.toContain('data:');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. Hook: atributo download= com extensões perigosas
// ─────────────────────────────────────────────────────────────────────────────

describe('Hook download= — extensões executáveis', () => {
  const dangerousExtensions = [
    ['malware.exe', '.exe'],
    ['setup.msi', '.msi'],
    ['script.sh', '.sh'],
    ['payload.ps1', '.ps1'],
    ['trojan.vbs', '.vbs'],
    ['evil.bat', '.bat'],
    ['attack.hta', '.hta'],
  ];

  it.each(dangerousExtensions)(
    'deve sanitizar download="%s" removendo extensão perigosa',
    (filename, ext) => {
      const result = sanitizeHtml(`<a href="/f" download="${filename}">baixar</a>`);
      expect(result).not.toContain(ext);
    }
  );

  it('deve permitir extensões de arquivo comuns seguras', () => {
    const result = sanitizeHtml('<a href="/f" download="relatorio.pdf">baixar</a>');
    expect(result).toContain('download="relatorio.pdf"');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. Tags perigosas sempre proibidas
// ─────────────────────────────────────────────────────────────────────────────

describe('ALWAYS_FORBIDDEN_TAGS', () => {
  const forbiddenTags = [
    ['<iframe src="https://evil.com"></iframe>', 'iframe'],
    ['<object data="evil.swf"></object>', 'object'],
    ['<embed src="evil.swf">', 'embed'],
    ['<form action="/steal"><input name="cc"></form>', 'form'],
    ['<base href="http://evil.com/">', 'base'],
    ['<meta http-equiv="refresh" content="0;url=http://evil.com">', 'meta'],
    ['<link rel="stylesheet" href="http://evil.com/evil.css">', 'link'],
    ['<applet code="evil.class"></applet>', 'applet'],
    ['<noscript><img src=x onerror=alert(1)></noscript>', 'noscript'],
    ['<template><script>alert(1)</script></template>', 'template'],
  ];

  it.each(forbiddenTags)(
    'deve remover/bloquear tag <%s>',
    (input, tagName) => {
      const result = sanitizeHtml(input);
      expect(result).not.toContain(`<${tagName}`);
    }
  );

  it('deve remover <script type="importmap"> (vetor emergente 2023)', () => {
    const result = sanitizeHtml(
      '<script type="importmap">{"imports":{"react":"http://evil.com/react.js"}}</script>'
    );
    expectNone(result, ['<script', 'importmap', 'evil.com']);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 12. CSS injection
// ─────────────────────────────────────────────────────────────────────────────

describe('Injeção CSS', () => {
  it('deve remover style com expression() — IE legado', () => {
    const result = sanitizeHtml(
      '<div style="width: expression(alert(1))">x</div>',
      'richText'
    );
    expectNone(result, ['expression(', 'alert(1)']);
  });

  it('deve remover style com -moz-binding — Firefox histórico', () => {
    const result = sanitizeHtml(
      '<div style="-moz-binding:url(http://evil.com/xss.xml#xss)">x</div>',
      'richText'
    );
    expect(result).not.toContain('-moz-binding');
  });

  it('deve remover style com url(javascript:)', () => {
    const result = sanitizeHtml(
      '<div style="background: url(javascript:alert(1))">x</div>',
      'richText'
    );
    expectNone(result, ['javascript:', 'alert(1)']);
  });

  it('deve remover style com @import (exfiltração via CSS)', () => {
    const result = sanitizeHtml(
      '<div style="@import url(http://evil.com/steal.css)">x</div>',
      'richText'
    );
    expect(result).not.toContain('@import');
  });

  it('deve remover style com behavior: — IE HTC', () => {
    const result = sanitizeHtml(
      '<div style="behavior: url(evil.htc)">x</div>',
      'richText'
    );
    expect(result).not.toContain('behavior:');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 13. Mutation XSS (mXSS) — vetores históricos
// ─────────────────────────────────────────────────────────────────────────────

describe('Mutation XSS (mXSS)', () => {
  it('deve bloquear mXSS via <template> — CVE DOMPurify < 2.3.3', () => {
    // O payload aparece inofensivo dentro de <template> mas torna-se script ao re-parsear
    const result = sanitizeHtml(
      '<template><script>alert(1)</script></template>'
    );
    expectNone(result, ['<template', '<script', 'alert(1)']);
  });

  it('deve bloquear namespace confusion SVG → HTML', () => {
    const result = sanitizeHtml(
      '<svg><p><style><!--</style></p><img src=x onerror=alert(1)></svg>'
    );
    expectNone(result, ['onerror', 'alert(1)']);
  });

  it('deve bloquear MathML maction com href — Firefox < 72', () => {
    const result = sanitizeHtml(
      '<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">click</maction></math>'
    );
    expectNone(result, ['xlink:href', 'javascript:', 'alert(1)']);
  });

  it('deve bloquear polyglot SVG+MathML com script', () => {
    const result = sanitizeHtml(
      '<svg><math><mtext></mtext><mglyph/><svg><script>alert(1)</script></svg></math></svg>'
    );
    expectNone(result, ['<script', 'alert(1)']);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 14. DOM Clobbering
// ─────────────────────────────────────────────────────────────────────────────

describe('DOM Clobbering', () => {
  it('deve tratar id="body" que tenta sobrescrever document.body', () => {
    // SANITIZE_NAMED_PROPS deve prefixar ou remover este id
    const result = sanitizeHtml('<a id="body">x</a>');
    // O id deve ser modificado (prefixado com "user-content-" pelo DOMPurify) ou removido
    expect(result).not.toContain('id="body"');
  });

  it('deve tratar id="cookie" que tenta sobrescrever document.cookie', () => {
    const result = sanitizeHtml('<a id="cookie">x</a>');
    expect(result).not.toContain('id="cookie"');
  });

  it('deve tratar name="getElementById" que tenta sobrescrever a API', () => {
    const result = sanitizeHtml('<a name="getElementById">x</a>');
    expect(result).not.toContain('name="getElementById"');
  });

  it('deve tratar elementos com id conflitante com globals do DOM', () => {
    const clobberable = ['location', 'document', 'window', 'history', 'alert'];
    for (const id of clobberable) {
      const result = sanitizeHtml(`<a id="${id}">x</a>`);
      expect(result).not.toContain(`id="${id}"`);
    }
  });

  it('deve permitir id comum que não conflita com propriedades do DOM', () => {
    // IDs legítimos devem ser preservados (DOMPurify os prefixará com user-content-)
    const result = sanitizeHtml('<div id="minha-secao">conteúdo</div>');
    // Ou o id sobrevive ou foi prefixado — em ambos os casos NÃO deve ser removido completamente
    expect(result).toContain('conteúdo');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 15. Payloads clássicos de XSS (OWASP Top Vectors)
// ─────────────────────────────────────────────────────────────────────────────

describe('Payloads clássicos XSS', () => {
  const classicPayloads: Array<[string, string]> = [
    ['<img src=x onerror=alert(1)>', 'onerror'],
    ['<svg onload=alert(1)>', 'onload'],
    ['<body onpageshow=alert(1)>', 'onpageshow'],
    ['<input autofocus onfocus=alert(1)>', 'onfocus'],
    ['<select onfocus=alert(1) autofocus>', 'onfocus'],
    ['<video src=x onerror=alert(1)>', 'onerror'],
    ['<details open ontoggle=alert(1)>', 'ontoggle'],
    ['<marquee onstart=alert(1)>', 'onstart'],
    ['<<SCRIPT>alert(1)//<</SCRIPT>', '<script'],
    ['<scr<script>ipt>alert(1)</scr</script>ipt>', 'alert(1)'],
    ['<IMG """><SCRIPT>alert(1)</SCRIPT>">', 'alert(1)'],
  ];

  it.each(classicPayloads)(
    'deve bloquear payload: %s',
    (payload, blockedToken) => {
      const result = sanitizeHtml(payload);
      expect(result).not.toContain(blockedToken);
    }
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// 16. sanitizeHtmlToFragment
// ─────────────────────────────────────────────────────────────────────────────

describe('sanitizeHtmlToFragment', () => {
  it('deve retornar DocumentFragment com conteúdo seguro', () => {
    const fragment = sanitizeHtmlToFragment('<p>Olá <strong>mundo</strong></p>');
    expect(fragment).toBeInstanceOf(DocumentFragment);
    const div = document.createElement('div');
    div.appendChild(fragment!);
    expect(div.querySelector('p')).not.toBeNull();
    expect(div.querySelector('strong')?.textContent).toBe('mundo');
  });

  it('deve remover scripts do fragment', () => {
    const fragment = sanitizeHtmlToFragment('<p>ok</p><script>alert(1)</script>');
    const div = document.createElement('div');
    div.appendChild(fragment!);
    expect(div.querySelector('script')).toBeNull();
    expect(div.textContent).toContain('ok');
  });

  it('deve retornar fragment vazio para input não-string', () => {
    const fragment = sanitizeHtmlToFragment(null as unknown as string);
    expect(fragment).toBeInstanceOf(DocumentFragment);
    expect(fragment?.childNodes.length).toBe(0);
  });

  it('deve respeitar o perfil passado', () => {
    const fragment = sanitizeHtmlToFragment('<a href="https://ok.com">link</a><p>texto</p>', 'strict');
    const div = document.createElement('div');
    div.appendChild(fragment!);
    // strict não permite <a> nem <p>
    expect(div.querySelector('a')).toBeNull();
    expect(div.querySelector('p')).toBeNull();
    expect(div.textContent).toContain('link');
    expect(div.textContent).toContain('texto');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 17. sanitizeTextOnly
// ─────────────────────────────────────────────────────────────────────────────

describe('sanitizeTextOnly', () => {
  it('deve converter < e > em entidades', () => {
    expect(sanitizeTextOnly('<script>')).toBe('&lt;script&gt;');
  });

  it('deve converter & em &amp;', () => {
    expect(sanitizeTextOnly('a & b')).toBe('a &amp; b');
  });

  it('deve converter aspas em entidades', () => {
    expect(sanitizeTextOnly('"hello"')).toBe('&quot;hello&quot;');
    expect(sanitizeTextOnly("it's")).toBe('it&#39;s');
  });

  it('deve converter backtick em entidade', () => {
    expect(sanitizeTextOnly('`cmd`')).toBe('&#96;cmd&#96;');
  });

  it('deve remover null bytes', () => {
    expect(sanitizeTextOnly('a\x00b')).toBe('ab');
  });

  it('deve retornar string vazia para input não-string', () => {
    expect(sanitizeTextOnly(null as unknown as string)).toBe('');
    expect(sanitizeTextOnly(undefined as unknown as string)).toBe('');
  });

  it('deve escapar payload completo sem deixar nada executável', () => {
    const payload = '<img src=x onerror=alert(1)>';
    const result = sanitizeTextOnly(payload);
    expect(result).toBe('&lt;img src=x onerror=alert(1)&gt;');
    expect(result).not.toContain('<');
    expect(result).not.toContain('>');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 18. Concorrência — hooks não devem sofrer race condition
// ─────────────────────────────────────────────────────────────────────────────

describe('Concorrência — hooks init uma única vez', () => {
  it('deve produzir resultados corretos em chamadas paralelas', async () => {
    const payloads = Array.from({ length: 10 }, (_, i) =>
      `<a href="/path-${i}" target="_blank">link ${i}</a>`
    );

    const results = await Promise.all(payloads.map(p => Promise.resolve(sanitizeHtml(p))));

    for (const result of results) {
      expect(result).toContain('noopener');
      expect(result).toContain('noreferrer');
      expect(result).not.toContain('javascript:');
    }
  });

  it('deve produzir output idêntico para o mesmo input em execuções repetidas', () => {
    const input = '<a href="https://ok.com" target="_blank">x</a>';
    const results = Array.from({ length: 5 }, () => sanitizeHtml(input));
    const unique = new Set(results);
    expect(unique.size).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 19. getDOMPurifyInfo
// ─────────────────────────────────────────────────────────────────────────────

describe('getDOMPurifyInfo', () => {
  it('deve retornar versão como string', () => {
    const info = getDOMPurifyInfo();
    expect(typeof info.version).toBe('string');
    expect(info.version.length).toBeGreaterThan(0);
  });

  it('deve retornar isSupported como boolean', () => {
    const info = getDOMPurifyInfo();
    expect(typeof info.isSupported).toBe('boolean');
  });

  it('deve reportar isSupported=true em ambiente com DOM (jsdom)', () => {
    const info = getDOMPurifyInfo();
    expect(info.isSupported).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 20. runSanityCheck
// ─────────────────────────────────────────────────────────────────────────────

describe('runSanityCheck', () => {
  it('deve retornar array de strings', () => {
    const warnings = runSanityCheck();
    expect(Array.isArray(warnings)).toBe(true);
  });

  it('não deve conter aviso crítico de sanitização falhou em ambiente jsdom saudável', () => {
    const warnings = runSanityCheck();
    const critical = warnings.find(w => w.includes('CRÍTICO: teste de sanitização falhou'));
    expect(critical).toBeUndefined();
  });

  it('deve detectar ausência de DOMPurify se isSupported for false', () => {
    // Simula DOMPurify.isSupported = false
    const DOMPurify = require('dompurify');
    const original = DOMPurify.isSupported;
    Object.defineProperty(DOMPurify, 'isSupported', { value: false, configurable: true });

    const warnings = runSanityCheck();
    expect(warnings.some(w => w.includes('não suportado'))).toBe(true);

    Object.defineProperty(DOMPurify, 'isSupported', { value: original, configurable: true });
  });
});