/**
 * @arquivo    sanitize/string.ts
 * @modulo     Utilitários / Sanitização
 * @descricao  Sanitiza strings removendo ou substituindo conteúdo potencialmente
 *             perigoso ou indesejado antes de armazenar, exibir ou enviar os
 *             dados. Complementa sanitize/html.ts com tratamentos específicos
 *             para texto puro, queries de banco, inputs de formulário e dados
 *             que serão interpolados em contextos diferentes.
 *
 * @exemplos_de_uso
 *   - sanitizarTexto("  Olá  Mundo  ")          → "Olá Mundo" (normaliza espaços)
 *   - removerCaracteresEspeciais("Ação$%@!")     → "Ação" (remove símbolos)
 *   - sanitizarParaSQL("'; DROP TABLE users;--")→ "\\'\\; DROP TABLE users\\;\\-\\-"
 *   - sanitizarParaURL("Meu Título Incrível")   → "Meu%20T%C3%ADtulo%20Incr%C3%ADvel"
 *   - sanitizarParaRegex("a.b*c?")              → "a\\.b\\*c\\?"
 *   - removerZeroWidth("te‍xt‍o")               → "texto" (remove zero-width chars)
 *   - normalizarEspacos("texto  com   espaços") → "texto com espaços"
 *   - sanitizarLDAP("user)(cn=*")               → "user\\29\\28cn\\3D\\2A"
 *
 * @tratamentos_especiais
 *   - String nula ou undefined → retorna string vazia ""
 *   - Apenas espaços/whitespace → retorna "" ou mantém conforme configuração
 *   - Caracteres de controle ASCII (0x00-0x1F) → removidos
 *   - Unicode RTL (Right-to-Left Override) → removidos para prevenir spoofing
 *   - Null bytes (\0) → removidos para prevenir injeção em sistemas C
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
