/**
 * @arquivo    format/string.ts
 * @modulo     Utilitários / Formatação
 * @descricao  Coleção de funções para manipulação e formatação de strings
 *             para exibição na interface. Abrange capitalização, truncagem,
 *             geração de slugs, ocultação parcial de dados sensíveis,
 *             pluralização e outras transformações textuais comuns.
 *
 * @exemplos_de_uso
 *   - capitalizarPrimeira("hello world")    → "Hello world"
 *   - capitalizarTodas("joao da silva")     → "João Da Silva"
 *   - truncar("Texto muito longo", 10)      → "Texto mu..."
 *   - gerarSlug("Meu Artigo Incrível!")    → "meu-artigo-incrivel"
 *   - ocultarEmail("user@example.com")     → "us**@example.com"
 *   - ocultarCPF("123.456.789-01")         → "***.***.789-01"
 *   - ocultarCartao("5500000000000004")     → "**** **** **** 0004"
 *   - pluralizar(1, "item", "itens")       → "1 item"
 *   - pluralizar(5, "item", "itens")       → "5 itens"
 *   - removerAcentos("ação")               → "acao"
 *   - contarPalavras("Olá mundo")          → 2
 *   - inverterString("ABC")                → "CBA"
 *
 * @tratamentos_especiais
 *   - String nula ou undefined → retorna string vazia ""
 *   - String apenas com espaços → trata como vazia quando aplicável
 *   - Caracteres especiais em slugs → removidos ou substituídos por hífen
 *   - Emojis e caracteres Unicode → preservados em operações que não sejam slug
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
