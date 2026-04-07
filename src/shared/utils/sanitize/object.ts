/**
 * @arquivo    sanitize/object.ts
 * @modulo     Utilitários / Sanitização
 * @descricao  Sanitiza objetos JavaScript removendo chaves desnecessárias,
 *             filtrando valores nulos/undefined, normalizando propriedades
 *             e prevenindo poluição de protótipo (__proto__, constructor,
 *             prototype) em payloads recebidos de fontes externas (APIs,
 *             formulários, parâmetros de URL). Garante que apenas dados
 *             esperados e seguros cheguem às camadas de negócio.
 *
 * @exemplos_de_uso
 *   - removerNulos({ a: 1, b: null, c: undefined }) → { a: 1 }
 *   - removerVazios({ a: 1, b: "", c: "  " })        → { a: 1 }
 *   - permitirChaves({a:1, b:2, c:3}, ["a","c"])      → { a: 1, c: 3 }
 *   - bloquearChaves({a:1, senha:"123"}, ["senha"])   → { a: 1 }
 *   - sanitizarPrototipo({__proto__:{x:1}})           → {} (ataque removido)
 *   - aplanarObjeto({a:{b:{c:1}}})                   → {"a.b.c": 1}
 *   - compactarObjeto({"a.b.c": 1})                  → {a:{b:{c:1}}}
 *
 * @prevencao_prototype_pollution
 *   Chaves como __proto__, constructor e prototype são removidas antes
 *   de qualquer processamento, prevenindo ataques de poluição de protótipo
 *   que poderiam comprometer objetos globais da aplicação.
 *
 * @tratamentos_especiais
 *   - Valor null/undefined como input → retorna objeto vazio {}
 *   - Arrays como input → processa cada elemento individualmente
 *   - Objetos aninhados → sanitização recursiva quando solicitada
 *   - Chaves com XSS no nome → escapadas ou removidas
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
