/**
 * @arquivo    helpers/deepClone.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Realiza a clonagem profunda (deep clone) de objetos e arrays
 *             JavaScript/TypeScript, criando uma cópia completamente independente
 *             da referência original. Evita mutações indesejadas em objetos
 *             compartilhados no estado da aplicação (ex: React state, Redux store).
 *             Suporta objetos aninhados, arrays, primitivos, Date, Map, Set
 *             e tipos especiais do JavaScript.
 *
 * @exemplos_de_uso
 *   - const copia = deepClone({ a: 1, b: { c: 2 } });
 *     copia.b.c = 99; // objeto original não é alterado
 *
 *   - const copiaArray = deepClone([{ id: 1 }, { id: 2 }]);
 *
 *   - const copiaComData = deepClone({ criado: new Date() });
 *     // copiaComData.criado é um novo objeto Date, não a mesma referência
 *
 * @casos_suportados
 *   - Objetos simples (plain objects): ✅
 *   - Arrays aninhados: ✅
 *   - Date: ✅ (clona como novo Date com mesmo valor)
 *   - Map e Set: ✅
 *   - Primitivos (string, number, boolean, null, undefined): ✅ (retorna o próprio valor)
 *   - Referências circulares: ⚠️ detecta e lança erro descritivo
 *   - Funções: ⚠️ não clona, mantém referência da função original
 *   - Símbolos e propriedades não enumeráveis: ❌ não clonados
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
