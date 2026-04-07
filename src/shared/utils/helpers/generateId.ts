/**
 * @arquivo    helpers/generateId.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Fornece funções para geração de identificadores únicos (IDs)
 *             no lado do cliente. Útil para criar chaves de componentes React
 *             (key prop), IDs temporários de elementos de lista antes da
 *             confirmação do servidor, identificadores de sessão locais
 *             e tokens de correlação para rastreamento de operações.
 *
 * @exemplos_de_uso
 *   - gerarUUID()              → "f47ac10b-58cc-4372-a567-0e02b2c3d479" (UUID v4)
 *   - gerarIdCurto()           → "k7x2m9" (6 caracteres alfanuméricos)
 *   - gerarIdCurto(8)          → "k7x2m9ab" (8 caracteres alfanuméricos)
 *   - gerarIdNumerico()        → 1743572482314 (timestamp + random)
 *   - gerarIdPrefixado("usr")  → "usr_k7x2m9ab"
 *   - gerarNanocol()           → ID compacto baseado em tempo + aleatoriedade
 *
 * @seguranca
 *   - Para IDs de segurança (tokens, CSRF) utilize crypto.randomUUID() diretamente
 *     ou a função gerarUUID() que usa a Web Crypto API.
 *   - gerarIdCurto() NÃO é criptograficamente seguro — use apenas para UI.
 *
 * @garantia_de_unicidade
 *   - gerarUUID(): unicidade global garantida pela especificação UUID v4
 *   - gerarIdCurto(): colisão improvável para uso em UI; não usar como PK de banco
 *   - gerarIdNumerico(): colisão possível em ambiente multithread ou alta frequência
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
