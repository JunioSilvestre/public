/**
 * @arquivo    transform/apiToClient.ts
 * @modulo     Utilitários / Transformação de Dados
 * @descricao  Transforma dados recebidos da API (snake_case, estrutura de banco,
 *             timestamps Unix, valores em centavos, etc.) no formato esperado
 *             pelo cliente/interface (camelCase, objetos tipados, datas como Date,
 *             valores monetários como float, etc.). Atua como camada de adaptação
 *             (Adapter Pattern) entre a API REST e os modelos de domínio do frontend,
 *             isolando o restante da aplicação das peculiaridades do contrato da API.
 *
 * @exemplos_de_uso
 *   - entrada API:    { user_id: 1, first_name: "João", created_at: 1743572482 }
 *     saída cliente: { userId: 1, firstName: "João", createdAt: Date }
 *
 *   - entrada API:    { price_in_cents: 1999, is_active: 1 }
 *     saída cliente: { price: 19.99, isActive: true }
 *
 *   - entrada API:    { items: [{ product_id: 5, qty: 2 }] }
 *     saída cliente: { items: [{ productId: 5, qty: 2 }] }
 *
 * @transformacoes_padrao
 *   - snake_case → camelCase em todas as chaves do objeto
 *   - Timestamps Unix (segundos) → objetos Date
 *   - Timestamps ISO 8601 string → objetos Date
 *   - Valores em centavos (inteiro) → valores em reais (float)
 *   - Inteiros booleanos (0/1) → booleans (false/true)
 *   - Arrays aninhados → transformados recursivamente
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
