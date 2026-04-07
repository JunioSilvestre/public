/**
 * @arquivo    transform/clientToApi.ts
 * @modulo     Utilitários / Transformação de Dados
 * @descricao  Transforma dados do cliente/interface (camelCase, objetos Date,
 *             valores monetários em float, booleans, etc.) no formato esperado
 *             pela API (snake_case, timestamps Unix, valores em centavos,
 *             inteiros booleanos, etc.). Atua como a operação inversa de
 *             apiToClient.ts, preparando os dados do frontend para envio
 *             via requisições HTTP (POST, PUT, PATCH).
 *
 * @exemplos_de_uso
 *   - entrada cliente: { userId: 1, firstName: "João", createdAt: new Date() }
 *     saída API:       { user_id: 1, first_name: "João", created_at: 1743572482 }
 *
 *   - entrada cliente: { price: 19.99, isActive: true }
 *     saída API:       { price_in_cents: 1999, is_active: 1 }
 *
 *   - entrada cliente: { items: [{ productId: 5, qty: 2 }] }
 *     saída API:       { items: [{ product_id: 5, qty: 2 }] }
 *
 * @transformacoes_padrao
 *   - camelCase → snake_case em todas as chaves do objeto
 *   - Objetos Date → timestamps Unix em segundos (inteiro)
 *   - Valores monetários em reais (float) → centavos (inteiro)
 *   - Booleans (true/false) → inteiros (1/0)
 *   - Arrays aninhados → transformados recursivamente
 *   - Valores undefined/null → omitidos do payload ou enviados como null
 *
 * @observacoes
 *   - Nunca enviar campos de senha ou tokens em texto plano (usar hash/encrypt antes)
 *   - Campos somente leitura do servidor (id, createdAt) devem ser omitidos
 *     nos payloads de criação (POST)
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
