/**
 * @arquivo    parse/date.ts
 * @modulo     Utilitários / Parseamento
 * @descricao  Converte diferentes representações de datas (strings em formatos
 *             variados, timestamps numéricos, objetos Date) em instâncias
 *             padronizadas de Date ou em formatos intermediários para
 *             processamento interno. Opera no sentido inverso de format/date.ts,
 *             ou seja, transforma dados brutos (input do usuário, resposta de API)
 *             em objetos Date válidos para o JavaScript.
 *
 * @exemplos_de_uso
 *   - parsearData("02/04/2026")              → Date(2026, 3, 2)
 *   - parsearData("2026-04-02")              → Date(2026, 3, 2)
 *   - parsearData("2026-04-02T07:51:00.000Z")→ Date UTC válido
 *   - parsearTimestamp(1743572482314)        → Date correspondente
 *   - parsearTimestampSegundos(1743572482)   → Date correspondente
 *   - parsearDataHoraBR("02/04/2026 07:51")  → Date(2026, 3, 2, 7, 51)
 *   - tentarParsearData("não é data")        → null (retorna null se falhar)
 *
 * @tratamentos_especiais
 *   - String no formato errado → retorna null ou lança erro descritivo
 *   - Timestamp zero → retorna Date(0) = 01/01/1970 UTC
 *   - Timestamp negativo → retorna data antes de 1970 (válido)
 *   - String "Invalid Date" → retorna null imediatamente
 *   - Data com fuso horário explícito → preserva o offset fornecido
 *   - Data de 29/02 em ano não bissexto → retorna null com mensagem de erro
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
