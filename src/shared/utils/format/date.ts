/**
 * @arquivo    format/date.ts
 * @modulo     Utilitários / Formatação
 * @descricao  Responsável pela formatação de datas e horas para exibição ao
 *             usuário. Converte objetos Date, timestamps Unix (em ms ou s) e
 *             strings ISO 8601 nos formatos visuais utilizados pela aplicação,
 *             respeitando o fuso horário e a localidade configurada (padrão pt-BR).
 *
 * @exemplos_de_uso
 *   - formatarData(new Date())          → "02/04/2026"
 *   - formatarDataHora(new Date())      → "02/04/2026 07:51"
 *   - formatarDataHoraCompleta(date)    → "02/04/2026 07:51:22"
 *   - formatarDataRelativa(date)        → "há 3 horas" | "ontem" | "há 5 dias"
 *   - formatarDiaSemana(date)           → "Quarta-feira"
 *   - formatarMesAno(date)             → "Abril de 2026"
 *   - formatarDataCurta(date)          → "02 abr. 2026"
 *   - dataParaISO(date)                → "2026-04-02T07:51:22.000Z"
 *
 * @tratamentos_especiais
 *   - Data nula ou undefined → retorna string vazia ou traço "-"
 *   - Data inválida (Invalid Date) → retorna "Data inválida"
 *   - Timestamp no passado distante ou futuro → formata normalmente sem erro
 *   - Datas em outros fusos horários → normaliza para o fuso local antes de formatar
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
