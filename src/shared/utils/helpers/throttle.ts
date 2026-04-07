/**
 * @arquivo    helpers/throttle.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Implementação da técnica de throttle para limitação de taxa de
 *             execução de funções. O throttle garante que uma função seja
 *             executada no máximo uma vez a cada intervalo de tempo definido,
 *             independentemente de quantas vezes for chamada nesse período.
 *             Diferente do debounce (que aguarda inatividade), o throttle
 *             executa periodicamente enquanto as chamadas continuam chegando.
 *
 * @diferenca_debounce_vs_throttle
 *   - Debounce: aguarda parar de chamar e então executa UMA vez no final
 *   - Throttle: executa periodicamente (a cada N ms) enquanto há chamadas
 *
 * @exemplos_de_uso
 *   - Scroll infinito: verifica posição do scroll no máximo a cada 100ms
 *     const verificarScroll = throttle(carregarMaisPaginas, 100);
 *     window.addEventListener('scroll', verificarScroll);
 *
 *   - Rastreamento de mouse: atualiza posição no máximo a cada 50ms
 *     const rastrearMouse = throttle(atualizarPosicao, 50);
 *
 *   - Animações: limita atualizações de frame a 60fps (16ms)
 *     const animar = throttle(atualizarAnimacao, 16);
 *
 *   - Rate limiting de cliques: evita múltiplos envios de formulário
 *     const enviarFormulario = throttle(submitForm, 2000);
 *
 * @parametros
 *   - fn: função a ser limitada em taxa de execução
 *   - intervalo: tempo mínimo em millisegundos entre execuções (padrão: 100ms)
 *
 * @retorno
 *   Função encapsulada com método .cancelar() para limpar o timer interno.
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
