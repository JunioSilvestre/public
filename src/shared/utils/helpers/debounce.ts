/**
 * @arquivo    helpers/debounce.ts
 * @modulo     Utilitários / Auxiliares
 * @descricao  Implementação da técnica de debounce para controle de frequência
 *             de execução de funções. O debounce adia a execução de uma função
 *             até que um determinado tempo de inatividade seja atingido após
 *             a última chamada. Ideal para evitar chamadas excessivas de API
 *             durante a digitação do usuário (busca em tempo real), redimensionamento
 *             de janela ou outros eventos disparados em alta frequência.
 *
 * @exemplos_de_uso
 *   - Busca em tempo real: aguarda 300ms após o usuário parar de digitar
 *     const buscarDebounced = debounce(buscarAPI, 300);
 *     input.addEventListener('input', (e) => buscarDebounced(e.target.value));
 *
 *   - Salvamento automático: aguarda 1s de inatividade antes de salvar
 *     const salvarDebounced = debounce(salvarRascunho, 1000);
 *
 *   - Redimensionamento: recalcula layout apenas quando janela para de mudar
 *     const recalcularDebounced = debounce(recalcularLayout, 200);
 *
 * @parametros
 *   - fn: função a ser controlada
 *   - espera: tempo em milissegundos de inatividade necessário (padrão: 300ms)
 *   - imediato: se true, executa na primeira chamada e ignora as seguintes
 *
 * @retorno
 *   Função encapsulada com os mesmos parâmetros da função original, além de
 *   método .cancelar() para cancelar a execução pendente se necessário.
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
