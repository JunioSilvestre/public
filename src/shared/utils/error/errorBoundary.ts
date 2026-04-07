/**
 * @arquivo    error/errorBoundary.ts
 * @modulo     Utilitários / Tratamento de Erros
 * @descricao  Utilitários de suporte ao Error Boundary do React, incluindo
 *             helpers para captura, formatação e reporte de erros não tratados
 *             na árvore de componentes. Define também tipos e interfaces
 *             utilizados pelo componente ErrorBoundary e pelo handler global
 *             de erros (window.onerror, unhandledrejection).
 *
 * @funcionalidades
 *   - formatarErro(erro):           serializa o objeto Error para log estruturado
 *   - reportarErro(erro, contexto): envia erro para serviço de monitoramento
 *   - ehErroDeRede(erro):           retorna true para erros de conectividade
 *   - ehErroDeChunk(erro):          detecta erros de carregamento de chunk (lazy)
 *   - extrairMensagemAmigavel(erro): converte erros técnicos em mensagem ao usuário
 *
 * @estrutura_log_erro
 *   {
 *     mensagem: "Cannot read properties of null",
 *     stack: "...",
 *     componentePai: "ProductList",
 *     rota: "/produtos",
 *     timestamp: "2026-04-02T07:51:22Z",
 *     usuarioId: "usr_123" | null,
 *     buildVersion: "1.0.0"
 *   }
 *
 * @tratamentos_especiais
 *   - ChunkLoadError → sugere recarregar a página (deploy novo)
 *   - NetworkError   → sugere verificar conexão com a internet
 *   - TypeError null → mensagem genérica sem expor stack trace ao usuário
 *   - Erros durante SSR → capturados separadamente sem quebrar hidratação
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
