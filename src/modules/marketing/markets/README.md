# Módulo de Mercados (Markets)

## 1. Propósito

O módulo `markets` é um exemplo de um **módulo de feature vertical**. Ele encapsula toda a funcionalidade relacionada à exibição de dados de mercados financeiros, como preços de ações, pares de moedas, e criptoativos.

Centralizar essa funcionalidade complexa em um único módulo permite que a equipe de "Mercados" trabalhe de forma independente, com seus próprios componentes, hooks e serviços, sem interferir em outras partes da aplicação.

## 2. Estrutura

- **`/components`**: Componentes de UI específicos para exibir dados de mercado.
  - `MarketOverview.tsx`: Um widget que mostra um resumo do estado do mercado.
  - `TopMovers.tsx`: Lista os ativos com as maiores altas e baixas do dia.
  - `PriceChange.tsx`: Um componente pequeno que exibe uma mudança de preço, colorindo-a de verde (alta) ou vermelho (baixa).
  - `HeatMap.tsx`: Visualização em mapa de calor da performance de diferentes setores ou ativos.

- **`/hooks`**: Lógica de estado para buscar e atualizar os dados de mercado.
  - `useMarketData.ts`: Busca os dados iniciais de uma API REST.
  - `useLivePrices.ts` e `useWebSocket.ts`: Estabelece uma conexão WebSocket com um provedor de dados de mercado para receber atualizações de preço em tempo real.

- **`/services`**: Camada de abstração para a comunicação com as fontes de dados.
  - `market-api.ts`: Funções para chamar os endpoints da API de mercado.
  - `websocket-client.ts`: Lógica para gerenciar a conexão WebSocket (conectar, desconectar, tratar mensagens).
  - `price-formatter.ts`: Utilitários para formatar preços com a precisão e a moeda corretas.

- **`/variants`**: Diferentes formas de apresentar os dados de mercado.
  - `GridCards.tsx`: Exibe os ativos em um layout de cartões.
  - `CompactTable.tsx`: Exibe os ativos em uma tabela densa.

- **`__tests__`**: Testes para a lógica de formatação de preços e para a simulação (`mock`) do WebSocket.

## 3. Como Usar

Uma página pode compor diferentes componentes deste módulo para criar uma visão completa do mercado.

```jsx
// Em uma página como /pages/MarketOverviewPage.tsx

import { PublicLayout } from '@layouts';
import { MarketOverview, TopMovers } from '@markets/components';

const MarketOverviewPage = () => {
  return (
    <PublicLayout>
      <h1>Visão Geral do Mercado</h1>
      <MarketOverview />
      
      <h2>Principais Movimentações</h2>
      <TopMovers />
    </PublicLayout>
  );
};
```