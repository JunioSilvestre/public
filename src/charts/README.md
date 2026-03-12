# Módulo de Gráficos (Charts)

## 1. Propósito

O módulo `charts` fornece um conjunto de componentes reutilizáveis para a visualização de dados financeiros e de mercado. O objetivo é abstrair a complexidade das bibliotecas de gráficos (como Recharts ou TradingView) e fornecer uma API simples e consistente para o resto da aplicação.

Isso nos permite manter um estilo visual unificado, otimizar a performance e, se necessário, trocar a biblioteca de gráficos subjacente sem ter que refatorar todas as páginas que exibem um gráfico.

## 2. Estrutura

- **`/components`**: Os componentes de gráfico que são diretamente consumidos pela aplicação. Ex: `LineChart`, `BarChart`, `CandlestickChart`.
  - Cada componente é responsável por renderizar o gráfico e elementos associados, como `ChartTooltip` (dica de ferramenta customizada) e `ChartLegend` (legenda).
  - Componentes como `ChartSkeleton` são usados para exibir um estado de carregamento elegante.

- **`/hooks`**: Hooks que gerenciam a lógica de estado e a busca de dados para os gráficos.
  - `useChartData`: Hook para buscar e processar os dados a serem exibidos no gráfico, possivelmente se conectando a uma API de mercado.
  - `useTimeframe`: Gerencia a seleção de período de tempo (ex: 1D, 1M, 1Y) e atualiza os dados de acordo.

- **`/utils`**: Funções puras para formatação e transformação de dados.
  - `formatters.ts`: Funções para formatar valores monetários, datas e percentuais de acordo com a localidade do usuário.
  - `ohlc-transform.ts`: Lógica para transformar dados de séries temporais em formatos OHLC (Open-High-Low-Close) para gráficos de velas (candlestick).

- **`/adapters`**: Camada de abstração que "traduz" as props dos nossos componentes para a API específica da biblioteca de gráficos sendo utilizada (ex: `recharts.ts`).

- **`__tests__`**: Testes unitários para os componentes e principalmente para os formatadores e transformadores de dados, que são lógicas críticas.

## 3. Como Usar

Para renderizar um gráfico de linha simples, o consumo seria direto:

```jsx
import { LineChart } from '@charts/components';
import { useChartData } from '@charts/hooks';

const StockPriceChart = ({ symbol }) => {
  const { data, isLoading, error } = useChartData(symbol, '1M');

  if (isLoading) return <ChartSkeleton />;
  if (error) return <ChartError message={error.message} />;

  return (
    <LineChart 
      data={data}
      dataKey="price"
      xAxisKey="date"
      height={400}
    />
  );
};
```