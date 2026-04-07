# Módulo de Preços (Pricing)

## 1. Propósito

O módulo `pricing` é uma feature de negócio vertical responsável por exibir os planos, preços e funcionalidades de cada um dos nossos produtos ou serviços. É uma das páginas mais importantes para a conversão de novos clientes.

Centralizar essa lógica em um módulo nos permite:
- Realizar testes A/B com diferentes estruturas de preço facilmente.
- Atualizar os preços e funcionalidades em um único lugar.
- Garantir uma apresentação clara e consistente dos planos.

## 2. Estrutura

- **`/components`**: Componentes de UI para construir a página de preços.
  - `PricingTable.tsx`: O componente principal que renderiza a tabela ou os cartões de preços.
  - `PlanCard.tsx`: Renderiza um único plano (ex: Básico, Pro, Enterprise) com seu preço, lista de funcionalidades e botão de CTA.
  - `PlanFeature.tsx`: Um pequeno componente para exibir uma linha na lista de funcionalidades, talvez com um ícone de "check".
  - `BillingCycleToggle.tsx`: O seletor que permite ao usuário alternar entre o faturamento mensal e anual, geralmente mostrando um desconto para o plano anual.

- **`/hooks`**: Hooks que gerenciam a lógica da página.
  - `usePricingData.ts`: Busca os dados dos planos de uma API ou de um arquivo local. Isso permite que os preços sejam alterados remotamente sem um novo deploy.
  - `useBillingCycle.ts`: Gerencia o estado do seletor de ciclo de faturamento (mensal/anual).

- **`/data`**: Arquivos (JSON ou TS) que contêm os dados dos planos. Separar os dados da UI é uma boa prática que facilita a manutenção.
  - `plans.json`: Um array de objetos, onde cada objeto descreve um plano, seus preços (mensal e anual) e a lista de funcionalidades.

- **`/variants`**: Diferentes layouts para a apresentação dos preços.
  - `Cards.tsx`: O layout mais comum, com cada plano em um cartão lado a lado.
  - `Table.tsx`: Um layout de tabela comparativa, útil para um grande número de funcionalidades.

- **`PricingFeature.tsx`**: O componente "orquestrador" que une todos os outros componentes, hooks e dados para formar a feature de preços completa.

## 3. Como Usar

A página de preços (`pages/pricing.tsx`) simplesmente importa e renderiza o componente `PricingFeature`.

```jsx
// Em src/pages/pricing.tsx

import { PublicLayout } from '@layouts';
import { PricingFeature } from '@pricing';

const PricingPage = () => {
  return (
    <PublicLayout>
      <PricingFeature />
    </PublicLayout>
  );
};

export default PricingPage;
```