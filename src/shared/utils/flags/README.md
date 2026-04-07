# Módulo de Feature Flags (flags)

## 1. Propósito

O módulo `flags` implementa o gerenciamento de *Feature Flags* (também conhecidas como *Feature Toggles*) e a capacidade de realizar testes A/B. Isso nos permite controlar a visibilidade de novas features em produção, sem a necessidade de um novo deploy.

Casos de uso principais:
- **Lançamentos Canary/Progressivos:** Liberar uma nova feature para um pequeno percentual de usuários (ex: 10%) e monitorar a estabilidade antes de liberar para todos.
- **Testes A/B:** Apresentar duas ou mais variantes de uma mesma feature (ex: dois textos diferentes em um botão de CTA) para grupos de usuários distintos e medir qual delas gera a melhor conversão.
- **Kill Switch:** Desativar rapidamente uma feature em produção caso um bug crítico seja descoberto.

## 2. Estrutura

- **`/providers`**: Adaptadores para serviços de Feature Flag de terceiros, como [GrowthBook](https://growthbook.io/), [LaunchDarkly](https://launchdarkly.com/), etc. Isso nos torna agnósticos à plataforma.

- **`/hooks`**: Hooks para verificar o estado de uma flag ou o valor de um experimento no código.
  - `useFlag('nova-feature-de-grafico')`: Retorna `true` ou `false`, indicando se a feature deve ser exibida para o usuário atual.
  - `useExperiment('hero-variant')`: Retorna o valor da variante que o usuário deve ver (ex: 'A', 'B', ou 'C').

- **`/experiments`**: Definição dos experimentos e testes A/B que estão em andamento. Cada arquivo descreve as variantes e a distribuição de tráfego.

- **`flags.ts`**: Um arquivo central que exporta todas as chaves de flags e experimentos como constantes. Isso evita "magic strings" espalhadas pelo código e facilita a busca por referências.

## 3. Fluxo

1.  **Inicialização:** O provedor de flags é inicializado na raiz da aplicação, buscando os valores atuais das flags do serviço externo.
2.  **Verificação:** Um componente usa o hook `useFlag` para decidir se renderiza uma nova funcionalidade.
3.  **Renderização Condicional:** O componente é renderizado (ou não) com base no valor retornado pelo hook.

## 4. Como Usar

**Exemplo: Lançando uma nova feature de forma controlada**

```jsx
import { useFlag } from '@flags/hooks';
import { FEATURE_NEW_DASHBOARD } from '@flags/flags';

// Componente antigo
import { OldDashboard } from './OldDashboard';
// Componente novo, ainda em teste
import { NewDashboard } from './NewDashboard';

const DashboardPage = () => {
  // A flag 'FEATURE_NEW_DASHBOARD' é controlada remotamente
  const isNewDashboardEnabled = useFlag(FEATURE_NEW_DASHBOARD);

  return isNewDashboardEnabled ? <NewDashboard /> : <OldDashboard />;
};
```