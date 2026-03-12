# Módulo de Fallbacks

## 1. Propósito

O módulo `fallbacks` é responsável por gerenciar e exibir os estados de UI "não ideais". Ele garante que a experiência do usuário seja graciosa e informativa mesmo quando ocorrem erros, o conteúdo está carregando ou a página não é encontrada.

Uma aplicação robusta não é aquela que nunca falha, mas aquela que lida com as falhas de forma elegante. Este módulo é a nossa rede de segurança para a experiência do usuário.

## 2. Estrutura

- **`ErrorBoundary.tsx`**: Um componente que "captura" erros de renderização em qualquer parte da sua árvore de componentes filhos. Em vez de a aplicação inteira quebrar (tela branca), o `ErrorBoundary` renderiza uma UI de erro amigável, como o componente `ErrorPage`.

- **`ErrorPage.tsx`**: Uma página de erro genérica e reutilizável, que pode ser customizada com uma mensagem e ações (como "Tentar novamente" ou "Voltar para a Home").

- **`NotFound.tsx` / `NotFoundPage.tsx`**: Componente ou página completa para ser exibida quando o usuário acessa uma rota que não existe (Erro 404).

- **`PageLoader.tsx`**: Um indicador de carregamento em tela cheia, para ser usado durante transições de página ou carregamento inicial de dados críticos.

- **Componentes de Skeleton (`SkeletonCard.tsx`, `SkeletonChart.tsx`, etc.)**: Placeholders que imitam a estrutura da UI final. Eles são exibidos enquanto o conteúdo real está sendo carregado, melhorando a percepção de performance em comparação com um spinner genérico.

## 3. Como Usar

### ErrorBoundary

Você deve envolver seções da sua aplicação (ou a aplicação inteira) com o `ErrorBoundary`.

```jsx
// No arquivo _app.tsx ou em um layout principal

import { ErrorBoundary } from '@fallbacks/components';
import { ErrorPage } from '@fallbacks/components';

function MyApp({ Component, pageProps }) {
  return (
    <ErrorBoundary fallback={<ErrorPage />}>
      <Component {...pageProps} />
    </ErrorBoundary>
  );
}
```

### Skeletons

Use os componentes de Skeleton dentro das suas features enquanto os dados estão sendo buscados.

```jsx
import { useMyData } from './hooks';
import { MyDataCard } from './components';
import { SkeletonCard } from '@fallbacks/components';

const MyFeature = () => {
  const { data, isLoading } = useMyData();

  if (isLoading) {
    return <SkeletonCard />;
  }

  return <MyDataCard data={data} />;
};
```