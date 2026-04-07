# Módulo de Performance

## 1. Propósito

O módulo `performance` centraliza as ferramentas e lógicas que usamos para medir e otimizar a velocidade de carregamento e a responsividade da nossa aplicação. Em um mercado competitivo, uma aplicação rápida é fundamental para reter usuários e melhorar o ranking em mecanismos de busca (SEO).

Este módulo nos ajuda a implementar as melhores práticas de performance web de forma consistente.

## 2. Estrutura

- **`/monitoring`**: Lógica para medir as métricas de performance no navegador do usuário e enviá-las para um serviço de monitoramento.
  - `web-vitals.ts`: Implementa a medição dos [Core Web Vitals](https://web.dev/vitals/) do Google (LCP, FID, CLS), que são métricas essenciais para a experiência do usuário.
  - `reporter.ts`: Envia os dados coletados para um serviço de analytics ou de monitoramento de performance.

- **`/hooks`**: Hooks que ajudam a implementar padrões de otimização de performance.
  - `useLazyLoad.ts`: Um hook que pode ser usado para adiar o carregamento de componentes ou imagens que estão fora da tela inicial (below the fold), economizando a banda do usuário e acelerando o carregamento inicial.
  - `useWebVitals.ts`: Um hook que pode ser usado para facilmente registrar e reportar as métricas de Web Vitals de uma página.

- **`/images`**: Utilitários para otimização de imagens.
  - `loader.ts`: Pode conter uma lógica de loader customizada para um serviço de otimização de imagens (como Cloudinary ou Imgix), ou para o otimizador de imagens do próprio Next.js.
  - `lazy.ts`: Componentes ou lógicas para implementar o carregamento preguiçoso (lazy loading) de imagens.

## 3. Como Usar

### Monitoramento de Web Vitals

O monitoramento geralmente é ativado no `_app.tsx` para cobrir toda a aplicação.

```jsx
// Em src/pages/_app.tsx

import { useEffect } from 'react';
import { reportWebVitals } from '@performance/monitoring/reporter';

function MyApp({ Component, pageProps }) {
  useEffect(() => {
    // Ativa o monitoramento assim que a aplicação carrega
    reportWebVitals(console.log); // Em um caso real, enviaria para um serviço de analytics
  }, []);

  return <Component {...pageProps} />;
}
```

### Lazy Loading de Componentes

O React e o Next.js já oferecem ótimas APIs para isso (`React.lazy` e `next/dynamic`), e nossos hooks podem simplificar ainda mais o processo.

```jsx
import React, { Suspense } from 'react';
import { useLazyLoad } from '@performance/hooks';

// O componente pesado que queremos carregar sob demanda
const HeavyComponent = React.lazy(() => import('./HeavyComponent'));

const MyPage = () => {
  const { ref, isVisible } = useLazyLoad();

  return (
    <div ref={ref}>
      {/* O Suspense mostra um fallback enquanto o componente não carrega */}
      {isVisible && (
        <Suspense fallback={<div>Carregando...</div>}>
          <HeavyComponent />
        </Suspense>
      )}
    </div>
  );
};
```