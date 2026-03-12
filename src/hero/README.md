# Módulo da Seção Hero

## 1. Propósito

A seção "Hero" é a área de conteúdo mais proeminente e de maior impacto visual, localizada no topo da página inicial (ou de outras páginas de destino importantes). Seu objetivo é capturar a atenção do usuário imediatamente, comunicar a proposta de valor principal da empresa e guiá-lo para uma ação primária (CTA - Call to Action).

Dada a sua importância para a primeira impressão e para a conversão, este módulo encapsula todos os elementos e variações complexas que podem compor uma seção Hero.

## 2. Estrutura

- **`/components`**: Os blocos de construção da seção Hero.
  - `HeroHeadline.tsx`: O título principal, geralmente grande e impactante.
  - `HeroSubtitle.tsx`: O texto de apoio que elabora a proposta de valor.
  - `HeroCta.tsx`: O botão de ação principal (ex: "Comece Agora", "Agende uma Demo").
  - `HeroBackground.tsx`: Componente para gerenciar fundos complexos, como vídeos, imagens ou gradientes animados.
  - `HeroTrustBar.tsx`: Uma barra com logos de clientes ou parceiros para gerar prova social e confiança.

- **`/animations`**: Lógicas de animação para os elementos do Hero, como animações de entrada (`entrance.ts`) ou efeitos de texto (`textReveal.ts`). Usar animações de forma intencional pode aumentar o engajamento.

- **`/hooks`**: Hooks para lógicas interativas.
  - `useCountUp.ts`: Anima um número de 0 até um valor final, usado para exibir estatísticas de forma dinâmica (ex: "+ de 10.000 clientes").
  - `useParallax.ts`: Aplica um efeito de paralaxe a elementos do fundo conforme o usuário rola a página.

- **`/variants`**: Diferentes layouts completos para a seção Hero, permitindo testes A/B ou uso em diferentes contextos.
  - `Centered.tsx`: Layout clássico com todo o conteúdo centralizado.
  - `SplitWithChart.tsx`: Layout dividido, com texto de um lado e uma visualização gráfica (como um mini-gráfico) do outro.
  - `VideoFull.tsx`: Layout imersivo com um vídeo de fundo em tela cheia.

## 3. Como Usar

O componente `Hero` é tipicamente o primeiro elemento dentro do `main` da página inicial.

```jsx
// Em src/pages/HomePage.tsx

import { Hero } from '@hero';
import { PublicLayout } from '@layouts';

const HomePage = () => {
  return (
    <PublicLayout>
      <Hero variant="SplitWithChart" />
      {/* ... resto do conteúdo da página */}
    </PublicLayout>
  );
};
```