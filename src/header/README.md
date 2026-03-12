# Módulo do Cabeçalho (Header)

## 1. Propósito

O `header` é um dos módulos mais críticos da aplicação. Ele é responsável pela identidade visual (logo), navegação principal, e pontos de entrada para ações importantes como login/cadastro e troca de idioma ou tema.

Sua complexidade justifica um módulo dedicado para garantir que a experiência seja consistente, performática e acessível em todas as páginas.

## 2. Estrutura

- **`/components`**: Componentes que compõem o cabeçalho.
  - `Logo.tsx`: Exibe o logo da empresa, que também serve como link para a home.
  - `NavBar.tsx` e `NavItem.tsx`: A barra de navegação principal para desktop.
  - `MegaMenu.tsx`: Componente para menus suspensos complexos, com múltiplas colunas e links.
  - `MobileNav.tsx` e `MobileNavToggle.tsx`: A navegação otimizada para dispositivos móveis, geralmente dentro de um menu "hambúrguer".
  - `MarketTickerBar.tsx`: Uma barra que pode exibir cotações de mercado em tempo real, comum em sites financeiros.
  - `AuthCtaBtn.tsx`: Botão de Call-to-Action para "Login" ou "Abrir Conta".

- **`/hooks`**: Lógica de estado e de interação para o cabeçalho.
  - `useScrollBehavior`: Hook que detecta a posição do scroll da página para aplicar efeitos como "cabeçalho fixo" (sticky) ou "esconder ao rolar para baixo".
  - `useMobileNav`: Gerencia o estado de aberto/fechado do menu móvel.
  - `useLiveTicker`: Conecta-se a um serviço (WebSocket, por exemplo) para obter os dados do `MarketTickerBar`.

- **`/data`**: Dados que alimentam a navegação, como a lista de links.

- **`/variants`**: Diferentes estilos de cabeçalho para diferentes contextos.
  - `Sticky.tsx`: Cabeçalho que permanece fixo no topo da página.
  - `Transparent.tsx`: Cabeçalho com fundo transparente, para ser usado sobre uma imagem de herói, por exemplo.

## 3. Como Usar

Assim como o `Footer`, o `Header` é normalmente inserido no layout principal da aplicação.

```jsx
// Em um arquivo de layout como /layouts/PublicLayout.tsx

import { Header } from '@header';
import { Footer } from '@footer';

const PublicLayout = ({ children }) => {
  return (
    <>
      <Header variant="Sticky" />
      <main>
        {children}
      </main>
      <Footer />
    </>
  );
};
```