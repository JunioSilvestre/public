# Módulo de Layouts

## 1. Propósito

O módulo `layouts` contém componentes React que definem a estrutura geral de diferentes tipos de páginas na aplicação. Eles servem como "molduras" ou "templates" para o conteúdo.

O principal objetivo é evitar a repetição de elementos comuns, como o `Header`, `Footer` ou barras laterais, em cada página individual. Ao envolver o conteúdo de uma página com um componente de layout, garantimos consistência e facilitamos a manutenção.

## 2. Estrutura

Cada arquivo neste módulo é um componente de layout que aceita uma prop `children` (o conteúdo da página).

- **`PublicLayout.tsx`**: O layout padrão para páginas públicas. Geralmente inclui o `Header` e o `Footer` principais da aplicação e define a largura máxima do conteúdo.

- **`MinimalLayout.tsx`**: Um layout simplificado, talvez usado para páginas de foco, como as de login, cadastro ou checkout, onde queremos minimizar distrações e não mostrar o `Header` e `Footer` completos.

- **`CampaignLayout.tsx`**: Um layout específico para páginas de destino (landing pages) de campanhas de marketing. Pode não ter navegação alguma e ser focado 100% na conversão.

- **`DashboardLayout.tsx` (se aplicável):** Em uma aplicação com área logada, este seria o layout do dashboard, incluindo uma barra lateral de navegação (`Sidebar`), o cabeçalho do usuário, etc.

## 3. Como Usar

O uso mais comum é aplicar o layout diretamente no arquivo da página.

```jsx
// Em src/pages/PricingPage.tsx

import { PublicLayout } from '@layouts';
import { PricingTable } from '@pricing/components'; // Componente da feature de preços

const PricingPage = () => {
  return (
    // Envolvemos o conteúdo da página com o layout desejado
    <PublicLayout>
      <h1>Nossos Planos</h1>
      <PricingTable />
    </PublicLayout>
  );
};

// Next.js também permite definir o layout de forma mais avançada
// no _app.tsx ou em layouts aninhados, mas o princípio é o mesmo.
```

Ao fazer isso, a `PricingPage` não precisa se preocupar em renderizar o `Header` ou o `Footer`; ela apenas se concentra em seu próprio conteúdo, e o `PublicLayout` cuida do resto.