# Módulo de Páginas (Pages)

## 1. Propósito

A pasta `pages` é o coração do sistema de roteamento do Next.js (na versão com o "Pages Router"). Cada arquivo `.tsx` dentro desta pasta se torna automaticamente uma rota na nossa aplicação.

Este módulo não contém lógica de negócio complexa. Em vez disso, seu papel é **compor** os componentes e layouts das outras features para construir uma página completa.

## 2. Estrutura e Roteamento

O mapeamento entre arquivos e rotas é direto:

- `pages/index.tsx` → `meusite.com/`
- `pages/pricing.tsx` → `meusite.com/pricing`
- `pages/contact.tsx` → `meusite.com/contact`
- `pages/legal/terms.tsx` → `meusite.com/legal/terms` (rotas aninhadas)

### Arquivos Especiais:

- **`_app.tsx`**: Este é o "invólucro" (app shell) de toda a aplicação. É o único componente que é renderizado em *todas* as páginas. É o lugar ideal para:
  - Aplicar layouts globais.
  - Injetar provedores de contexto (Context Providers) para temas, autenticação, etc.
  - Inicializar serviços de analytics e feature flags.
  - Importar folhas de estilo globais.

- **`_document.tsx`**: Este arquivo (opcional) permite customizar o `<html>` e `<body>` que envolvem a aplicação. É usado para tarefas mais avançadas, como adicionar fontes do Google Fonts ou configurar metatags para toda a aplicação.

- **`404.tsx`**: Permite criar uma página de erro "Não Encontrado" (404) customizada.

## 3. Boas Práticas

- **Mantenha as páginas "magras" (thin):** Uma página deve ser apenas um ponto de entrada que compõe componentes mais inteligentes de outros módulos. Evite colocar lógica de busca de dados, estado complexo ou regras de negócio diretamente em um arquivo de página.

- **Use `getStaticProps` ou `getServerSideProps`:** Para buscar dados antes de a página ser renderizada, use as funções de data fetching do Next.js. Isso melhora a performance e o SEO.

**Exemplo de uma página "magra":**

```jsx
// Em src/pages/pricing.tsx

import { PublicLayout } from '@layouts';
import { PricingFeature } from '@pricing'; // Importa a feature completa de outro módulo

// A página em si é muito simples. Sua única responsabilidade é
// colocar a feature de Preços dentro do Layout Público.
const PricingPage = () => {
  return (
    <PublicLayout>
      <PricingFeature />
    </PublicLayout>
  );
};

export default PricingPage;
```