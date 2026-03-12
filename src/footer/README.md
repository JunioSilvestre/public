# Módulo do Rodapé (Footer)

## 1. Propósito

O módulo `footer` é responsável por renderizar o rodapé global da aplicação. O rodapé é uma parte crucial da navegação e da confiança do usuário, contendo links importantes, informações legais e selos de conformidade.

Por ser uma área com muitos links e textos específicos, centralizá-lo em um módulo facilita a manutenção e garante sua consistência em todas as páginas.

## 2. Estrutura

- **`/components`**: Pequenos componentes que formam as diferentes seções do rodapé.
  - `FooterNav.tsx`: Renderiza as colunas de links de navegação.
  - `FooterSocial.tsx`: Exibe os ícones de redes sociais.
  - `FooterLegalText.tsx`: Mostra o texto de direitos autorais e links para termos de serviço e política de privacidade.
  - `FooterRegulatorySeals.tsx`: Exibe selos de certificação ou conformidade regulatória, importantes para o setor financeiro.

- **`/data`**: Arquivos JSON ou TS que contêm os dados para os links e textos do rodapé. Separar os dados do código da UI facilita a atualização dos links sem precisar alterar a lógica dos componentes.
  - `nav-columns.json`: Estrutura de dados para as colunas de navegação.
  - `legal-links.json`: Lista de links para as páginas legais.

- **`/variants`**: Diferentes versões do rodapé que podem ser usadas em contextos distintos.
  - `Full.tsx`: O rodapé completo, usado na maioria das páginas públicas.
  - `Minimal.tsx`: Uma versão simplificada, talvez para ser usada dentro da área logada da aplicação.

- **`Footer.tsx`**: O componente principal que agrega todos os subcomponentes e variantes.

## 3. Como Usar

O componente `Footer` geralmente é inserido no layout principal da aplicação para que apareça em todas as páginas.

```jsx
// Em um arquivo de layout como /layouts/PublicLayout.tsx

import { Header } from '@header';
import { Footer } from '@footer';

const PublicLayout = ({ children }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <Header />
      <main style={{ flex: 1 }}>
        {children}
      </main>
      <Footer />
    </div>
  );
};
```