# Módulo de Acessibilidade (a11y)

## 1. Propósito

O módulo `a11y` (um numerônimo para *Accessibility*, onde "11" representa as 11 letras entre 'A' e 'y') é dedicado a garantir que nossa aplicação seja utilizável por todas as pessoas, incluindo aquelas com deficiências visuais, motoras, auditivas ou cognitivas.

Investir em acessibilidade não é apenas uma boa prática de UX, mas um requisito legal em muitos mercados (como a LBI no Brasil e a ADA nos EUA), especialmente no setor financeiro, onde a clareza e o acesso à informação são críticos.

## 2. Estrutura

Este módulo está organizado em três áreas principais:

- **`/components`**: Contém componentes React focados em resolver desafios de acessibilidade. Por exemplo:
  - `VisuallyHidden`: Esconde um elemento visualmente, mas o mantém acessível para leitores de tela. Útil para fornecer contexto adicional que não precisa estar visível na UI.
  - `FocusTrap`: Prende o foco do teclado dentro de um elemento, como um modal, impedindo que o usuário navegue para o conteúdo de fundo acidentalmente.

- **`/hooks`**: Fornece hooks customizados que encapsulam lógicas de acessibilidade complexas.
  - `useReducedMotion`: Detecta se o usuário prefere movimento reduzido nas configurações do seu sistema operacional, permitindo desativar ou simplificar animações.
  - `useKeyboardNav`: Facilita a criação de navegação complexa via teclado em componentes como menus e listas.

- **`/validators`**: Funções utilitárias para auditar e validar a acessibilidade de componentes em tempo de desenvolvimento ou em testes automatizados, como checar o contraste de cores.

## 3. Como Usar

Os componentes e hooks deste módulo são projetados para serem "plug-and-play".

**Exemplo: Usando `VisuallyHidden`**

Para adicionar um texto descritivo a um ícone que só será lido por leitores de tela, você pode fazer:

```jsx
import { VisuallyHidden } from '@a11y/components';
import { Icon } from '@ds/atoms';

const CloseButton = () => (
  <button>
    <Icon name="close" />
    <VisuallyHidden>Fechar modal</VisuallyHidden>
  </button>
);
```

Neste caso, um usuário vidente verá apenas o ícone 'X', mas um usuário de leitor de tela ouvirá "Fechar modal", entendendo a função do botão.