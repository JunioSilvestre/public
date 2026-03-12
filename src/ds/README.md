# Design System (ds)

## 1. Propósito

O Design System (`ds`) é a fonte única da verdade para a nossa interface de usuário (UI). Ele é uma coleção de componentes reutilizáveis, padrões e diretrizes que unificam nossa linguagem visual e de interação.

Ter um Design System robusto nos permite:
- **Construir mais rápido:** Reutilizando componentes prontos em vez de recriá-los.
- **Manter a consistência:** Garantir que a aplicação tenha uma aparência e comportamento coesos.
- **Facilitar a manutenção:** Atualizar um componente no `ds` propaga a mudança para toda a aplicação.
- **Melhorar a colaboração:** Criar uma linguagem comum entre designers e desenvolvedores.

## 2. Estrutura (Atomic Design)

Nossa estrutura é inspirada na metodologia [Atomic Design](https://atomicdesign.bradfrost.com/):

- **`/tokens`**: As partículas fundamentais da nossa UI. Não são componentes, mas variáveis de design. 
  - `colors.ts`, `spacing.ts`, `typography.ts`, `shadows.ts`.
  - Ex: `colors.brand.primary` em vez de `"#5A32E1"`.

- **`/atoms`**: Os blocos de construção mais básicos da UI. São componentes agnósticos de contexto de negócio.
  - `Button.tsx`, `Input.tsx`, `Icon.tsx`, `Spinner.tsx`.

- **`/molecules`**: Composições de átomos que formam componentes um pouco mais complexos.
  - `Modal.tsx` (usa `Button` e `Icon`).
  - `SectionHeader.tsx` (usa `Typography` e `Divider`).
  - `Toast.tsx` (usa `Icon` e `Typography`).

- **`/layouts`**: Componentes que definem a estrutura e o espaçamento da página, mas não têm um design ou "aparência" própria.
  - `Container.tsx`: Centraliza e limita a largura do conteúdo.
  - `Grid.tsx`: Implementa um sistema de grid para layout.
  - `Stack.tsx`: Empilha elementos verticalmente ou horizontalmente com espaçamento consistente.

- **`/themes`**: Define os temas da aplicação (ex: `light`, `dark`). Cada tema consome os `tokens` e os aplica, permitindo a troca de aparência de forma global.

## 3. Como Usar

Componentes do Design System são feitos para serem importados e utilizados em qualquer lugar da aplicação.

```jsx
import { Button, Input } from '@ds/atoms';
import { Modal } from '@ds/molecules';
import { Container } from '@ds/layouts';
import { useState } from 'react';

const MyFeature = () => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <Container>
      <Input placeholder="Digite seu nome..." />
      <Button onClick={() => setIsOpen(true)}>Abrir Modal</Button>
      <Modal title="Meu Modal" isOpen={isOpen} onClose={() => setIsOpen(false)}>
        <p>Conteúdo do modal.</p>
      </Modal>
    </Container>
  );
}
```