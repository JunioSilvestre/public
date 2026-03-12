# Módulo do Roteador (Router)

## 1. Propósito

O módulo `router` serve como uma camada de abstração sobre a biblioteca de roteamento da aplicação (que, no nosso caso, é o roteador do Next.js). Embora o Next.js já facilite muito o roteamento, centralizar certas funcionalidades aqui nos dá mais controle e organização.

Os principais objetivos são:
- **Centralizar as rotas:** Ter um único lugar que define todas as rotas da aplicação, evitando "magic strings" (ex: `router.push('/pricing')`) espalhadas pelo código.
- **Tipagem de rotas:** Garantir que as rotas e seus parâmetros sejam fortemente tipados.
- **Gerenciamento de estado:** Lidar com eventos do roteador, como exibir um indicador de carregamento durante a navegação entre páginas.

## 2. Estrutura

- **`routes.ts`**: Este é o arquivo mais importante. Ele exporta um objeto que mapeia nomes de rotas para seus caminhos e, opcionalmente, para funções que constroem rotas dinâmicas.
  ```typescript
  export const ROUTES = {
    home: '/',
    pricing: '/pricing',
    // Rota dinâmica com um parâmetro `id`
    userProfile: (id: string) => `/users/${id}`,
  };
  ```

- **`/hooks`**: Hooks customizados que encapsulam o roteador do Next.js.
  - `useNavigation.ts`: Retorna uma função `navigate` que recebe uma rota tipada do nosso arquivo `routes.ts`, prevenindo erros de digitação.
  - `useRouteEvents.ts`: Permite que componentes "escutem" eventos de navegação (ex: `routeChangeStart`, `routeChangeComplete`) para disparar ações, como exibir um `PageLoader`.

- **`/components`**: Componentes relacionados ao roteamento.
  - `Link.tsx`: Um componente `Link` customizado que pode ser construído sobre o `next/link` para adicionar funcionalidades extras ou garantir que todas as rotas passem pela nossa definição tipada em `routes.ts`.
  - `PageLoader.tsx`: Um indicador de progresso (geralmente uma barra no topo da página) que é exibido automaticamente durante a navegação entre páginas.

## 3. Como Usar

### Navegação Tipada

Em vez de usar o `useRouter` do Next.js diretamente, usamos nosso hook customizado.

```jsx
// Em vez de:
// import { useRouter } from 'next/router';
// const router = useRouter();
// router.push('/users/123'); // -> propenso a erros de digitação

// Usamos:
import { useNavigation } from '@router/hooks';
import { ROUTES } from '@router/routes';

const MyComponent = () => {
  const { navigate } = useNavigation();

  const handleGoToProfile = () => {
    // A rota é tipada e o parâmetro é obrigatório!
    // O TypeScript vai acusar erro se você esquecer o `id`.
    navigate(ROUTES.userProfile('123'));
  };

  return <button onClick={handleGoToProfile}>Ver Perfil</button>;
};
```

### Indicador de Carregamento de Página

O componente `PageLoader` é geralmente colocado no `_app.tsx` e usa o `useRouteEvents` para se controlar automaticamente.

```jsx
// Em @router/components/PageLoader.tsx

import { useRouteEvents } from '@router/hooks';

export const PageLoader = () => {
  const { isLoading } = useRouteEvents();
  
  return isLoading ? <div className="page-loading-bar" /> : null;
};
```