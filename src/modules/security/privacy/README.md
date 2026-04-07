# Módulo de Privacidade (Privacy)

## 1. Propósito

O módulo `privacy` lida com funcionalidades relacionadas à privacidade do usuário e à conformidade com regulamentações como a GDPR (Europa) e a LGPD (Brasil). Em um mundo onde a privacidade de dados é uma preocupação crescente, ter um módulo dedicado a isso é um sinal de maturidade e gera confiança no usuário.

## 2. Estrutura

- **`/components`**: Componentes de UI para interações de privacidade.
  - `ConsentBanner.tsx`: O banner (geralmente no rodapé) que informa sobre o uso de cookies e solicita o consentimento do usuário para rastreamento.
  - `ConsentManager.tsx`: Um modal ou página onde o usuário pode gerenciar suas preferências de privacidade de forma granular (ex: aceitar cookies de analytics, mas não de marketing).
  - `PrivacyPolicy.tsx`: Um componente que renderiza o conteúdo da política de privacidade, talvez buscando o texto de um CMS para facilitar as atualizações.

- **`/hooks`**: Hooks para gerenciar o estado do consentimento.
  - `useConsent.ts`: O hook principal, que retorna o estado atual do consentimento do usuário e uma função para atualizá-lo.

- **`/services`**: Lógica para armazenar as preferências do usuário.
  - `consent-storage.ts`: Funções para salvar e ler as preferências de consentimento do armazenamento do navegador (ex: `localStorage` ou um cookie específico).

## 3. Fluxo

1.  **Verificação:** Quando um usuário visita o site pela primeira vez, o `useConsent` verifica se já existe uma preferência de consentimento armazenada.
2.  **Exibição do Banner:** Se não houver preferência, o `ConsentBanner` é exibido.
3.  **Interação do Usuário:** O usuário pode aceitar tudo, rejeitar tudo, ou abrir o `ConsentManager` para escolher suas preferências.
4.  **Armazenamento:** A preferência do usuário é salva pelo `consent-storage`.
5.  **Aplicação:** Outras partes da aplicação (como o módulo `analytics`) usam o hook `useConsent` para verificar se podem executar certas ações (ex: inicializar o Google Analytics).

## 4. Como Usar

O `ConsentBanner` e o gerenciamento de estado geralmente são adicionados ao layout principal ou ao `_app.tsx`.

```jsx
// Em _app.tsx ou em um layout principal

import { ConsentProvider } from '@privacy/hooks/useConsent'; // Supondo um Context Provider
import { ConsentBanner } from '@privacy/components';

function MyApp({ Component, pageProps }) {
  return (
    <ConsentProvider>
      {/* ... outros provedores ... */}
      <Component {...pageProps} />
      <ConsentBanner />
    </ConsentProvider>
  );
}
```

O módulo de analytics então usaria o hook para agir de acordo:

```jsx
// Em @analytics/providers/google.ts

import { useConsent } from '@privacy/hooks';

export const initializeGoogleAnalytics = () => {
  const { consent } = useConsent();

  // Só inicializa o GA se o usuário deu consentimento para analytics
  if (consent.analytics) {
    // ... lógica de inicialização do Google Analytics ...
  }
};
```