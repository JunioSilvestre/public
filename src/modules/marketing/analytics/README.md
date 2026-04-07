# Módulo de Analytics

## 1. Propósito

O módulo `analytics` é responsável por toda a coleta e envio de dados de comportamento do usuário. Ele nos permite entender como os usuários interagem com a aplicação, identificar pontos de atrito e medir o sucesso de novas features.

A arquitetura deste módulo é projetada para ser agnóstica em relação ao provedor de analytics, permitindo-nos trocar ou adicionar ferramentas (Google Analytics, PostHog, Meta Pixel, etc.) com o mínimo de impacto no código da aplicação.

## 2. Estrutura

- **`/providers`**: Contém os "adaptadores" para cada serviço de analytics. Cada arquivo aqui implementa uma interface comum para inicializar o serviço e enviar eventos (ex: `google.ts`, `hotjar.ts`).

- **`/events`**: Define os eventos de negócio específicos que queremos rastrear. Em vez de espalhar chamadas genéricas como `track('click')` pelo código, criamos funções tipadas como `cta-click.ts` ou `form-submit.ts`. Isso cria um dicionário de eventos claro e fácil de manter.

- **`/hooks`**: Hooks customizados que facilitam o rastreamento de eventos no código da aplicação.
  - `useTrackEvent`: O hook principal para disparar um evento de negócio.
  - `usePageView`: Rastreia automaticamente as visualizações de página, integrando-se ao roteador.

- **`/consent`**: Gerencia o consentimento do usuário para o rastreamento, em conformidade com regulações como GDPR (Europa) e LGPD (Brasil).

## 3. Fluxo de Dados

1.  **Consentimento:** O `ConsentManager` pergunta ao usuário quais categorias de rastreamento ele aceita.
2.  **Inicialização:** O `AnalyticsProvider` (no `_app.tsx` ou similar) inicializa apenas os provedores para os quais o usuário deu consentimento.
3.  **Rastreamento:** Um componente na aplicação usa o hook `useTrackEvent` para disparar um evento de negócio (ex: `trackCtaClick({ buttonName: 'RequestDemo' })`).
4.  **Disparo:** O hook `useTrackEvent` itera sobre os provedores inicializados e chama o método `track` de cada um, enviando os dados do evento para as plataformas correspondentes.

## 4. Como Usar

**Exemplo: Rastreando um clique em um botão de CTA**

```jsx
import { useTrackEvent } from '@analytics/hooks';
import { trackCtaClick } from '@analytics/events';

const MyComponent = () => {
  const track = useTrackEvent();

  const handleClick = () => {
    // Dispara um evento de negócio bem definido
    track(trackCtaClick({ 
      ct-name: 'start-free-trial',
      location: 'hero-section'
    }));
  };

  return <button onClick={handleClick}>Start Free Trial</button>;
};
```