# Módulo de Internacionalização (i18n)

## 1. Propósito

O módulo `i18n` (numerônimo de *Internationalization*) é responsável por toda a lógica de tradução da aplicação. Ele nos permite exibir o conteúdo da UI em diferentes idiomas, adaptando-se à preferência do usuário ou do navegador.

Ter uma aplicação multi-idioma é crucial para alcançar um mercado global, especialmente no setor financeiro.

## 2. Estrutura

- **`/locales`**: Esta pasta contém os arquivos de tradução, geralmente no formato JSON. Cada arquivo corresponde a um idioma suportado.
  - `en.json`: Contém o mapeamento de chaves de tradução para o texto em Inglês. (Ex: `{"header.nav.pricing": "Pricing"}`)
  - `pt.json`: Contém o mapeamento para o Português. (Ex: `{"header.nav.pricing": "Preços"}`)
  - `es.json`: Contém o mapeamento para o Espanhol. (Ex: `{"header.nav.pricing": "Precios"}`)

- **`/hooks`**: Hooks que fornecem acesso às traduções e à funcionalidade de formatação.
  - `useTranslation.ts`: O hook principal. Ele retorna uma função `t`, que recebe uma chave de tradução e retorna o texto no idioma ativo.
  - `useLocale.ts`: Retorna o código do idioma atualmente ativo (ex: 'en', 'pt').
  - `useLocalizedFormat.ts`: Fornece funções para formatar datas, números e moedas de acordo com as convenções do idioma ativo.

- **`config.ts`**: Arquivo de configuração que define quais idiomas são suportados e qual é o idioma padrão.

## 3. Fluxo

1.  **Inicialização:** Uma biblioteca de `i18n` (como `i18next` ou `react-i18next`) é configurada na raiz da aplicação (`_app.tsx`), carregando os arquivos de tradução do idioma detectado.
2.  **Tradução:** Um componente usa o hook `useTranslation` para obter a função `t`.
3.  **Renderização:** O componente chama `t('chave.de.traducao')` para renderizar o texto. A biblioteca de `i18n` automaticamente encontra o valor correspondente no arquivo de tradução do idioma ativo.

## 4. Como Usar

**Exemplo: Traduzindo um título em um componente**

```jsx
import { useTranslation } from '@i18n/hooks';

const PricingHeader = () => {
  // Obtém a função de tradução 't'
  const { t } = useTranslation();

  return (
    <header>
      {/* Em vez de texto fixo, usamos chaves de tradução */}
      <h1>{t('pricing.page.title')}</h1>
      <p>{t('pricing.page.subtitle')}</p>
    </header>
  );
};
```

Isso torna o componente `PricingHeader` totalmente dinâmico. Se o idioma ativo for 'en', ele renderizará "Our Plans"; se for 'pt', renderizará "Nossos Planos".