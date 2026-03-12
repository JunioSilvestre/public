# Módulo de Segurança (Security)

## 1. Propósito

O módulo `security` centraliza as funcionalidades e as melhores práticas de segurança do lado do cliente (*client-side*). Embora a maior parte da segurança resida no backend, há medidas importantes que podemos e devemos tomar no frontend para proteger nossos usuários contra ataques comuns, como Cross-Site Scripting (XSS).

## 2. Estrutura

- **`/sanitization`**: Funções para "limpar" (sanitizar) dados antes de serem renderizados na tela ou enviados para o backend.
  - `dom.ts`: Contém funções que usam bibliotecas como `DOMPurify` para remover HTML ou scripts maliciosos de strings que precisam ser renderizadas com `dangerouslySetInnerHTML`.
  - `input.ts`: Funções para sanitizar a entrada do usuário em formulários, removendo caracteres potencialmente perigosos.

- **`/headers`**: Configuração dos cabeçalhos de segurança HTTP. Embora muitos cabeçalhos sejam configurados no backend ou na infraestrutura (CDN), alguns podem ser gerenciados via metatags no frontend.
  - `csp.ts`: Lógica para gerar uma política de segurança de conteúdo ([Content Security Policy - CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)). A CSP é uma camada de defesa poderosa contra ataques XSS.

- **`/hooks`**: Hooks que ajudam a aplicar práticas de segurança.
  - `useSanitizedHtml.ts`: Um hook que recebe uma string de HTML "sujo" e retorna uma versão segura para ser usada com `dangerouslySetInnerHTML`, evitando o uso direto dessa API perigosa.

- **`__tests__`**: Testes específicos para as funções de sanitização, garantindo que elas removem payloads maliciosos conhecidos sem quebrar o conteúdo legítimo.

## 3. Como Usar

### Sanitização de HTML

Sempre que precisar renderizar HTML que vem de uma fonte externa (como um CMS), use o hook de sanitização.

```jsx
// Em vez de:
// <div dangerouslySetInnerHTML={{ __html: dirtyHtmlFromApi }} />

// Usamos:
import { useSanitizedHtml } from '@security/hooks';

const BlogPost = ({ content }) => {
  const sanitizedContent = useSanitizedHtml(content);

  // É seguro renderizar o conteúdo sanitizado
  return <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />;
};
```

### Content Security Policy (CSP)

A configuração da CSP geralmente é feita no `next.config.js` ou em um middleware, aplicando o cabeçalho a todas as respostas do servidor.

```javascript
// Em next.config.js

const { createCsp } = require('./src/security/headers/csp');

const csp = createCsp();

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: csp,
          },
        ],
      },
    ];
  },
};
```