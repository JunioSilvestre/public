# Módulo de Segurança: Prevenção de Cross-Site Scripting (XSS)

Este diretório contém uma suíte de ferramentas e utilitários para proteger a aplicação contra ataques de XSS, que ocorrem quando um atacante consegue injetar scripts maliciosos em páginas web visualizadas por outros usuários.

## Estratégia de Defesa

A nossa abordagem é baseada em camadas, utilizando as melhores práticas e bibliotecas auditadas pela comunidade:

1.  **Sanitização de HTML**: Filtragem de tags e atributos perigosos de qualquer conteúdo HTML que precise ser renderizado.
2.  **Escapagem de Texto**: Codificação de texto simples para garantir que ele seja sempre tratado como texto, e não como código.
3.  **Abstrações Seguras**: Fornecimento de funções de alto nível que aplicam essas proteções por padrão, reduzindo a chance de erro humano.

## Arquivos

-   `html-sanitizer.ts`
    -   **Propósito**: É a principal linha de defesa. Utiliza a biblioteca `DOMPurify` para analisar e limpar strings de HTML.
    -   **Função Principal**: `sanitizeHtml(dirtyHtml)`.
    -   **Quando usar**: Sempre que você precisar renderizar um conteúdo HTML que venha de uma fonte não confiável (ex: um campo de texto rico preenchido pelo usuário).

-   `xss-protection.ts`
    -   **Propósito**: Lida com a "escapagem" de texto. Usa a biblioteca `he` para converter caracteres como `<` e `>` em `&lt;` e `&gt;`.
    -   **Função Principal**: `escapeText(text)`.
    -   **Quando usar**: Quando você precisa exibir um texto simples (que não deve conter HTML) dentro de uma tag. Isso garante que, se o texto contiver `<b>`, ele será exibido literalmente, em vez de criar uma tag em negrito.

-   `dom-xss-guard.ts`
    -   **Propósito**: Fornece funções "guardiãs" para manipular o DOM de forma segura.
    -   **Funções Principais**:
        -   `safeSetInnerHTML(element, html)`: Um substituto seguro para `element.innerHTML`, que sempre sanitiza o HTML antes de inseri-lo.
        -   `safeSetURLAttribute(element, attr, url)`: Um validador para `href` e `src`, que impede o uso de URLs maliciosas como `javascript:alert(1)`.
    -   **Quando usar**: Como um padrão seguro em toda a base de código para evitar o uso direto de APIs de DOM perigosas.

-   `index.ts`
    -   **Propósito**: Unifica todas as exportações do módulo, permitindo importações limpas e centralizadas. Ex: `import { sanitizeHtml } from '@/security/xss';`.
