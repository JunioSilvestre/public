# Módulo de Sanitização (Sanitize)

## 1. Propósito

O módulo `sanitize` é dedicado a "limpar" qualquer dado que venha de uma fonte externa ou do usuário antes que ele seja processado ou renderizado. Esta é uma defesa fundamental contra ataques de injeção, como Cross-Site Scripting (XSS) e outros.

## 2. Estrutura

- **`html.ts`**: Especializado em sanitizar strings que contêm HTML. Usa bibliotecas como `DOMPurify` para remover tags e atributos perigosos (como `<script>` ou `onerror`), permitindo que um subconjunto seguro de HTML seja renderizado.

- **`input.ts`**: Focado em sanitizar entradas de formulários, removendo ou escapando caracteres que podem ser usados em ataques, sem necessariamente remover todo o HTML.

- **`url.ts`**: Sanitiza URLs para prevenir ataques de phishing ou XSS através de protocolos como `javascript:`. Garante que as URLs apontem para protocolos seguros como `http:`, `https:` ou `mailto:`.

- **`index.ts`**: Reexporta as funções de sanitização para fácil acesso em toda a aplicação.