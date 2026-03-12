# Testes End-to-End (E2E)

## 1. Propósito

A pasta `e2e` contém nossos testes ponta-a-ponta, automatizados com [Playwright](https://playwright.dev/).

O objetivo desses testes é simular a jornada de um usuário real na aplicação, interagindo com a interface gráfica (clicando em botões, preenchendo formulários, navegando entre páginas) para validar fluxos de negócio completos. Eles são a camada mais alta da pirâmide de testes e garantem que todas as peças da nossa aplicação (frontend, APIs, etc.) funcionam corretamente em conjunto.

## 2. Estrutura

Cada arquivo `.spec.ts` representa um conjunto de testes para uma funcionalidade ou página específica.

- **`home.spec.ts`**: Testa a página inicial, verificando se elementos chave como o hero e os CTAs principais são renderizados.
- **`contact.spec.ts`**: Simula o preenchimento e envio do formulário de contato, validando tanto o sucesso quanto os erros.
- **`security.spec.ts`**: Verifica a presença de headers de segurança importantes (como CSP) e outras melhores práticas.
- **`a11y.spec.ts`**: Executa auditorias de acessibilidade automatizadas em páginas críticas para detectar violações de contraste, falta de atributos ARIA, etc.
- **`performance.spec.ts`**: Mede métricas de performance (como o LCP - Largest Contentful Paint) para garantir que a aplicação permaneça rápida.

## 3. Como Executar

Para rodar todos os testes E2E, utilize o comando definido no `package.json`:

```bash
npm run test:e2e
```

O Playwright irá iniciar um navegador real (headless, por padrão) e executar as ações descritas nos arquivos de teste. Ao final, um relatório detalhado será gerado na pasta `playwright-report`.

**Executando um único teste:**

```bash
npx playwright test e2e/contact.spec.ts
```

## 4. Boas Práticas

- **Foco no fluxo, não em detalhes de implementação:** Testes E2E devem validar o "o quê" (o usuário consegue se cadastrar?), não o "como" (o botão de cadastro tem a classe CSS `btn-primary`?).
- **Use `data-testid`:** Para selecionar elementos de forma resiliente, evite seletores de CSS frágeis. Adicione o atributo `data-testid` aos seus componentes React e use `page.getByTestId('meu-elemento')` nos testes.