# Módulo Anti-Bot

## 1. Propósito

O módulo `anti-bot` implementa estratégias para diferenciar usuários legítimos de bots automatizados maliciosos. Proteger formulários de contato, login e cadastro contra bots é essencial para evitar spam, ataques de força bruta e a criação de contas falsas.

## 2. Estrutura

- **`honeypot.ts`**: Implementa a técnica de "pote de mel". Um campo de formulário é criado e escondido de usuários humanos via CSS. Bots que preenchem todos os campos indiscriminadamente serão pegos ao preencher este campo "invisível", e sua submissão pode ser bloqueada.

- **`recaptcha.ts`**: Contém a lógica para integrar o serviço reCAPTCHA do Google (ou similar). Ele pode ser usado para apresentar um desafio (como o "Não sou um robô" ou um desafio invisível baseado em score) para o usuário, provando que ele é humano.

- **`index.ts`**: Exporta os componentes e lógicas do módulo para serem facilmente consumidos, como um componente React `<HoneypotField />` ou um hook `useRecaptcha()`.