# Módulo de Contato (Contact)

## 1. Propósito

O módulo `contact` gerencia todas as formas de comunicação iniciadas pelo usuário, como formulários de contato geral, solicitações de demonstração e inscrições em newsletters. 

Centralizar essa lógica em um módulo garante que:
- A validação de dados seja consistente.
- A integração com serviços de CRM (ex: HubSpot, Salesforce) seja feita em um único lugar.
- A experiência do usuário ao preencher formulários seja padronizada.

## 2. Estrutura

- **`/components`**: Contém todos os componentes de UI relacionados a formulários. 
  - `ContactForm.tsx`: O formulário de contato padrão.
  - `DemoRequestForm.tsx`: Um formulário específico para solicitar uma demonstração, potencialmente com mais campos.
  - `FormField.tsx`: Um componente genérico que encapsula um campo de formulário (`<input>`, `<label>`, erro de validação), para ser reutilizado em todos os formulários.
  - `CalendlyEmbed.tsx`: Componente para embutir um widget do Calendly, permitindo o agendamento direto.

- **`/hooks`**: Hooks que gerenciam o estado, a validação e o envio dos formulários.
  - `useContactForm`: Encapsula toda a lógica para o formulário de contato, utilizando bibliotecas como `react-hook-form` e `zod` para validação.

- **`/services`**: Camada responsável pela comunicação com APIs externas.
  - `submit-contact.ts`: Função que envia os dados do formulário para o nosso backend ou diretamente para um serviço de CRM.
  - `crm-hubspot.ts`: Um adaptador específico para a API do HubSpot.

- **`/validation`**: Schemas de validação (usando `zod` ou `yup`) que definem as regras para cada campo de cada formulário.
  - `contact.schema.ts`: Define que o campo `email` deve ser um email válido e que a `mensagem` deve ter no mínimo 10 caracteres.

## 3. Como Usar

As páginas da aplicação (como `/contact`) importam e renderizam o componente de formulário principal, que já vem com toda a lógica embutida.

```jsx
// Em uma página como /pages/RequestDemoPage.tsx

import { DemoRequestForm } from '@contact/components';

const RequestDemoPage = () => {
  const handleSuccess = () => {
    // Redirecionar para uma página de "Obrigado" ou mostrar uma mensagem.
    console.log('Demonstração solicitada com sucesso!');
  };

  return (
    <div>
      <h2>Agende sua Demonstração</h2>
      <DemoRequestForm onSuccess={handleSuccess} />
    </div>
  );
};
```