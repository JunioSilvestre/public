/**
 * @arquivo     src/contact/contact.config.ts
 * @módulo      Contact / Configuração
 * @descrição   Dados de contato e labels para a seção de formulário.
 */

import { ContactConfig } from './contact.types';

export const CONTACT_CONFIG: ContactConfig = {
  title: "Vamos conversar?",
  description: "Tem um projeto em mente, uma dúvida ou quer bater um papo? Estou à disposição para te ajudar.",
  info: {
    email: {
      label: "Email",
      value: "seuemail@exemplo.com",
      href: "mailto:seuemail@exemplo.com",
      icon: "mail"
    },
    phone: {
      label: "Telefone / WhatsApp",
      value: "(11) 99999-9999",
      href: "tel:+5511999999999",
      icon: "phone"
    },
    location: {
      label: "Localização",
      value: "São Paulo, Brasil",
      icon: "map-pin"
    }
  },
  socials: [
    { name: "LinkedIn", icon: "fa-brands fa-linkedin", href: "#" },
    { name: "GitHub", icon: "fa-brands fa-github", href: "#" },
    { name: "Instagram", icon: "fa-brands fa-instagram", href: "#" }
  ],
  form: {
    fields: {
      name: { label: "Seu nome", placeholder: "João Silva" },
      email: { label: "Seu email", placeholder: "voce@exemplo.com" },
      message: { label: "Mensagem", placeholder: "Me conte sobre seu projeto..." }
    },
    submitLabel: "Enviar mensagem",
    successMsg: {
      title: "Mensagem enviada com sucesso!",
      sub: "Entrarei em contato em breve. Obrigado!"
    }
  }
};
