/**
 * @file        src/contact/contact.config.ts
 * @module      Contact / Configuration
 * @description Contact data and labels for the form section.
 */

import { ContactConfig } from './contact.types';

export const CONTACT_CONFIG: ContactConfig = {
  title: "Let's talk?",
  description: "Have a project in mind, a question, or just want to chat? I'm available to help you.",
  info: {
    email: {
      label: "Email",
      value: "youremail@example.com",
      href: "mailto:youremail@example.com",
      icon: "mail"
    },
    phone: {
      label: "Phone / WhatsApp",
      value: "+1 (555) 000-0000",
      href: "tel:+15550000000",
      icon: "phone"
    },
    location: {
      label: "Location",
      value: "New York, NY",
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
      name: { label: "Your name", placeholder: "John Doe" },
      email: { label: "Your email", placeholder: "you@example.com" },
      message: { label: "Message", placeholder: "Tell me about your project..." }
    },
    submitLabel: "Send Message",
    successMsg: {
      title: "Message sent successfully!",
      sub: "I'll get back to you shortly. Thank you!"
    }
  }
};
