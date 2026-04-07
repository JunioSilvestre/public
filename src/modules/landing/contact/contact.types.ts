/**
 * @arquivo     src/contact/contact.types.ts
 * @módulo      Contact / Tipagem
 * @descrição   Definições de interfaces para o módulo de contato.
 */

export interface ContactInfoItem {
  label: string;
  value: string;
  icon: string;
  href?: string;
}

export interface ContactSocialItem {
  name: string;
  icon: string;
  href: string;
}

export interface ContactFieldConfig {
  label: string;
  placeholder: string;
}

export interface ContactConfig {
  title: string;
  description: string;
  info: Record<string, ContactInfoItem>;
  socials: ContactSocialItem[];
  form: {
    fields: {
      name: ContactFieldConfig;
      email: ContactFieldConfig;
      message: ContactFieldConfig;
    };
    submitLabel: string;
    successMsg: {
      title: string;
      sub: string;
    };
  };
}
