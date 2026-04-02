/**
 * @arquivo     src/footer/footer.types.ts
 * @módulo      Footer / Tipos
 * @descrição   Definições de tipos TypeScript para o componente Footer e seus
 *              sub-componentes (FooterSocial, FooterCopyright). Centraliza
 *              interfaces para garantir consistência de contratos entre componentes.
 *
 * @como-usar   import { SocialLink, FooterProps } from './footer.types';
 *
 * @dependências React (ReactNode)
 * @notas       Nenhum código de runtime neste arquivo — apenas definições de tipos.
 */

import React from 'react';

/**
 * Estrutura de um link de rede social.
 */
export interface SocialLink {
    /** Identificador da plataforma (ex: 'github', 'linkedin'). */
    id: string;
    /** Rótulo acessível para leitores de tela. */
    label: string;
    /** URL do perfil na rede social. */
    href: string;
    /** Componente de ícone ou SVG da plataforma. */
    icon: React.ReactNode;
}

/**
 * Props do componente Footer principal.
 */
export interface FooterProps {
    /** Classe CSS opcional para estilização customizada. */
    className?: string;
    /** Links sociais customizados para sobrescrever os padrões. */
    socialLinks?: SocialLink[];
    /** Texto de copyright customizado. */
    copyrightText?: string;
}

/**
 * Props do sub-componente FooterSocial.
 */
export interface FooterSocialProps {
    /** Array de objetos de links de redes sociais. */
    links: SocialLink[];
}

/**
 * Props do sub-componente FooterCopyright.
 */
export interface FooterCopyrightProps {
    /** A string de texto do copyright. */
    text: string;
}
