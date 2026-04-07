/**
 * @arquivo     src/header/header.types.ts
 * @módulo      Header / Tipos
 * @descrição   Definições de tipos TypeScript compartilhadas entre os
 *              componentes e hooks do módulo Header. Centraliza interfaces
 *              para evitar duplicação e garantir consistência de contratos.
 *
 * @como-usar   Importe os tipos necessários:
 *              import { NavLink, HeaderProps } from './header.types';
 *
 * @dependências Apenas tipos nativos do TypeScript e React (ReactNode)
 * @notas       Nenhum código de runtime neste arquivo — apenas definições de tipos.
 */

/**
 * Estrutura de um link de navegação.
 */
export interface NavLink {
    /** Identificador único do link. */
    id: string;
    /** Texto exibido ao usuário. */
    label: string;
    /** URL de destino do link. */
    href: string;
    /** Se verdadeiro, renderiza como botão de ação principal (destaque visual). */
    isPrimary?: boolean;
}

/**
 * Props do componente Header principal.
 */
export interface HeaderProps {
    /**
     * Classe CSS adicional para o container do header.
     */
    className?: string;
    /**
     * Itens de navegação a exibir.
     */
    links?: NavLink[];
    /**
     * Texto ou componente para o logotipo da marca.
     * Padrão: "JS"
     */
    logo?: React.ReactNode;
}

/** Props do menu mobile (overlay de navegação). */
export interface MobileMenuProps {
    /** Define se o menu está aberto. */
    isOpen: boolean;
    /** Callback para fechar o menu. */
    onClose: () => void;
    /** Lista de links de navegação exibidos no menu. */
    links: NavLink[];
}
