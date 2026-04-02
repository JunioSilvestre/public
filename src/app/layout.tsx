/**
 * @arquivo     src/app/layout.tsx
 * @módulo      App / Layout Raiz
 * @descrição   Layout raiz da aplicação Next.js (App Router).
 *              Define a estrutura HTML global, fonte padrão (Inter), metadados
 *              de SEO e os componentes de moldura comuns a todas as páginas:
 *              Header (fixo no topo) e Footer.
 *
 * @como-usar   Este arquivo é carregado automaticamente pelo Next.js como
 *              layout global. Envolva suas páginas aninhando-as como `children`.
 *              Personalize `metadata` para ajustar título, descrição e robots.
 *
 * @dependências next/font (Inter), @/styles/globals.css, @/header, @/footer
 * @notas       - `lang="pt-BR"` deve ser configurado quando o projeto for localizado
 *              - O padding-top no <main> compensa a altura do Header fixo (72px)
 */
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "@/styles/globals.css";
import Header from "@/header";
import Footer from "@/footer";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "PRJ-BASE | Plataforma Segura",
  description: "Plataforma empresarial com segurança avançada e proteção multicamada.",
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <Header />
        <main style={{ paddingTop: '72px' }}>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
