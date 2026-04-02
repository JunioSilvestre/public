/**
 * @arquivo     src/app/layout.tsx
 * @módulo      App / Layout Raiz
 * @descrição   Layout raiz da aplicação Next.js (App Router).
 *              Define a estrutura HTML global, fonte padrão (Inter), metadados
 *              de SEO e os componentes de moldura comuns a todas as páginas:
 *              Header (fixo no topo) e Footer.
 */
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "@/styles/globals.css";
import Header from "@/header";
import Footer from "@/footer";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Senior Software Engineer | Portfolio",
  description: "High-performance web architectures and modern frontend engineering.",
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
