/**
 * @arquivo     src/app/page.tsx
 * @módulo      App / Página Inicial
 * @descrição   Página raiz da aplicação (rota "/"). Renderiza apenas o componente Hero
 *              para exibição do portfólio.
 *
 * @como-usar   Acesse "/" no navegador.
 */
"use client";

import Hero from '@/hero';

export default function HomePage() {
  return (
    <main className="min-h-screen bg-[#f5f5f5]">
      <Hero />
      {/* Seção de rodapé ou conteúdo adicional pode ser adicionada aqui */}
      <section className="py-20 px-10 text-center text-[#6B7280]">
        <p>© 2024 Engenheiro de Software — Especialista em Front-End & Arquiteturas Modernas</p>
      </section>
    </main>
  );
}
