/**
 * @arquivo     src/app/page.tsx
 * @módulo      App / Página Inicial
 * @descrição   Página raiz da aplicação. Inclui o Hero e seções de ancoragem
 *              para o portfólio (About, Works, Contact).
 */
"use client";

import Hero from '@/hero';
import Footer from '@/footer';
import Contact from '@/contact';
import About from '@/about';

export default function HomePage() {
  return (
    <div className="bg-[#f5f5f5]">
      {/* Hero section carries the id="hero" internally */}
      <Hero />

      <main className="max-w-[1440px] mx-auto px-6 md:px-10">
        
        {/* Section: About */}
        <About />

        {/* Section: Works */}

        {/* Section: Works */}
        <section id="works" className="py-32 border-b border-black/5">
          <h2 className="text-4xl font-bold text-[#111827] mb-12 font-[family-name:var(--font-head)]">Selected Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
            {/* Project Card 1 */}
            <div className="group cursor-pointer">
              <div className="aspect-video bg-black/5 rounded-2xl mb-6 overflow-hidden transition-transform duration-500 group-hover:scale-[1.02]">
                <div className="w-full h-full flex items-center justify-center text-black/20 font-mono text-xs">PROJECT_PREVIEW_01</div>
              </div>
              <h3 className="text-xl font-bold text-[#111827] mb-2">HealthBridge Platform</h3>
              <p className="text-[#6B7280]">Full-scale data visualization and claim analytics engine.</p>
            </div>
            
            {/* Project Card 2 */}
            <div className="group cursor-pointer">
              <div className="aspect-video bg-black/5 rounded-2xl mb-6 overflow-hidden transition-transform duration-500 group-hover:scale-[1.02]">
                <div className="w-full h-full flex items-center justify-center text-black/20 font-mono text-xs">PROJECT_PREVIEW_02</div>
              </div>
              <h3 className="text-xl font-bold text-[#111827] mb-2">Nexus Design System</h3>
              <p className="text-[#6B7280]">Modern, atomic-based component library for enterprise apps.</p>
            </div>
          </div>
        </section>

        {/* Section: Contact */}
        <Contact />
      </main>
    </div>
  );
}
