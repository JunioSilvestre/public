/**
 * @file        src/app/page.tsx
 * @module      App / Home Page
 * @description Root page of the application. Includes the Hero and anchor sections
 *              for the portfolio (About, Works, Contact).
 */
"use client";

import Hero from '@/hero';
import Contact from '@/contact';
import About from '@/about';
import Works, { CTA } from '@/works';

export default function HomePage() {
  return (
    <div className="bg-[#f5f5f5]">
      {/* Hero section carries the id="hero" internally */}
      <Hero />

      <main className="max-w-[1440px] mx-auto px-6 md:px-10">
        
        {/* Section: About */}
        <About />

        {/* Section: Works */}
        <Works />
        
        <CTA />

        {/* Section: Contact */}
        <Contact />
      </main>
    </div>
  );
}
