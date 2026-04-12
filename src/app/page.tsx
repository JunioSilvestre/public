/**
 * @file        src/app/page.tsx
 * @module      App / Home Page
 * @description Root page of the application. Includes the Hero and anchor sections
 *              for the portfolio (About, Works, Contact).
 */
"use client";

import dynamic from 'next/dynamic';
import Hero from '@/modules/landing/hero';
import Header from "@/shared/components/header";
import Footer from "@/shared/components/footer";

const Contact = dynamic(() => import('@/modules/landing/contact'), {
  loading: () => <div className="h-96 animate-pulse bg-slate-100 rounded-3xl mb-8" />
});
const About = dynamic(() => import('@/modules/landing/about'), {
  loading: () => <div className="h-96 animate-pulse bg-slate-100 rounded-3xl mb-8" />
});
const Works = dynamic(() => import('@/modules/landing/works'), {
  loading: () => <div className="h-96 animate-pulse bg-slate-100 rounded-3xl mb-8" />
});
const CTA = dynamic(() => import('@/modules/landing/works').then(mod => mod.CTA), {
  ssr: false
});

export default function HomePage() {
  return (
    <div className="bg-[#f5f5f5]">
      <Header />
      <main style={{ paddingTop: '72px' }}>
        {/* Hero section carries the id="hero" internally */}
        <Hero />

        <div className="max-w-[1440px] mx-auto px-6 md:px-10">
          
          {/* Section: About */}
          <About />

          {/* Section: Works */}
          <Works />
          
          <CTA />

          {/* Section: Contact */}
          <Contact />
        </div>
      </main>
      <Footer />
    </div>
  );
}
