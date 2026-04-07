/**
 * @file        src/about/About.tsx
 * @module      About / Component
 * @description "About Me" section adapted from the original HTML design.
 */
"use client";

import React from 'react';
import Image from 'next/image';
import { 
  Code2, 
  Palette, 
  Layers, 
  Zap, 
  ArrowLeftRight, 
  ShieldCheck, 
  Settings, 
  Rocket 
} from 'lucide-react';
import styles from './About.module.css';

const About: React.FC = () => {
  const responsibilities = [
    {
      id: 'ui-ux',
      title: 'Interfaces & UX',
      description: 'Pixel-perfect UI development (Figma) focused on usability, accessibility (A11y), and intuitive experiences.',
      icon: <Palette className="w-6 h-6" />,
      colorClass: 'bg-cyan-50 text-cyan-600',
    },
    {
      id: 'stack',
      title: 'Frameworks & Architecture',
      description: 'Expertise in React, Next.js, and TypeScript to create modular, reusable, and scalable components.',
      icon: <Layers className="w-6 h-6" />,
      colorClass: 'bg-indigo-50 text-indigo-600',
    },
    {
      id: 'perf',
      title: 'Optimization & Performance',
      description: 'Focused on Core Web Vitals, Lazy Loading, and Code Splitting to ensure maximum load speed.',
      icon: <Zap className="w-6 h-6" />,
      colorClass: 'bg-emerald-50 text-emerald-600',
    },
    {
      id: 'integration',
      title: 'Integration & State',
      description: 'Consuming complex APIs and efficient global state management (Zustand, Redux, or Context API).',
      icon: <ArrowLeftRight className="w-6 h-6" />,
      colorClass: 'bg-orange-50 text-orange-600',
    },
    {
      id: 'quality',
      title: 'Testing & Refactoring',
      description: 'Ensuring stability via unit testing (Jest/RTL) and constant maintenance of code quality.',
      icon: <ShieldCheck className="w-6 h-6" />,
      colorClass: 'bg-red-50 text-red-600',
    },
    {
      id: 'ecosystem',
      title: 'Environment & DevOps',
      description: 'Configuration of modern tooling (Vite, ESLint), Git versioning, and collaboration via Agile Methodologies.',
      icon: <Settings className="w-6 h-6" />,
      colorClass: 'bg-slate-50 text-slate-600',
    },
  ];

  return (
    <section id="about" className="py-24 px-6 md:px-12 lg:px-24 max-w-7xl mx-auto">
      {/* Header & Intro */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 mb-20">
        
        {/* Photo Column */}
        <div className="lg:col-span-5">
          <div className={styles.photoFrame}>
            <div className="aspect-[4/5] rounded-3xl overflow-hidden bg-slate-200 border-4 border-white shadow-2xl relative">
              <Image 
                src="/assets/images/about/ju.jpg" 
                alt="Your Photo" 
                fill
                className="object-cover grayscale hover:grayscale-0 transition duration-700" 
              />
            </div>

            {/* Stats Overlays */}
            <div className={`absolute -bottom-6 -right-6 ${styles.statBadge} p-4 rounded-2xl shadow-lg`}>
              <div className="flex items-center gap-3">
                <div className="p-2 bg-cyan-100 text-cyan-600 rounded-lg">
                  <Code2 className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-[10px] uppercase font-bold text-slate-400 tracking-widest">Stack</p>
                  <p className="text-sm font-bold text-slate-800 italic">Frontend Focused</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Impact Text */}
        <div className="lg:col-span-7 flex flex-col justify-center">
          <h2 className="text-indigo-600 font-bold uppercase tracking-[0.3em] text-xs mb-4">Software Engineer</h2>
          <h1 className="text-3xl md:text-5xl font-bold text-slate-900 leading-[1.1] mb-8">
            Software Engineer specializing in <span className={styles.textGradient}>Front-End</span>.
          </h1>
          <p className="text-xl text-slate-600 font-medium mb-6">
            I transform complex architectures into elegant, fluid, and high-performance interfaces, combining
            technical rigor with visual excellence.
          </p>
          <div className="flex gap-6 mt-4">
            <div className="flex items-center gap-2">
              <span className="w-10 h-[2px] bg-slate-300"></span>
              <span className="text-slate-400 text-sm font-semibold uppercase tracking-widest leading-none">
                Committed to quality
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Responsibilities (Grid) */}
      <div className="space-y-10">
        <div className="text-center max-w-2xl mx-auto">
          <h3 className="text-2xl font-bold text-slate-900 mb-4">Expertise Domains</h3>
          <p className="text-slate-500">
            My work covers the entire Front-End lifecycle, from design to development infrastructure.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {responsibilities.map((resp) => (
            <div key={resp.id} className={`${styles.responsibilityCard} p-6 rounded-2xl`}>
              <div className={`w-12 h-12 ${resp.colorClass} rounded-xl flex items-center justify-center mb-4`}>
                {resp.icon}
              </div>
              <h4 className="font-bold text-slate-800 mb-2">{resp.title}</h4>
              <p className="text-sm text-slate-500 leading-relaxed">
                {resp.description}
              </p>
            </div>
          ))}
        </div>
      </div>

    </section>
  );
};

export default About;
