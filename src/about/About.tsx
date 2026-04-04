/**
 * @arquivo     src/about/About.tsx
 * @módulo      About / Componente
 * @descrição   Seção "About Me" adaptada do design HTML original.
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
      description: 'Desenvolvimento de UIs pixel-perfect (Figma) focadas em usabilidade, acessibilidade (A11y) e experiências intuitivas.',
      icon: <Palette className="w-6 h-6" />,
      colorClass: 'bg-cyan-50 text-cyan-600',
    },
    {
      id: 'stack',
      title: 'Frameworks & Arquitetura',
      description: 'Domínio de React, Next.js e TypeScript para criar componentes modulares, reutilizáveis e escaláveis.',
      icon: <Layers className="w-6 h-6" />,
      colorClass: 'bg-indigo-50 text-indigo-600',
    },
    {
      id: 'perf',
      title: 'Otimização & Performance',
      description: 'Foco em Core Web Vitals, Lazy Loading e Code Splitting para garantir velocidade máxima de carregamento.',
      icon: <Zap className="w-6 h-6" />,
      colorClass: 'bg-emerald-50 text-emerald-600',
    },
    {
      id: 'integration',
      title: 'Integração & Estado',
      description: 'Consumo de APIs complexas e gerenciamento de estado global eficiente (Zustand, Redux ou Context API).',
      icon: <ArrowLeftRight className="w-6 h-6" />,
      colorClass: 'bg-orange-50 text-orange-600',
    },
    {
      id: 'quality',
      title: 'Testes & Refatoração',
      description: 'Garantia de estabilidade via testes unitários (Jest/RTL) e manutenção constante da qualidade do código.',
      icon: <ShieldCheck className="w-6 h-6" />,
      colorClass: 'bg-red-50 text-red-600',
    },
    {
      id: 'ecosystem',
      title: 'Ambiente & DevOps',
      description: 'Configuração de tooling moderno (Vite, ESLint), versionamento Git e colaboração via Metodologias Ágeis.',
      icon: <Settings className="w-6 h-6" />,
      colorClass: 'bg-slate-50 text-slate-600',
    },
  ];

  return (
    <section id="about" className="py-24 px-6 md:px-12 lg:px-24 max-w-7xl mx-auto">
      {/* Header & Intro */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 mb-20">
        
        {/* Coluna Foto */}
        <div className="lg:col-span-5">
          <div className={styles.photoFrame}>
            <div className="aspect-[4/5] rounded-3xl overflow-hidden bg-slate-200 border-4 border-white shadow-2xl relative">
              <Image 
                src="/assets/images/about/ju.jpg" 
                alt="Sua Foto" 
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

        {/* Texto de Impacto */}
        <div className="lg:col-span-7 flex flex-col justify-center">
          <h2 className="text-indigo-600 font-bold uppercase tracking-[0.3em] text-xs mb-4">Software Engineer</h2>
          <h1 className="text-3xl md:text-5xl font-bold text-slate-900 leading-[1.1] mb-8">
            Engenheiro de Software especializado em <span className={styles.textGradient}>Front-End</span>.
          </h1>
          <p className="text-xl text-slate-600 font-medium mb-6">
            Transformo arquiteturas complexas em interfaces elegantes, fluidas e de alta performance, unindo
            rigor técnico com excelência visual.
          </p>
          <div className="flex gap-6 mt-4">
            <div className="flex items-center gap-2">
              <span className="w-10 h-[2px] bg-slate-300"></span>
              <span className="text-slate-400 text-sm font-semibold uppercase tracking-widest leading-none">
                Comprometido com a qualidade
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Responsabilidades (Grid das Funções) */}
      <div className="space-y-10">
        <div className="text-center max-w-2xl mx-auto">
          <h3 className="text-2xl font-bold text-slate-900 mb-4">Domínios de Atuação</h3>
          <p className="text-slate-500">
            Minha atuação abrange todo o ciclo de vida do Front-End, do design à infraestrutura de desenvolvimento.
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

      {/* Footer Call */}
      <div className="mt-20 p-8 rounded-3xl bg-white border border-slate-200 flex flex-col md:flex-row items-center justify-between gap-8">
        <div className="flex items-center gap-6">
          <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-indigo-500 rounded-full flex items-center justify-center text-white shadow-lg">
            <Rocket className="w-8 h-8" />
          </div>
          <div>
            <p className="text-slate-900 font-bold text-lg leading-tight">
              Pronto para elevar o nível do seu projeto?
            </p>
            <p className="text-slate-500 text-sm">Expertise técnica e olhar refinado para o Front-End.</p>
          </div>
        </div>
        <a 
          href="#contact"
          className="w-full md:w-auto px-10 py-4 bg-slate-900 text-white rounded-2xl font-bold hover:bg-slate-800 transition-all text-center"
        >
          Vamos Conversar
        </a>
      </div>
    </section>
  );
};

export default About;
