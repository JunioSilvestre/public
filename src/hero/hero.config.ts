/**
 * @arquivo     src/hero/hero.config.ts
 * @módulo      Hero / Configuração
 * @descrição   Dados de conteúdo para o Hero Portfólio.
 *              Atualizado com os textos solicitados em Inglês.
 */
import { MarketItem, NetworkItem, TickerItem, StatItem } from './hero.types';

export const HERO_CONFIG = {
  badge: 'AVAILABLE FOR NEW PROJECTS — SENIOR FRONT-END ENGINEER',
  headline: {
    text: 'Building Scalable & High-Performance Front-End Architectures.',
    highlights: [
      { text: 'Scalable', color: '#00C98A' },
      { text: 'Architectures.', color: '#2DD4F5' }
    ]
  },
  subHeadline: 'Software Engineer specialized in building high-end, responsive and accessible web applications using React, Next.js, and modern CSS frameworks. Focused on performance and modularity.',
  ctas: {
    primary: { label: 'View Projects', icon: 'visibility' },
    secondary: { label: 'Contact Me', icon: 'email' }
  },
  stats: [
    { value: '50', suffix: '+', label: 'Projects Delivered', trend: '▲ 100% Success', up: true },
    { value: '10', suffix: 'Y', label: 'Experience (Years)', trend: '▲ Seniority', up: true },
    { value: '99.', suffix: '9%', label: 'Code Coverage', trend: '▲ Reliable', up: true },
    { value: '500', suffix: 'KB', label: 'Performance Budget', trend: '▼ Fast Load', up: false } 
  ] as StatItem[],
  marketData: [
    { sym: 'REACT', val: '18.3.1', chg: 'NOMINAL', up: true, fillPct: 95, fillColor: '#00C98A' },
    { sym: 'NEXT.JS', val: '14.2.1', chg: 'OPTIMIZED', up: true, fillPct: 90, fillColor: '#2DD4F5' },
    { sym: 'TS', val: '5.4.5', chg: 'TYPESAFE', up: true, fillPct: 88, fillColor: '#00C98A' },
    { sym: 'NODE', val: '20.12.2', chg: 'STABLE', up: true, fillPct: 82, fillColor: '#F59E0B' },
    { sym: 'DOCKER', val: '24.0.7', chg: 'READY', up: true, fillPct: 75, fillColor: '#EF4444' }
  ] as MarketItem[],
  networkCoverage: [
    { name: 'Architecture', members: 'Scalable Patterns', pct: 92, color: '#00C98A' },
    { name: 'Optimization', members: 'Core Web Vitals', pct: 85, color: '#2DD4F5' },
    { name: 'Accessibility', members: 'WCAG 2.1', pct: 80, color: '#F59E0B' },
    { name: 'Testing', members: 'E2E & Unit', pct: 74, color: '#a78bfa' }
  ] as NetworkItem[],
  tickerItems: [
    { sym: 'REACT', val: 'v18', chg: 'ACTIVE', up: true },
    { sym: 'NEXT.JS', val: 'v14', chg: 'SSR/SSG', up: true },
    { sym: 'TYPESCRIPT', val: 'v5.4', chg: 'STRICT', up: true },
    { sym: 'TAILWIND', val: 'v3.4', chg: 'UTILITY', up: true },
    { sym: 'GSAP', val: 'v3.12', chg: 'ANIMATED', up: true },
    { sym: 'NODE.JS', val: 'v20', chg: 'BACKEND', up: true },
    { sym: 'POSTGRES', val: 'v16', chg: 'DB', up: true },
    { sym: 'DOCKER', val: 'v24', chg: 'CONTAINER', up: true },
    { sym: 'JEST', val: 'v29', chg: 'ROBUST', up: true },
    { sym: 'SLA', val: '99.9%', chg: 'NOMINAL', up: true },
  ] as TickerItem[]
};
