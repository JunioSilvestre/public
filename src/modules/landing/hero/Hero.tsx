/**
 * @arquivo     src/hero/Hero.tsx
 * @módulo      Hero / Componente Principal
 * @descrição   Orquestração do Hero Portfólio. Removido branding específico
 *              de saúde conforme solicitado.
 */
import React, { useState, useEffect } from 'react';
import styles from './Hero.module.css';
import { HeroContent } from './components/HeroContent';
import { HeroVisual } from './components/HeroVisual';
import { useHeroCanvas } from './hooks/useHeroCanvas';
import { useHealthBridgeAnimations } from './hooks/useHealthBridgeAnimations';
import { HERO_CONFIG } from './hero.config';

export const Hero: React.FC = () => {
  const { canvasRef } = useHeroCanvas();
  useHealthBridgeAnimations();
  const [uptime, setUptime] = useState(99.97);

  useEffect(() => {
    const interval = setInterval(() => {
      setUptime(u => u + (Math.random() - 0.5) * 0.001);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className={styles.hero} id="hero">
      <canvas ref={canvasRef} className={styles.bgCanvas}></canvas>
      <div className={styles.overlayLeft}></div>
      <div className={styles.overlayRight}></div>
      <div className={styles.overlayBottom}></div>
      <div className={styles.scanLine}></div>

      {/* Floating Data Chips — Versão Genérica de Portfólio */}
      <div className={`${styles.dataChip} animate-chip`} style={{ top: '150px', left: '720px' }}>
        <div className={styles.chipLabel}>TOTAL PROJECTS</div>
        <div className={styles.chipVal}>50+</div>
        <div className={`${styles.chipSub} ${styles.chipUp}`}>▲ Active Development</div>
      </div>
      
      <div className={`${styles.dataChip} animate-chip`} style={{ top: '240px', left: '850px' }}>
        <div className={styles.chipLabel}>CLIENTS SERVED</div>
        <div className={styles.chipVal}>120+</div>
        <div className={`${styles.chipSub} ${styles.chipUp}`}>▲ 5 Continents</div>
      </div>

      <div className={`${styles.dataChip} animate-chip`} style={{ top: '350px', left: '770px' }}>
        <div className={styles.chipLabel}>SYSTEM UPTIME</div>
        <div className={styles.chipVal}>{uptime.toFixed(2)}%</div>
        <div className={`${styles.chipSub} ${styles.chipUp}`}>▲ Highly Available</div>
      </div>

      {/* TOPBAR — Simplificado (Sem links, logo HealthBridge ou botões) */}
      <nav className={styles.topbar}>
        <div className={styles.logo}>
          <div className={styles.logoIcon}>
            <svg viewBox="0 0 18 18" fill="none" width="18" height="18">
              <path d="M4 4l10 10M4 14l10-10" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          Software Engineer
        </div>
        {/* Nav Links e botões removidos conforme solicitado */}
        <div className={styles.navRight}>
          {/* Espaço reservado se necessário futuramente */}
        </div>
      </nav>

      {/* MAIN CONTENT */}
      <div className={styles.mainContent}>
        <HeroContent />
        <HeroVisual />
      </div>

      {/* TICKER — Versão de Tech Stack */}
      <div className={styles.tickerBar}>
        <div className={styles.tickerLabel}>◉ STACK & PERFORMANCE</div>
        <div className={styles.tickerTrack}>
          <div className={styles.tickerInner}>
            {[...HERO_CONFIG.tickerItems, ...HERO_CONFIG.tickerItems].map((item, i) => (
              <span key={i} className={styles.tickItem}>
                <span className={styles.tickSym}>{item.sym}</span>
                <span className={styles.tickVal}>{item.val}</span>
                <span className={item.up ? styles.tickUp : styles.tickDn}>{item.chg}</span>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Hero;
