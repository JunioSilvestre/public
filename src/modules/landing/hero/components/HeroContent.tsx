/**
 * @arquivo     src/hero/components/HeroContent.tsx
 * @módulo      Hero / Conteúdo
 * @descrição   Lado esquerdo do Hero Portfólio.
 *              Inclui efeito de máquina de escrever no título e melhorias de layout.
 */
import React, { useState, useEffect } from 'react';
import styles from '../Hero.module.css';
import { HERO_CONFIG } from '../hero.config';
import { Eye } from 'lucide-react';

export const HeroContent: React.FC = () => {
  const [displayText, setDisplayText] = useState('');
  const fullText = HERO_CONFIG.headline.text;
  const speed = 50; // Velocidade em ms

  useEffect(() => {
    let i = 0;
    const timer = setInterval(() => {
      if (i < fullText.length) {
        setDisplayText(fullText.substring(0, i + 1));
        i++;
      } else {
        clearInterval(timer);
      }
    }, speed);

    return () => clearInterval(timer);
  }, [fullText]);

  return (
    <div className={styles.leftCol}>
      <div className={`${styles.badge} animate-in`}>
        <div className={styles.badgeDot}></div>
        {HERO_CONFIG.badge}
      </div>

      <h1 className={`${styles.headline} animate-in`}>
        {displayText}
        <span className={styles.cursor}>|</span>
      </h1>

      <p className={`${styles.subline} animate-in`}>
        {HERO_CONFIG.subHeadline}
      </p>

      <div className={`${styles.ctaRow} animate-in`}>
        <button className={styles.ctaPrimary}>
          <Eye size={18} className="mr-2" />
          {HERO_CONFIG.ctas.primary.label}
        </button>
        <button className={styles.ctaSecondary}>
          {HERO_CONFIG.ctas.secondary.label}
          <span className={styles.arrowIcon}>→</span>
        </button>
      </div>

      <div className={`${styles.statsRow} animate-in`}>
        {HERO_CONFIG.stats.map((stat, i) => (
          <div key={i} className={styles.statItem}>
            <div className={styles.statNum}>
              {stat.value}<span>{stat.suffix}</span>
            </div>
            <div className={styles.statLabel}>{stat.label}</div>
            <div className={`${styles.statTrend} ${stat.up ? styles.up : styles.dn}`}>
              {stat.trend}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
