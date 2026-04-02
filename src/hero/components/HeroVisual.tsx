/**
 * @arquivo     src/hero/components/HeroVisual.tsx
 * @módulo      Hero / Visual
 * @descrição   Lado direito do Hero HealthBridge (Mercados, Gráficos, Cobertura).
 */
import React, { useState, useEffect } from 'react';
import styles from '../Hero.module.css';
import { HERO_CONFIG } from '../hero.config';
import { useHeroChart } from '../hooks/useHeroChart';

export const HeroVisual: React.FC = () => {
  const { chartRef } = useHeroChart();
  const [prices, setPrices] = useState(HERO_CONFIG.marketData.map(d => parseFloat(d.val)));

  useEffect(() => {
    const interval = setInterval(() => {
      setPrices(prev => prev.map(p => p + (Math.random() - 0.49) * 0.5));
    }, 2200);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className={`${styles.rightCol} animate-right`}>
      {/* Market Data */}
      <div className={styles.cardPanel}>
        <div className={styles.cardTitle}>Tecnologias · Versões Atuais</div>
        <div className={styles.marketList}>
          {HERO_CONFIG.marketData.map((data, i) => (
            <div key={data.sym} className={styles.marketItem}>
              <span className={styles.marketSym}>{data.sym}</span>
              <div className={styles.marketBar}>
                <div 
                  className={styles.marketFill} 
                  style={{ width: `${data.fillPct}%`, backgroundColor: data.fillColor }} 
                />
              </div>
              <span className={styles.marketVal}>v {prices[i].toFixed(2)}</span>
              <span className={`${styles.marketChg} ${data.up ? styles.chgUp : styles.chgDn}`}>
                {data.chg}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Sparkline Chart */}
      <div className={styles.cardPanel}>
        <div className={styles.cardTitle}>Performance · 30 Dias</div>
        <div className={styles.chartWrap}>
          <canvas ref={chartRef}></canvas>
        </div>
      </div>

      {/* Network Coverage */}
      <div className={styles.cardPanel}>
        <div className={styles.cardTitle}>Arquitetura & Otimização</div>
        <div className={styles.networkGrid}>
          {HERO_CONFIG.networkCoverage.map((net, i) => (
            <div key={i} className={styles.netItem}>
              <div className={styles.netName}>{net.name}</div>
              <div className={styles.netMembers}>{net.members}</div>
              <div className={styles.netBar}>
                <div 
                  className={styles.netFill} 
                  style={{ width: `${net.pct}%`, backgroundColor: net.color }} 
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
