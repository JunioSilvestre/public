/**
 * @arquivo     src/hero/components/HeroContent.tsx
 * @módulo      Hero / Conteúdo
 * @descrição   Sub-componente de conteúdo textual da seção Hero. Renderiza:
 *              - Badge de disponibilidade (Available for hire)
 *              - Headline principal com palavra de destaque colorida
 *              - Sub-headline descritivo
 *              - Badges de stack tecnológica
 *              - Botões de CTA (Ver Projetos / Contato)
 *
 * @como-usar   Renderizado internamente pelo Hero.tsx.
 *              <HeroContent />
 *
 * @dependências ../Hero.module.css, ../hero.config (HERO_CONFIG)
 * @notas       O texto do headline é controlado por HERO_CONFIG. Para customizar,
 *              edite hero.config.ts sem alterar este componente.
 */
import React from 'react';
import styles from '../Hero.module.css';
import { HERO_CONFIG } from '../hero.config';

export const HeroContent: React.FC = () => {
    return (
        <div className={styles.content}>
            <div className="flex flex-col space-y-8 text-center lg:text-left">
                <div className="space-y-4">
                    <span className={styles.badgeHighlight}>
                        Available for hire
                    </span>
                    <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-[#e3e1e9] tracking-tighter leading-[1.1]">
                        {HERO_CONFIG.headline.prefix} <span className="text-[#b0c6ff]">{HERO_CONFIG.headline.highlight}</span> {HERO_CONFIG.headline.suffix}
                    </h1>
                    <p className="text-lg md:text-xl lg:text-2xl text-[#c3c6d4] font-medium max-w-xl mx-auto lg:mx-0">
                        {HERO_CONFIG.subHeadline}
                    </p>
                </div>

                {/* Badges da Stack Tecnológica */}
                <div className="flex flex-wrap gap-3 justify-center lg:justify-start">
                    {HERO_CONFIG.techStack.map((tech) => (
                        <div key={tech.label} className={styles.badge}>
                            <span
                                className={styles.dot}
                                style={{ backgroundColor: tech.color, boxShadow: `0 0 8px ${tech.glowColor}` }}
                            />
                            <span className="text-xs font-bold tracking-tight text-[#c3c6d4] uppercase">
                                {tech.label}
                            </span>
                        </div>
                    ))}
                </div>

                {/* CTAs (Chamadas para Ação) */}
                <div className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start pt-4">
                    <button className={styles.primaryBtn}>
                        VIEW PROJECTS
                        <span className="material-symbols-outlined text-sm">arrow_forward</span>
                    </button>
                    <button className={styles.secondaryBtn}>
                        CONTACT ME
                    </button>
                </div>
            </div>
        </div>
    );
};
