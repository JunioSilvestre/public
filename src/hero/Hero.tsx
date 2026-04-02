/**
 * @arquivo     src/hero/Hero.tsx
 * @módulo      Hero / Componente Principal
 * @descrição   Componente de seção Hero da página principal. Combina elementos
 *              visuais de fundo (grid, blobs de gradiente), o conteúdo textual
 *              (HeroContent) e o elemento visual decorativo (HeroVisual) num
 *              layout responsivo. Inclui também um indicador de scroll.
 *
 * @como-usar   import Hero from '@/hero';
 *              <Hero />
 *
 * @dependências ./Hero.module.css, ./components/HeroContent,
 *              ./components/HeroVisual, ./hooks/useHero
 * @notas       O componente usa `useHero` para controlar a visibilidade inicial
 *              com uma animação de fade-in via classe Tailwind (opacity-0 → opacity-100).
 */
import React from 'react';
import styles from './Hero.module.css';
import { HeroContent } from './components/HeroContent';
import { HeroVisual } from './components/HeroVisual';
import { useHero } from './hooks/useHero';

export const Hero: React.FC = () => {
    const { isVisible } = useHero();

    return (
        <section className={styles.hero} id="hero">
            {/* Elementos de Fundo */}
            <div className={styles.grid}></div>
            <div className={styles.blob1}></div>
            <div className={styles.blob2}></div>

            <div className={`${styles.container} transition-opacity duration-1000 ${isVisible ? 'opacity-100' : 'opacity-0'}`}>
                <div className={styles.layout}>
                    <HeroContent />
                    <HeroVisual />
                </div>
            </div>

            {/* Indicador de Rolagem */}
            <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 opacity-50">
                <span className="text-[8px] font-black tracking-[0.3em] text-[#c3c6d4] uppercase italic">Scroll</span>
                <div className="w-[1px] h-12 bg-gradient-to-b from-[#b0c6ff]/60 to-transparent"></div>
            </div>
        </section>
    );
};

export default Hero;
