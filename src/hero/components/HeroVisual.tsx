/**
 * @arquivo     src/hero/components/HeroVisual.tsx
 * @módulo      Hero / Visual Decorativo
 * @descrição   Sub-componente visual decorativo da seção Hero. Renderiza:
 *              - Editor de código estilizado com syntax highlighting
 *              - Cartões flutuantes de métricas (Uptime e Speed)
 *              - Pontos decorativos pulsantes
 *
 * @como-usar   Renderizado internamente pelo Hero.tsx.
 *              <HeroVisual />
 *
 * @dependências ../Hero.module.css, ../hero.config (HERO_CONFIG)
 * @notas       A função auxiliar `getWordColor` aplica syntax highlighting
 *              simples baseado em palavras-chave. Expanda conforme necessário.
 */
import React from 'react';
import styles from '../Hero.module.css';
import { HERO_CONFIG } from '../hero.config';

export const HeroVisual: React.FC = () => {
    return (
        <div className="relative w-full aspect-square lg:aspect-auto h-full min-h-[400px] flex items-center justify-center">
            {/* Trecho de Editor de Código */}
            <div className={`${styles.glass} z-20 w-full max-w-lg shadow-2xl overflow-hidden`}>
                {/* Cabeçalho do Editor */}
                <div className="flex items-center justify-between px-4 py-3 bg-white/5 border-b border-white/10">
                    <div className="flex gap-2">
                        <div className="w-3 h-3 rounded-full bg-[#ffb4ab]/40"></div>
                        <div className="w-3 h-3 rounded-full bg-[#bdf4ff]/40"></div>
                        <div className="w-3 h-3 rounded-full bg-[#b0c6ff]/40"></div>
                    </div>
                    <span className="text-[10px] font-mono text-[#c3c6d4] uppercase tracking-widest">
                        {HERO_CONFIG.editor.filename}
                    </span>
                </div>

                {/* Conteúdo do Editor com syntax highlighting */}
                <div className="p-6 font-mono text-sm leading-relaxed overflow-hidden bg-[#1e1f25]/40">
                    {HERO_CONFIG.editor.lines.map((line) => (
                        <div key={line.num} className="flex gap-4">
                            <span className="text-[#8d909d]/40 select-none">{line.num}</span>
                            <div className="flex gap-1">
                                {line.content === '' ? <span>&nbsp;</span> : (
                                    line.content.split(' ').map((word, idx) => (
                                        <span key={idx} style={{ color: getWordColor(word) }}>
                                            {word}{' '}
                                        </span>
                                    ))
                                )}
                                {line.hasCursor && <span className={styles.cursor} />}
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Cartão Flutuante 1: Uptime */}
            <div className="absolute top-0 right-0 lg:-right-4 lg:-top-10 z-30 glass-panel p-4 rounded-lg bg-[rgba(30,31,37,0.7)] backdrop-blur-xl border border-white/10 shadow-xl flex items-center gap-4">
                <div className="w-10 h-10 rounded-full bg-[#bdf4ff]/10 flex items-center justify-center">
                    <span className="material-symbols-outlined text-[#bdf4ff]" style={{ fontVariationSettings: "'FILL' 1" }}>speed</span>
                </div>
                <div>
                    <p className="text-[10px] text-[#c3c6d4] font-bold tracking-widest uppercase">Uptime</p>
                    <h4 className="text-lg font-black text-[#e3e1e9]">99.99%</h4>
                </div>
            </div>

            {/* Cartão Flutuante 2: Velocidade */}
            <div className="absolute bottom-10 left-0 lg:-left-12 lg:bottom-4 z-30 glass-panel p-4 rounded-lg bg-[rgba(30,31,37,0.7)] backdrop-blur-xl border border-white/10 shadow-xl flex items-center gap-4">
                <div className="w-10 h-10 rounded-full bg-[#f8acff]/10 flex items-center justify-center">
                    <span className="material-symbols-outlined text-[#f8acff]" style={{ fontVariationSettings: "'FILL' 1" }}>bolt</span>
                </div>
                <div>
                    <p className="text-[10px] text-[#c3c6d4] font-bold tracking-widest uppercase">Speed</p>
                    <h4 className="text-lg font-black text-[#e3e1e9]">&lt; 100ms</h4>
                </div>
            </div>

            {/* Decoração: Pontos Pulsantes */}
            <div className="absolute top-1/4 left-1/4 w-1 h-1 bg-[#00e3fd] rounded-full shadow-[0_0_10px_#00e3fd]"></div>
            <div className="absolute bottom-1/3 right-1/4 w-1.5 h-1.5 bg-[#b0c6ff] rounded-full shadow-[0_0_10px_#b0c6ff]"></div>
        </div>
    );
};

// Utilitário simples de syntax highlighting para palavras-chave TypeScript/JSX
function getWordColor(word: string): string {
    if (['import', 'from', 'const', 'return', 'export', 'default'].includes(word)) return '#f8acff'; // tertiary
    if (['Engine', 'App'].includes(word)) return '#bdf4ff'; // secondary
    if (word.startsWith("'") || word.startsWith('"')) return '#b0c6ff'; // primary
    return '#e3e1e9'; // onSurface
}
