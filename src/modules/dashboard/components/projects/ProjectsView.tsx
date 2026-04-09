"use client";

import React, { useState } from 'react';
import { ArrowLeft, ArrowRight } from 'lucide-react';
import { PROJ_CATEGORIES, generateProjItems } from '../../lib/data';
import { Modal } from '../shared/Modal';

export const ProjectsView = () => {
    const [selectedCategory, setSelectedCategory] = useState<any | null>(null);
    const [selectedItem, setSelectedItem] = useState<any | null>(null);

    const items = selectedCategory ? generateProjItems(selectedCategory.id) : [];

    const handleOpenCategory = (cat: any) => {
        setSelectedCategory(cat);
    };

    return (
        <section className="space-y-10 animate-fade-in w-full">
            {!selectedCategory ? (
                // Categories Grid
                <div>
                    <div className="mb-10">
                        <h2 className="text-3xl font-bold font-head mb-2 text-slate-800 dark:text-white">
                            Portfolio de Projetos
                        </h2>
                        <p className="text-slate-500 font-medium">Cases reais desenvolvidos para Finanças e Saúde.</p>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                        {PROJ_CATEGORIES.map(c => (
                            <div 
                                key={c.id} 
                                className="cat-card bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-8 cursor-pointer group rounded-[2rem] hover:-translate-y-1 transition-all duration-300 shadow-sm hover:shadow-xl"
                                onClick={() => handleOpenCategory(c)}
                            >
                                <div className="w-14 h-14 rounded-2xl flex items-center justify-center text-3xl mb-6 bg-slate-50 dark:bg-slate-800 shadow-sm transition-colors font-head">
                                    {c.icon}
                                </div>
                                <h3 className="text-xl font-bold mb-3 font-head">{c.name}</h3>
                                <p className="text-slate-500 text-sm mb-6 leading-relaxed">{c.desc}</p>
                                <span className="text-xs font-bold text-primary flex items-center gap-2 transition-transform group-hover:translate-x-1">
                                    Explorar {c.count} Projetos <ArrowRight className="w-4 h-4" />
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            ) : (
                // Items Grid
                <div>
                    <button 
                        onClick={() => setSelectedCategory(null)}
                        className="flex items-center gap-2 text-primary font-bold hover:underline mb-8 font-head"
                    >
                        <ArrowLeft className="w-4 h-4" /> Setores
                    </button>
                    <div className="mb-10">
                        <h2 className="text-3xl font-bold font-head text-slate-800 dark:text-white">
                            {selectedCategory.icon} {selectedCategory.name}
                        </h2>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-5 gap-6">
                        {items.map((item, i) => (
                            <div 
                                key={item.id} 
                                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 rounded-[2rem] hover:shadow-xl cursor-pointer group transition-all duration-300"
                                onClick={() => setSelectedItem(item)}
                            >
                                <div className="flex justify-between items-start mb-6">
                                    <div className="text-2xl">{selectedCategory.icon}</div>
                                    <span className="text-[10px] font-mono text-slate-300">
                                        #{String(item.id).padStart(3, '0')}
                                    </span>
                                </div>
                                <h4 className="font-bold text-sm mb-2 group-hover:text-primary transition-colors text-slate-800 dark:text-white">
                                    {item.name}
                                </h4>
                                <p className="text-[11px] text-slate-500 mb-6 leading-relaxed">
                                    {item.snippet}
                                </p>
                                <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
                                    <span className="text-[9px] font-black px-2 py-1 bg-slate-100 dark:bg-slate-800 rounded-lg uppercase tracking-widest text-slate-600 dark:text-slate-300">
                                        {item.level}
                                    </span>
                                    <span className="text-[9px] font-bold text-primary font-mono">
                                        {item.tech}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <Modal 
                isOpen={!!selectedItem} 
                onClose={() => setSelectedItem(null)}
                title={selectedItem?.name || ''}
                subtitle={`PROJETO • ${selectedItem?.tech || ''}`}
                icon="📁"
            >
                <div className="space-y-6">
                    <h3 className="font-bold text-xl mb-4 font-head text-slate-800 dark:text-white">Visão Técnica</h3>
                    <p className="text-slate-500 leading-relaxed">
                        Este case demonstra proficiência em arquiteturas críticas para o setor. Foco em escalabilidade e segurança de ponta-a-ponta.
                    </p>
                </div>
            </Modal>
        </section>
    );
};
