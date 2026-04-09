"use client";

import React, { useState } from 'react';
import { LayoutGrid, Layers, ArrowLeft, Clock } from 'lucide-react';
import { KB_CATEGORIES, generateKBItems } from '../../lib/data';
import { Modal } from '../shared/Modal';

export const KnowledgeView = () => {
    const [filter, setFilter] = useState('all');
    const [selectedCategory, setSelectedCategory] = useState<any | null>(null);
    const [selectedItem, setSelectedItem] = useState<any | null>(null);

    const filteredCategories = filter === 'all' 
        ? KB_CATEGORIES 
        : KB_CATEGORIES.filter(c => c.type === filter);

    const items = selectedCategory ? generateKBItems(selectedCategory.name, selectedCategory.icon) : [];

    const getLevelStyle = (lvl: string) => {
        if (lvl === 'básico') return 'bg-emerald-50 text-emerald-600 dark:bg-emerald-900/20';
        if (lvl === 'intermediário') return 'bg-amber-50 text-amber-600 dark:bg-amber-900/20';
        return 'bg-violet-50 text-violet-600 dark:bg-violet-900/20';
    };

    return (
        <section className="space-y-10 animate-fade-in w-full">
            {!selectedCategory ? (
                <div>
                    <div className="mb-10">
                        <h2 className="text-3xl font-bold font-head mb-2 text-slate-800 dark:text-white">
                            Base de Conhecimento
                        </h2>
                        <p className="text-slate-500 text-sm mb-8 font-medium">
                            Explore os temas, selecione uma categoria e acesse exemplos práticos
                        </p>

                        <div className="flex items-center gap-3 mb-8">
                            <span className="flex items-center gap-2 px-3 py-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-full text-xs font-bold text-slate-500 shadow-sm">
                                <LayoutGrid className="w-4 h-4" /> 8 categorias
                            </span>
                            <span className="flex items-center gap-2 px-3 py-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-full text-xs font-bold text-slate-500 shadow-sm">
                                <Layers className="w-4 h-4" /> 247 exemplos
                            </span>
                        </div>

                        <div className="flex flex-wrap gap-2">
                            <button 
                                onClick={() => setFilter('all')}
                                className={`px-6 py-2.5 text-xs font-bold rounded-full transition-all shadow-sm ${filter === 'all' ? 'bg-primary text-white shadow-lg shadow-primary/20' : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-primary'}`}
                            >
                                Todos
                            </button>
                            <button 
                                onClick={() => setFilter('frontend')}
                                className={`px-6 py-2.5 text-xs font-bold rounded-full transition-all shadow-sm ${filter === 'frontend' ? 'bg-primary text-white shadow-lg shadow-primary/20' : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-primary'}`}
                            >
                                Frontend
                            </button>
                            <button 
                                onClick={() => setFilter('backend')}
                                className={`px-6 py-2.5 text-xs font-bold rounded-full transition-all shadow-sm ${filter === 'backend' ? 'bg-primary text-white shadow-lg shadow-primary/20' : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-primary'}`}
                            >
                                Backend
                            </button>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-6">
                        {filteredCategories.map(c => (
                            <div 
                                key={c.id}
                                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-8 cursor-pointer flex flex-col h-full relative overflow-hidden rounded-[2rem] hover:-translate-y-1 transition-transform shadow-sm hover:shadow-xl"
                                onClick={() => setSelectedCategory(c)}
                            >
                                <div className="w-12 h-12 rounded-2xl flex items-center justify-center text-2xl mb-6 bg-slate-50 dark:bg-slate-800 shadow-sm">
                                    {c.icon}
                                </div>
                                <h3 className="text-xl font-bold mb-3 font-head text-slate-800 dark:text-white">{c.name}</h3>
                                <p className="text-slate-500 text-xs leading-relaxed mb-8 flex-1">{c.desc}</p>
                                <div className="flex items-center justify-between mt-auto">
                                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{c.count} exemplos</span>
                                    <span className="text-[9px] font-black px-2 py-0.5 bg-slate-100 dark:bg-slate-800 rounded-full" style={{ color: c.color }}>
                                        {c.tag.toUpperCase()}
                                    </span>
                                </div>
                                <div className="absolute bottom-0 left-0 right-0 h-1 bg-slate-100 dark:bg-slate-800">
                                    <div className="h-full" style={{ width: `${c.progress}%`, backgroundColor: c.color }}></div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            ) : (
                <div>
                    <button 
                        onClick={() => setSelectedCategory(null)}
                        className="flex items-center gap-2 text-primary font-bold hover:underline mb-8 font-head"
                    >
                        <ArrowLeft className="w-4 h-4" /> Voltar para Categorias
                    </button>

                    <div className="mb-10 space-y-4">
                        <p className="text-slate-500 text-sm max-w-3xl font-medium leading-relaxed">
                            {selectedCategory.desc}
                        </p>
                        <div className="flex items-center gap-3">
                            <span className="px-3 py-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-full text-xs font-bold text-slate-500 shadow-sm">
                                {selectedCategory.count} exemplos
                            </span>
                            <span className="px-3 py-1 bg-indigo-50 dark:bg-indigo-900/20 text-primary text-[10px] font-black rounded-full uppercase tracking-wider">
                                {selectedCategory.tag}
                            </span>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-5 gap-4">
                        {items.map((item, i) => (
                            <div 
                                key={item.id}
                                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 rounded-[2rem] hover:shadow-xl cursor-pointer group relative overflow-hidden transition-shadow"
                                onClick={() => setSelectedItem(item)}
                            >
                                <div className="flex justify-between items-start mb-6">
                                    <div className="w-10 h-10 rounded-xl bg-slate-50 dark:bg-slate-800 flex items-center justify-center text-xl shadow-sm">
                                        {selectedCategory.icon}
                                    </div>
                                    <span className="text-[10px] font-mono text-slate-300 group-hover:text-primary transition-colors">
                                        #{String(item.id).padStart(3, '0')}
                                    </span>
                                </div>
                                <h4 className="font-bold text-sm mb-2 font-head group-hover:text-primary transition-colors text-slate-800 dark:text-white">
                                    {item.name}
                                </h4>
                                <p className="text-[11px] text-slate-500 line-clamp-2 mb-6">
                                    {item.snippet}
                                </p>
                                <div className="flex items-center justify-between pt-4 border-t border-slate-50 dark:border-slate-800">
                                    <span className={`text-[9px] font-black px-2 py-0.5 rounded-md uppercase tracking-wider ${getLevelStyle(item.level)}`}>
                                        {item.level}
                                    </span>
                                    <span className="text-[10px] text-slate-400 font-bold flex items-center gap-1.5">
                                        <Clock className="w-3.5 h-3.5" /> {item.time}
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
                subtitle={`CONHECIMENTO • ${selectedItem?.level.toUpperCase()}`}
                icon={selectedItem?.icon}
            >
                <div className="space-y-6">
                    <p className="text-slate-500 leading-relaxed font-medium">
                        Implementação prática seguindo diretrizes de Clean Code e Performance para {selectedItem?.name}.
                    </p>
                    <div className="flex bg-slate-50 dark:bg-slate-800/40 p-1 border-b border-slate-100 dark:border-slate-800 max-w-max rounded-xl mb-4 mt-6">
                        <button className="px-6 py-2.5 text-sm font-bold rounded-xl bg-white dark:bg-slate-900 shadow-sm text-slate-800 dark:text-white">
                            Conteúdo
                        </button>
                        <button className="px-6 py-2.5 text-sm font-bold text-slate-500 hover:text-slate-700 dark:hover:text-slate-300">
                            Código
                        </button>
                    </div>
                    {/* Aqui renderiza o conteúdo Markdown, PDF, Docs ou Textos estáticos futuramente */}
                    <div className="p-4 bg-slate-50 dark:bg-slate-800 rounded-xl text-slate-500 text-sm italic">
                        Área reservada para o renderizador de documentos...
                    </div>
                </div>
            </Modal>
        </section>
    );
};
