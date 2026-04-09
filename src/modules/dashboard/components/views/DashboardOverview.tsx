"use client";

import React from 'react';
import Link from 'next/link';
import { Rocket, Activity } from 'lucide-react';

export const DashboardOverview = () => {
    return (
        <section className="space-y-8 animate-fade-in">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 p-10 rounded-[2.5rem] bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 text-white relative overflow-hidden shadow-xl">
                    <div className="relative z-10">
                        <span className="px-3 py-1 bg-primary/20 border border-primary/30 rounded-full text-[10px] font-bold uppercase tracking-widest text-[#a855f7] mb-4 inline-block font-head">
                            Sênior Fullstack Developer
                        </span>
                        <h1 className="text-4xl font-extrabold mb-4 font-head text-white">
                            Soluções Especialistas <br/>
                            <span className="text-primary">Fintech & Healthtech</span>
                        </h1>
                        <p className="text-slate-400 text-lg max-w-md mb-8 leading-relaxed">
                            Arquitetura de alto impacto e segurança máxima para setores de missão crítica.
                        </p>
                        <Link 
                            href="/dashboard/projects"
                            className="px-8 py-4 bg-primary text-white rounded-2xl font-bold hover:scale-105 transition-transform flex items-center gap-2 shadow-lg shadow-primary/20 w-max"
                        >
                            <Rocket className="w-5 h-5" /> Explorar Portfolio
                        </Link>
                    </div>
                    <Activity className="absolute -right-10 -bottom-10 w-80 h-80 text-white/5 rotate-12 pointer-events-none" />
                </div>
                
                <div className="bg-white dark:bg-slate-900 p-8 rounded-[2.5rem] border border-slate-200 dark:border-slate-800 flex flex-col justify-between shadow-sm">
                    <h3 className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-6 font-head">
                        Métricas do Portfolio
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                        <div className="text-center p-4 bg-slate-50 dark:bg-slate-800 rounded-3xl">
                            <p className="text-2xl font-black text-primary font-mono">20</p>
                            <p className="text-[10px] font-bold text-slate-400 uppercase">Cases Reais</p>
                        </div>
                        <div className="text-center p-4 bg-slate-50 dark:bg-slate-800 rounded-3xl">
                            <p className="text-2xl font-black text-emerald-500 font-mono">12</p>
                            <p className="text-[10px] font-bold text-slate-400 uppercase">Artigos</p>
                        </div>
                    </div>
                    <p className="text-[10px] text-slate-400 font-bold mt-4 uppercase px-2 text-center">
                        Disponível para novos desafios
                    </p>
                </div>
            </div>
        </section>
    );
};
