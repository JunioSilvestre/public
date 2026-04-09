"use client";

import React from 'react';

export const ProfileView = () => {
    return (
        <section className="animate-fade-in w-full max-w-5xl mx-auto">
            <div className="bg-white dark:bg-slate-900 rounded-[2.5rem] border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm w-full mx-auto">
                <div className="h-[180px] bg-gradient-to-br from-primary to-secondary rounded-t-[2.5rem]"></div>
                <div className="px-6 md:px-10 pb-12">
                    <div className="relative flex flex-col md:flex-row md:justify-between md:items-end -mt-16 mb-8 gap-4">
                        <div className="w-32 h-32 rounded-[2.5rem] bg-white dark:bg-slate-900 p-2 shadow-xl border-4 border-slate-50 dark:border-slate-800 shrink-0">
                            <img 
                                src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix" 
                                alt="Avatar" 
                                className="w-full h-full rounded-[2rem] object-cover"
                            />
                        </div>
                        <button className="w-max px-6 py-2.5 bg-primary text-white rounded-xl font-bold text-sm shadow-lg mb-4 hover:bg-primary/90 transition-colors">
                            Editar Perfil
                        </button>
                    </div>
                    <h2 className="text-3xl font-bold font-head text-slate-800 dark:text-white">John Silva</h2>
                    <p className="text-slate-500 text-lg">Arquiteto de Sistemas Sênior</p>
                </div>
            </div>
        </section>
    );
};
