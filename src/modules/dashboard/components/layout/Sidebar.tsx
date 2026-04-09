"use client";

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LayoutDashboard, User, Brain, FolderKanban, History, Mail, Settings } from 'lucide-react';

interface SidebarProps {
    isOpen: boolean;
    isExpanded: boolean;
    setExpanded: (val: boolean) => void;
}

export const Sidebar = ({ isOpen, isExpanded, setExpanded }: SidebarProps) => {
    const pathname = usePathname();

    const menuItems = [
        { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { path: '/dashboard/profile', label: 'Perfil', icon: User },
        { path: '/dashboard/knowledge', label: 'Conhecimentos', icon: Brain },
        { path: '/dashboard/projects', label: 'Projetos', icon: FolderKanban },
        // { path: '/dashboard/experience', label: 'Experiência', icon: History },
        // { path: '/dashboard/contact', label: 'Contato', icon: Mail },
    ];

    const isCurrentPath = (path: string) => {
        if (path === '/dashboard') return pathname === path;
        return pathname?.startsWith(path);
    };

    return (
        <aside 
            onMouseEnter={() => setExpanded(true)}
            onMouseLeave={() => setExpanded(false)}
            className={`sticky top-0 h-screen bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 transition-all duration-300 ease-in-out overflow-hidden flex flex-col z-50 
                ${isExpanded ? 'w-[280px]' : 'w-[80px] hidden lg:flex'}
                ${isOpen ? 'translate-x-0 w-[280px] fixed lg:sticky' : '-translate-x-full lg:translate-x-0 absolute lg:relative'}
            `}
        >
            <div className="h-full flex flex-col py-6 px-4">
                {/* Logo */}
                <Link href="/dashboard" className="flex items-center gap-4 mb-10 px-2 overflow-hidden cursor-pointer shrink-0">
                    <div className="min-w-[40px] w-10 h-10 rounded-xl bg-gradient-to-tr from-primary to-secondary flex items-center justify-center text-white font-bold shrink-0 shadow-lg shadow-primary/20">
                        JS
                    </div>
                    <span className={`font-bold text-xl tracking-tight whitespace-nowrap transition-opacity duration-300 font-head text-primary ${isExpanded ? 'opacity-100' : 'opacity-0'}`}>
                        John Silva
                    </span>
                </Link>

                {/* Main Menu */}
                <nav className="space-y-1 flex-1 overflow-y-auto scrollbar-hide">
                    <h3 className={`text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-4 px-3 transition-opacity duration-300 ${isExpanded ? 'opacity-100' : 'opacity-0'}`}>
                        🧭 Menu
                    </h3>

                    {menuItems.map((item) => {
                        const Icon = item.icon;
                        const active = isCurrentPath(item.path);

                        return (
                            <Link 
                                key={item.path} 
                                href={item.path}
                                className={`w-full flex items-center gap-4 px-3 py-3 rounded-xl transition-all duration-300 group
                                    ${active ? 'bg-primary/10 text-primary' : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'}
                                `}
                            >
                                <Icon className={`w-6 h-6 shrink-0 ${active ? 'text-primary' : 'text-slate-500 group-hover:text-primary'}`} />
                                <span className={`whitespace-nowrap transition-opacity duration-300 font-medium ${isExpanded ? 'opacity-100' : 'opacity-0'}`}>
                                    {item.label}
                                </span>
                            </Link>
                        );
                    })}
                </nav>

                {/* Footer Settings Area */}
                <div className="mt-auto pt-6 border-t border-slate-100 dark:border-slate-800 shrink-0">
                    <button className="w-full flex items-center gap-4 px-3 py-2.5 rounded-xl text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800">
                        <Settings className="w-6 h-6 shrink-0" />
                        <span className={`whitespace-nowrap transition-opacity duration-300 text-sm font-medium ${isExpanded ? 'opacity-100' : 'opacity-0'}`}>
                            Ajustes
                        </span>
                    </button>
                </div>
            </div>
        </aside>
    );
};
