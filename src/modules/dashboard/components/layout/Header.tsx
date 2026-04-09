"use client";

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Menu, ChevronRight } from 'lucide-react';
import { ThemeToggle } from '../shared/ThemeToggle';

interface HeaderProps {
    toggleSidebarMobile: () => void;
}

export const Header = ({ toggleSidebarMobile }: HeaderProps) => {
    const pathname = usePathname();

    const getPageTitle = () => {
        if (!pathname) return 'Dashboard';
        if (pathname === '/dashboard') return 'Dashboard';
        if (pathname.includes('/profile')) return 'Perfil Profissional';
        if (pathname.includes('/knowledge')) return 'Base de Conhecimento';
        if (pathname.includes('/projects')) return 'Portfolio de Projetos';
        return 'Dashboard';
    };

    return (
        <header className="h-20 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-6 sticky top-0 z-40 transition-all duration-300">
            <div className="flex items-center gap-4">
                <button 
                    onClick={toggleSidebarMobile}
                    className="lg:hidden p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                    <Menu className="w-6 h-6 text-slate-600 dark:text-slate-300" />
                </button>

                <div className="hidden lg:flex items-center gap-2 text-sm text-slate-500 font-medium font-head">
                    <Link href="/dashboard" className="hover:text-primary cursor-pointer transition-colors">
                        DevBoard
                    </Link>
                    <ChevronRight className="w-4 h-4 opacity-30" />
                    <span className="text-slate-900 dark:text-slate-100 font-bold uppercase tracking-tight">
                        {getPageTitle()}
                    </span>
                </div>
            </div>

            <div className="flex items-center gap-4">
                <ThemeToggle />
                
                {/* User Photo Placeholder / Upload Hook Area */}
                <Link href="/dashboard/profile">
                    <div className="relative w-9 h-9 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden ring-2 ring-white dark:ring-slate-800 cursor-pointer shadow-sm group">
                        {/* Placeholder generic user image */}
                        <img 
                            src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix" 
                            alt="User Profile" 
                            className="w-full h-full object-cover"
                        />
                        {/* Overlay on hover indicating clickability */}
                        <div className="absolute inset-0 bg-black/20 hidden group-hover:flex items-center justify-center transition-all duration-200">
                        </div>
                    </div>
                </Link>
            </div>
        </header>
    );
};
