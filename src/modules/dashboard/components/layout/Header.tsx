"use client";

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Menu, ChevronRight, Bell, Search } from 'lucide-react';
import { ThemeToggle } from '../shared/ThemeToggle';
import { UserMenu } from './UserMenu';

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
        <header className="h-16 sm:h-[72px] w-full bg-white/70 dark:bg-slate-900/70 backdrop-blur-xl border-b border-slate-200/60 dark:border-slate-800/60 flex items-center justify-between px-4 sm:px-6 lg:px-8 sticky top-0 z-40 transition-all duration-300">
            {/* Left Section — Hamburger + Breadcrumb */}
            <div className="flex items-center gap-3 min-w-0">
                <button
                    onClick={toggleSidebarMobile}
                    className="lg:hidden p-2 -ml-1 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors duration-200"
                    aria-label="Toggle sidebar"
                    id="sidebar-toggle"
                >
                    <Menu className="w-5 h-5 text-slate-600 dark:text-slate-300" />
                </button>

                {/* Breadcrumb — desktop */}
                <div className="hidden lg:flex items-center gap-2 text-sm text-slate-500 font-medium font-head">
                    <Link
                        href="/dashboard"
                        className="hover:text-primary cursor-pointer transition-colors duration-200"
                    >
                        DevBoard
                    </Link>
                    <ChevronRight className="w-4 h-4 opacity-30" />
                    <span className="text-slate-900 dark:text-slate-100 font-bold uppercase tracking-tight">
                        {getPageTitle()}
                    </span>
                </div>

                {/* Page title — mobile only */}
                <span className="lg:hidden text-sm font-bold text-slate-900 dark:text-white uppercase tracking-tight truncate font-head">
                    {getPageTitle()}
                </span>
            </div>

            {/* Right Section — Search, Notifications, Theme, User */}
            <div className="flex items-center gap-2 sm:gap-3">
                {/* Search — icon only on mobile, expanded on desktop */}
                <button
                    className="hidden sm:flex items-center gap-2 px-3 py-2 rounded-xl bg-slate-100/80 dark:bg-slate-800/60 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-200/80 dark:hover:bg-slate-700/60 transition-all duration-200 text-sm min-w-[160px] lg:min-w-[200px]"
                    id="search-trigger"
                >
                    <Search className="w-4 h-4 shrink-0" />
                    <span className="text-slate-400 text-xs font-medium truncate">Buscar...</span>
                    <kbd className="hidden lg:inline-flex ml-auto text-[10px] bg-white dark:bg-slate-700 px-1.5 py-0.5 rounded-md border border-slate-200 dark:border-slate-600 text-slate-400 font-mono">
                        ⌘K
                    </kbd>
                </button>
                <button
                    className="sm:hidden p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors duration-200"
                    aria-label="Search"
                >
                    <Search className="w-5 h-5 text-slate-500" />
                </button>

                {/* Notifications */}
                <button
                    className="relative p-2 sm:p-2.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors duration-200"
                    aria-label="Notifications"
                    id="notifications-trigger"
                >
                    <Bell className="w-5 h-5 text-slate-500 dark:text-slate-400" />
                    {/* Notification badge */}
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-white dark:ring-slate-900" />
                </button>

                {/* Divider */}
                <div className="hidden sm:block w-px h-6 bg-slate-200 dark:bg-slate-700 mx-1" />

                {/* Theme Toggle */}
                <ThemeToggle />

                {/* User Menu */}
                <UserMenu />
            </div>
        </header>
    );
};
