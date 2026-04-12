"use client";

import React, { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import { User, Settings, LogOut, Info, Monitor, Globe, Clock, ChevronRight } from 'lucide-react';
import { useSystemInfo } from '../../hooks/useSystemInfo';

export const UserMenu = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [showInfo, setShowInfo] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);
    const timeoutRef = useRef<NodeJS.Timeout | null>(null);
    const systemInfo = useSystemInfo();

    // Close menu when clicking outside
    useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
                setIsOpen(false);
                setShowInfo(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const handleMouseEnter = () => {
        if (timeoutRef.current) clearTimeout(timeoutRef.current);
        setIsOpen(true);
    };

    const handleMouseLeave = () => {
        timeoutRef.current = setTimeout(() => {
            setIsOpen(false);
            setShowInfo(false);
        }, 300);
    };

    return (
        <div
            ref={menuRef}
            className="relative"
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
        >
            {/* Avatar Trigger */}
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="relative w-10 h-10 rounded-full overflow-hidden ring-2 ring-transparent hover:ring-primary/50 transition-all duration-300 cursor-pointer group shadow-md"
                aria-label="User menu"
                id="user-menu-trigger"
            >
                <img
                    src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix"
                    alt="User Profile"
                    className="w-full h-full object-cover bg-slate-200 dark:bg-slate-700"
                />
                {/* Pulse ring on hover */}
                <span className="absolute inset-0 rounded-full ring-2 ring-primary/0 group-hover:ring-primary/40 transition-all duration-500 group-hover:scale-110" />
            </button>

            {/* Dropdown Menu */}
            <div
                className={`absolute right-0 top-[calc(100%+8px)] w-72 rounded-2xl overflow-hidden transition-all duration-300 ease-out z-[100]
                    ${isOpen
                        ? 'opacity-100 translate-y-0 scale-100 pointer-events-auto'
                        : 'opacity-0 -translate-y-2 scale-95 pointer-events-none'
                    }
                `}
                style={{
                    background: 'rgba(255,255,255,0.85)',
                    backdropFilter: 'blur(24px) saturate(180%)',
                    WebkitBackdropFilter: 'blur(24px) saturate(180%)',
                    border: '1px solid rgba(148,163,184,0.2)',
                    boxShadow: '0 20px 60px -15px rgba(0,0,0,0.15), 0 8px 20px -8px rgba(0,0,0,0.1)',
                }}
            >
                {/* Dark mode override */}
                <div className="dark:bg-slate-900/90 dark:border-slate-700/50 rounded-2xl">
                    {/* User Header */}
                    <div className="px-5 py-4 border-b border-slate-200/60 dark:border-slate-700/40">
                        <div className="flex items-center gap-3">
                            <div className="w-11 h-11 rounded-full overflow-hidden ring-2 ring-primary/20 shrink-0">
                                <img
                                    src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix"
                                    alt="User"
                                    className="w-full h-full object-cover bg-slate-200 dark:bg-slate-700"
                                />
                            </div>
                            <div className="min-w-0">
                                <p className="text-sm font-bold text-slate-900 dark:text-white truncate font-head">
                                    John Silva
                                </p>
                                <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                                    Senior Software Engineer
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Menu Items */}
                    <div className="py-2 px-2">
                        {/* Info Button */}
                        <button
                            onClick={() => setShowInfo(!showInfo)}
                            className="w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-100/80 dark:hover:bg-slate-800/60 transition-all duration-200 group"
                            id="user-menu-info"
                        >
                            <span className="flex items-center gap-3">
                                <Info className="w-4 h-4 text-primary/70 group-hover:text-primary transition-colors" />
                                <span className="font-medium">Info</span>
                            </span>
                            <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${showInfo ? 'rotate-90' : ''}`} />
                        </button>

                        {/* Info Expandable Section */}
                        <div
                            className={`overflow-hidden transition-all duration-300 ease-out ${showInfo ? 'max-h-48 opacity-100' : 'max-h-0 opacity-0'}`}
                        >
                            <div className="mx-3 mb-2 p-3 rounded-xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/40 dark:border-slate-700/30 space-y-2.5">
                                <div className="flex items-center gap-2.5">
                                    <Clock className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                                    <div className="min-w-0">
                                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Último Acesso</p>
                                        <p className="text-xs text-slate-700 dark:text-slate-200 font-medium truncate">
                                            {systemInfo.lastAccess ?? 'Primeiro acesso'}
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2.5">
                                    <Monitor className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                                    <div className="min-w-0">
                                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Sistema Operacional</p>
                                        <p className="text-xs text-slate-700 dark:text-slate-200 font-medium truncate">
                                            {systemInfo.os || '...'}
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2.5">
                                    <Globe className="w-3.5 h-3.5 text-blue-500 shrink-0" />
                                    <div className="min-w-0">
                                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Navegador</p>
                                        <p className="text-xs text-slate-700 dark:text-slate-200 font-medium truncate">
                                            {systemInfo.browser || '...'}
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Profile Link */}
                        <Link
                            href="/dashboard/profile"
                            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-100/80 dark:hover:bg-slate-800/60 transition-all duration-200 group"
                            id="user-menu-profile"
                        >
                            <User className="w-4 h-4 text-primary/70 group-hover:text-primary transition-colors" />
                            <span className="font-medium">Perfil</span>
                        </Link>

                        {/* Settings Link */}
                        <button
                            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-100/80 dark:hover:bg-slate-800/60 transition-all duration-200 group"
                            id="user-menu-settings"
                        >
                            <Settings className="w-4 h-4 text-primary/70 group-hover:text-primary transition-colors" />
                            <span className="font-medium">Configurações</span>
                        </button>
                    </div>

                    {/* Logout Section */}
                    <div className="px-2 pb-3 pt-1 border-t border-slate-200/40 dark:border-slate-700/30 mt-1">
                        <button
                            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 transition-all duration-200 group"
                            id="user-menu-logout"
                        >
                            <LogOut className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                            <span className="font-medium">Sair</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
