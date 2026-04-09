"use client";

import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

interface DashboardLayoutProps {
    children: React.ReactNode;
}

export const DashboardLayout = ({ children }: DashboardLayoutProps) => {
    const [isSidebarOpen, setSidebarOpen] = useState(false);
    const [isSidebarExpanded, setSidebarExpanded] = useState(false);

    const toggleSidebarMobile = () => setSidebarOpen(!isSidebarOpen);
    const closeSidebarMobile = () => setSidebarOpen(false);

    return (
        <div className="w-full min-h-screen flex relative shadow-2xl bg-bgLight dark:bg-bgDark overflow-x-hidden text-slate-900 dark:text-slate-100 transition-colors duration-300">
            {/* Overlay for mobile sidebar */}
            {isSidebarOpen && (
                <div 
                    className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-40 transition-opacity lg:hidden"
                    onClick={closeSidebarMobile}
                />
            )}

            <Sidebar 
                isOpen={isSidebarOpen} 
                isExpanded={isSidebarExpanded}
                setExpanded={setSidebarExpanded}
            />

            <main className="flex-1 flex flex-col min-w-0 transition-all duration-300 ease-in-out">
                <Header toggleSidebarMobile={toggleSidebarMobile} />
                <div className="p-6 md:p-10 space-y-8 overflow-y-auto max-h-[calc(100vh-80px)] scroll-smooth">
                    {children}
                </div>
            </main>
        </div>
    );
};
