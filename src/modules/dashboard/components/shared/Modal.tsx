"use client";

import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
    isOpen: boolean;
    onClose: () => void;
    title: string;
    subtitle?: string;
    icon?: string | React.ReactNode;
    children: React.ReactNode;
}

export const Modal = ({ isOpen, onClose, title, subtitle, icon, children }: ModalProps) => {
    // Prevent scrolling when modal is open
    useEffect(() => {
        if (isOpen) {
            document.body.style.overflow = 'hidden';
        } else {
            document.body.style.overflow = '';
        }
        return () => {
            document.body.style.overflow = '';
        };
    }, [isOpen]);

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-[100] bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 transition-all duration-300">
            <div className="bg-white dark:bg-slate-900 w-full max-w-5xl max-h-[90vh] rounded-[2.5rem] overflow-hidden shadow-2xl flex flex-col scale-100 transition-all duration-300">
                {/* Header Container */}
                <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between bg-white dark:bg-slate-900 shrink-0">
                    <div className="flex items-center gap-4">
                        {icon && (
                            <div className="text-4xl p-2 bg-slate-50 dark:bg-slate-800 rounded-2xl flex items-center justify-center w-14 h-14">
                                {icon}
                            </div>
                        )}
                        <div>
                            <h2 className="text-xl font-bold font-head text-slate-800 dark:text-slate-100">{title}</h2>
                            {subtitle && (
                                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">
                                    {subtitle}
                                </p>
                            )}
                        </div>
                    </div>
                    <button 
                        onClick={onClose}
                        className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-colors text-slate-500"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>

                {/* Content Container */}
                <div className="flex-1 overflow-y-auto p-6 md:p-12 relative bg-white dark:bg-slate-900">
                    {children}
                </div>
            </div>
        </div>
    );
};
