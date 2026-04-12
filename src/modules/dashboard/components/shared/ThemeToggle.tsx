"use client";

import React, { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';

export const ThemeToggle = () => {
    const [theme, setTheme] = useState<'light' | 'dark'>('light');
    const [isAnimating, setIsAnimating] = useState(false);

    useEffect(() => {
        if (
            localStorage.getItem('theme') === 'dark' ||
            (!('theme' in localStorage) &&
                window.matchMedia('(prefers-color-scheme: dark)').matches)
        ) {
            setTheme('dark');
            document.documentElement.classList.add('dark');
        } else {
            setTheme('light');
            document.documentElement.classList.remove('dark');
        }
    }, []);

    const toggleTheme = () => {
        setIsAnimating(true);
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);

        if (newTheme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }

        setTimeout(() => setIsAnimating(false), 500);
    };

    const isDark = theme === 'dark';

    return (
        <button
            onClick={toggleTheme}
            className={`
                relative w-14 h-8 rounded-full p-1 transition-all duration-500 ease-out
                focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50
                ${isDark
                    ? 'bg-gradient-to-r from-indigo-600 to-violet-700 shadow-lg shadow-indigo-500/20'
                    : 'bg-gradient-to-r from-sky-300 to-blue-400 shadow-lg shadow-sky-300/30'
                }
            `}
            aria-label="Toggle Theme"
            id="theme-toggle"
            role="switch"
            aria-checked={isDark}
        >
            {/* Stars / clouds background decoration */}
            <span className={`absolute inset-0 rounded-full overflow-hidden transition-opacity duration-500 ${isDark ? 'opacity-100' : 'opacity-0'}`}>
                <span className="absolute top-1.5 left-2 w-1 h-1 bg-white/60 rounded-full" />
                <span className="absolute top-3 left-4 w-0.5 h-0.5 bg-white/40 rounded-full" />
                <span className="absolute top-2 right-3 w-0.5 h-0.5 bg-white/50 rounded-full" />
            </span>

            {/* Sliding knob */}
            <span
                className={`
                    flex items-center justify-center w-6 h-6 rounded-full
                    bg-white shadow-md
                    transition-all duration-500 ease-out
                    ${isDark ? 'translate-x-6' : 'translate-x-0'}
                    ${isAnimating ? 'scale-90' : 'scale-100'}
                `}
            >
                {isDark ? (
                    <Moon
                        className={`w-3.5 h-3.5 text-indigo-600 transition-all duration-500 ${isAnimating ? 'rotate-[360deg] scale-75' : 'rotate-0 scale-100'}`}
                    />
                ) : (
                    <Sun
                        className={`w-3.5 h-3.5 text-amber-500 transition-all duration-500 ${isAnimating ? '-rotate-180 scale-75' : 'rotate-0 scale-100'}`}
                    />
                )}
            </span>
        </button>
    );
};
