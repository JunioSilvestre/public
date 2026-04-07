"use client";

/**
 * @file        src/works/CTA.tsx
 * @module      Works / CTA
 * @description Call-to-action component for the bottom of the works section.
 */

import React from 'react';
import { Rocket } from 'lucide-react';

const CTA: React.FC = () => {
  return (
    <div className="mt-20 p-8 rounded-3xl bg-white border border-slate-200 flex flex-col md:flex-row items-center justify-between gap-8 mb-20 shadow-sm">
      <div className="flex items-center gap-6">
        <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-indigo-500 rounded-full flex items-center justify-center text-white shadow-lg">
          <Rocket className="w-8 h-8" />
        </div>
        <div>
          <p className="text-slate-900 font-bold text-lg leading-tight">
            Ready to take your project to the next level?
          </p>
          <p className="text-slate-500 text-sm">Technical expertise and a refined eye for the Front-End.</p>
        </div>
      </div>
      <a 
        href="#contact"
        className="w-full md:w-auto px-10 py-4 bg-slate-900 text-white rounded-2xl font-bold hover:bg-slate-800 transition-all text-center"
      >
        Let's Talk
      </a>
    </div>
  );
};

export default CTA;
