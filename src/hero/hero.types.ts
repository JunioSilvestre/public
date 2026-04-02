/**
 * @arquivo     src/hero/hero.types.ts
 * @módulo      Hero / Tipos TypeScript
 * @descrição   Todas as interfaces e tipos utilizados pelo Hero e seus sub-componentes.
 */
import React from 'react';

export interface NavLink {
  label: string;
  href: string;
}

export interface MarketItem {
  sym:    string;
  val:    string;
  chg:    string;
  up:     boolean;
  fillPct: number;
  fillColor: string;
}

export interface NetworkItem {
  name:     string;
  members:  string;
  pct:      number;
  color:    string;
}

export interface TickerItem {
  sym:  string;
  val:  string;
  chg:  string;
  up:   boolean;
}

export interface StatItem {
  value:  string;
  suffix?: string;
  label:  string;
  trend:  string;
  up:     boolean;
}

export interface HeroProps {
  headline?:    React.ReactNode;
  subHeadline?: string;
}
