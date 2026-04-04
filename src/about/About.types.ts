/**
 * @arquivo     src/about/About.types.ts
 * @módulo      About / Tipos
 * @descrição   Definições de interface para a seção About.
 */

export interface AboutStat {
  id: string;
  icon: string;
  label: string;
  value: string;
  colorClass: string;
}

export interface Responsibility {
  id: string;
  title: string;
  description: string;
  icon: string;
  colorClass: string;
}
