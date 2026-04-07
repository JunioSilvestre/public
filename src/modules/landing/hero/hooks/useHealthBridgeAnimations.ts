/**
 * @arquivo     src/hero/hooks/useHealthBridgeAnimations.ts
 * @módulo      Hero / Hook Animações
 * @descrição   Lógica de animação de entrada usando GSAP.
 */
import { useEffect } from 'react';
import gsap from 'gsap';

export function useHealthBridgeAnimations() {
  useEffect(() => {
    const tl = gsap.timeline({ delay: 0.2 });

    gsap.set('.animate-in', { opacity: 0, y: 20 });
    gsap.set('.animate-right', { opacity: 0, x: 20 });
    gsap.set('.animate-chip', { opacity: 0 });

    tl.to('.animate-in', {
      opacity: 1,
      y: 0,
      duration: 0.5,
      stagger: 0.15,
      ease: 'power2.out'
    })
    .to('.animate-right', {
      opacity: 1,
      x: 0,
      duration: 0.6,
      ease: 'power2.out'
    }, '-=0.4')
    .to('.animate-chip', {
      opacity: 1,
      duration: 0.4,
      stagger: 0.1,
      ease: 'power2.out'
    }, '-=0.2');

    return () => {
      tl.kill();
    };
  }, []);
}
