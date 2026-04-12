/**
 * @arquivo     src/hero/hooks/useHeroCanvas.ts
 * @módulo      Hero / Hook Canvas
 * @descrição   Lógica de animação da rede de conexões ao fundo do Hero.
 *              Baseado na implementação do HealthBridge.
 */
import { useEffect, useRef } from 'react';
import { HERO_TOKENS } from '../hero.tokens';

export function useHeroCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let W: number, H: number;
    let nodes: any[] = [];
    let packets: any[] = [];
    const NODE_COUNT = 55;
    const COLORS = HERO_TOKENS.colors.nodeColors;

    const resize = () => {
      W = canvas.width = canvas.parentElement?.offsetWidth || 1440;
      H = canvas.height = canvas.parentElement?.offsetHeight || 600;
    };

    const rnd = (a: number, b: number) => a + Math.random() * (b - a);

    const initNodes = () => {
      nodes = Array.from({ length: NODE_COUNT }, (_, i) => ({
        x: rnd(0, W),
        y: rnd(0, H),
        vx: rnd(-0.35, 0.35),
        vy: rnd(-0.35, 0.35),
        r: rnd(1.5, 4),
        color: COLORS[Math.floor(Math.random() * COLORS.length)],
        alpha: rnd(0.3, 0.9),
        pulse: Math.random() * Math.PI * 2,
        pulseSpeed: rnd(0.015, 0.04),
        type: i < 8 ? 'hub' : 'node'
      }));
    };

    resize();
    initNodes();

    window.addEventListener('resize', () => {
      resize();
      initNodes();
    });

    const spawnPacket = (x1: number, y1: number, x2: number, y2: number) => {
      packets.push({ x1, y1, x2, y2, t: 0, speed: rnd(0.008, 0.02) });
    };

    const drawNetwork = () => {
      ctx.clearRect(0, 0, W, H);

      // Edges
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          const maxDist = a.type === 'hub' || b.type === 'hub' ? 200 : 130;
          if (dist < maxDist) {
            const alpha = (1 - dist / maxDist) * 0.18;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(0, 201, 138, ${alpha})`;
            ctx.lineWidth = a.type === 'hub' || b.type === 'hub' ? 0.8 : 0.4;
            ctx.stroke();
          }
        }
      }

      // Nodes (Bolinhas removidas conforme solicitado - mantendo apenas lógica de movimento)
      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < -10) n.x = W + 10;
        if (n.x > W + 10) n.x = -10;
        if (n.y < -10) n.y = H + 10;
        if (n.y > H + 10) n.y = -10;
      }

      if (Math.random() < 0.015) {
        const a = nodes[Math.floor(Math.random() * nodes.length)];
        const b = nodes[Math.floor(Math.random() * nodes.length)];
        if (a !== b) spawnPacket(a.x, a.y, b.x, b.y);
      }
    };

    const drawPackets = () => {
      for (let i = packets.length - 1; i >= 0; i--) {
        const p = packets[i];
        p.t += p.speed;
        const x = p.x1 + (p.x2 - p.x1) * p.t;
        const y = p.y1 + (p.y2 - p.y1) * p.t;
        ctx.beginPath();
        ctx.arc(x, y, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 201, 138, ${0.9 - p.t * 0.8})`;
        ctx.fill();
        if (p.t >= 1) packets.splice(i, 1);
      }
    };

    let animationId: number;
    let isVisible = true;

    const animate = () => {
      if (!isVisible) return;
      drawNetwork();
      drawPackets();
      animationId = requestAnimationFrame(animate);
    };

    const observer = new IntersectionObserver((entries) => {
      isVisible = entries[0].isIntersecting;
      if (isVisible) {
        cancelAnimationFrame(animationId);
        animate();
      }
    }, { threshold: 0 });

    observer.observe(canvas);
    animate();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resize);
      observer.disconnect();
    };
  }, []);

  return { canvasRef };
}
