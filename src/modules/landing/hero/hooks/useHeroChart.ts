/**
 * @arquivo     src/hero/hooks/useHeroChart.ts
 * @módulo      Hero / Hook Chart
 * @descrição   Lógica de renderização do gráfico sparkline usando Chart.js.
 */
import { useEffect, useRef } from 'react';
import { Chart, LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler } from 'chart.js';
import { HERO_TOKENS } from '../hero.tokens';

Chart.register(LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler);

export function useHeroChart() {
  const chartRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const ctx = chartRef.current?.getContext('2d');
    if (!ctx) return;

    const makeSparkData = () => {
      let v = 1800;
      return Array.from({ length: 30 }, () => {
        v += (Math.random() - 0.46) * 18;
        return +v.toFixed(2);
      });
    };

    const sparkData = makeSparkData();

    const chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: sparkData.map((_, i) => i),
        datasets: [{
          data: sparkData,
          borderColor: HERO_TOKENS.colors.accent,
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.4,
          fill: true,
          backgroundColor: (context) => {
            const g = context.chart.ctx.createLinearGradient(0, 0, 0, 64);
            g.addColorStop(0, 'rgba(0, 201, 138, 0.18)');
            g.addColorStop(1, 'rgba(0, 201, 138, 0)');
            return g;
          }
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false, min: Math.min(...sparkData) * 0.995, max: Math.max(...sparkData) * 1.005 }
        },
        animation: { duration: 800 }
      }
    });

    const interval = setInterval(() => {
      const last = sparkData[sparkData.length - 1];
      const next = +(last + (Math.random() - 0.47) * 14).toFixed(2);
      sparkData.shift();
      sparkData.push(next);
      chart.data.datasets[0].data = [...sparkData];
      chart.update('none');
    }, 1800);

    return () => {
      chart.destroy();
      clearInterval(interval);
    };
  }, []);

  return { chartRef };
}
