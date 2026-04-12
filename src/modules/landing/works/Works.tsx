"use client";

/**
 * @file        src/works/Works.tsx
 * @module      Works / Component
 * @description Premium portfolio cards with dynamic canvas animations and magnetic tilt effects.
 */

import React, { useEffect, useRef, useState } from 'react';
import styles from './Works.module.css';

const Works: React.FC = () => {
  const canvasRefA = useRef<HTMLCanvasElement>(null);
  const canvasRefB = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Helper for rounded rectangles
  const rr = (ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) => {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y); ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r); ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h); ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r); ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  };

  // Canvas A Animation: Distributed Cache
  useEffect(() => {
    const cv = canvasRefA.current;
    if (!cv) return;
    const wrap = cv.parentElement;
    if (!wrap) return;
    
    let W: number, H: number, dpr = window.devicePixelRatio || 1;
    const g = cv.getContext('2d')!;
    let t = 0, ptimer = 0;
    let animationFrameId: number;

    const resize = () => {
      W = wrap.clientWidth; H = wrap.clientHeight;
      cv.width = W * dpr; cv.height = H * dpr;
      cv.style.width = W + 'px'; cv.style.height = H + 'px';
    };
    resize();
    window.addEventListener('resize', resize);

    const NODES = [
      { id: 'cli', lx: .09, ly: .5, rw: .14, rh: .3, label: 'CLIENT', sub: 'SDK', role: 'cli' },
      { id: 'lb', lx: .41, ly: .5, rw: .17, rh: .34, label: 'BALANCER', sub: 'L7 Proxy', role: 'lb' },
      { id: 'n1', lx: .74, ly: .2, rw: .15, rh: .27, label: 'NODE-01', sub: 'Leader', role: 'lead' },
      { id: 'n2', lx: .74, ly: .52, rw: .15, rh: .27, label: 'NODE-02', sub: 'Replica', role: 'rep' },
      { id: 'n3', lx: .74, ly: .82, rw: .15, rh: .27, label: 'NODE-03', sub: 'Replica', role: 'rep' },
    ];

    const EDGES = [
      { a: 'cli', b: 'lb', color: '#0ea5e9', sync: false },
      { a: 'lb', b: 'n1', color: '#0ea5e9', sync: false },
      { a: 'lb', b: 'n2', color: '#0ea5e9', sync: false },
      { a: 'lb', b: 'n3', color: '#0ea5e9', sync: false },
      { a: 'n1', b: 'n2', color: '#22d3a0', sync: true },
      { a: 'n1', b: 'n3', color: '#22d3a0', sync: true },
    ];

    const particles: any[] = [];
    const nget = (id: string) => NODES.find(n => n.id === id);
    const ncx = (n: any) => n.lx * W;
    const ncy = (n: any) => n.ly * H;

    const spawn = (edge: any) => {
      particles.push({
        edge,
        t: 0,
        spd: .007 + Math.random() * .008,
        r: 3 + Math.random() * 2,
        color: edge.color,
      });
    };

    const nodeTheme = (role: string) => {
      if (role === 'lb') return { bg: ['#dbeafe', '#bfdbfe'], bdr: '#93c5fd', tc: '#0369a1' };
      if (role === 'lead') return { bg: ['#d1fae5', '#a7f3d0'], bdr: '#6ee7b7', tc: '#059669' };
      if (role === 'cli') return { bg: ['#f0f9ff', '#e0f2fe'], bdr: '#bae6fd', tc: '#0284c7' };
      return { bg: ['#f5f3ff', '#ede9fe'], bdr: '#c4b5fd', tc: '#6d28d9' };
    };

    const drawNode = (n: any) => {
      const x = ncx(n) - n.rw * W / 2, y = ncy(n) - n.rh * H / 2;
      const w = n.rw * W, h = n.rh * H, rad = 9;
      const th = nodeTheme(n.role);

      if (n.role === 'lb' || n.role === 'lead') {
        const s = .5 + .5 * Math.sin(t * .05 + (n.role === 'lead' ? 1.2 : 0));
        g.beginPath(); rr(g, x - 5, y - 5, w + 10, h + 10, rad + 4);
        g.strokeStyle = `rgba(${n.role === 'lb' ? '14,165,233' : '34,211,160'},${.12 + s * .2})`;
        g.lineWidth = 1.8; g.stroke();
      }

      const gr = g.createLinearGradient(x, y, x + w, y + h);
      gr.addColorStop(0, th.bg[0]); gr.addColorStop(1, th.bg[1]);
      g.beginPath(); rr(g, x, y, w, h, rad);
      g.fillStyle = gr; g.fill();
      g.strokeStyle = th.bdr; g.lineWidth = 1.3; g.stroke();

      g.textAlign = 'center';
      g.font = `500 ${w * .125}px 'Geist Mono',monospace`;
      g.fillStyle = th.tc;
      g.fillText(n.label, x + w / 2, y + h * .44);

      g.font = `400 ${w * .15}px 'Geist',sans-serif`;
      g.fillStyle = '#374151';
      g.fillText(n.sub, x + w / 2, y + h * .72);

      const dx = x + w - 9, dy = y + 9;
      const dc = n.role === 'lead' ? '#059669' : n.role === 'rep' ? '#7c3aed' : n.role === 'lb' ? '#0ea5e9' : '#94a3b8';
      const pr2 = 2.5 + 1.5 * Math.sin(t * .08 + (ncx(n) * .02));
      g.beginPath(); g.arc(dx, dy, pr2 * 2.2, 0, Math.PI * 2);
      g.fillStyle = dc + '28'; g.fill();
      g.beginPath(); g.arc(dx, dy, 3.5, 0, Math.PI * 2);
      g.fillStyle = dc; g.fill();

      if (n.role === 'lb') {
        const sx = x + 6, sy = y + h * .85, sw = w - 12, sh = h * .1;
        for (let i = 0; i < 8; i++) {
          const bh2 = sh * (.4 + .6 * Math.abs(Math.sin(t * .04 + i * .7)));
          g.fillStyle = '#0ea5e944';
          g.fillRect(sx + i * (sw / 8), sy + sh - bh2, sw / 8 - 2, bh2);
        }
      }
    };

    let isVisible = false;

    const frame = () => {
      if (!isVisible) return;
      animationFrameId = requestAnimationFrame(frame);
      g.clearRect(0, 0, cv.width, cv.height);
      g.save(); g.scale(dpr, dpr);

      EDGES.forEach(e => {
        const a = nget(e.a), b = nget(e.b);
        if (!a || !b) return;
        g.beginPath();
        g.setLineDash([5, 5]);
        g.lineDashOffset = -(t * .5);
        g.strokeStyle = e.color + '44';
        g.lineWidth = 1.2;
        g.moveTo(ncx(a), ncy(a));
        g.lineTo(ncx(b), ncy(b));
        g.stroke();
        g.setLineDash([]);
      });

      NODES.forEach(drawNode);

      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.t += p.spd;
        if (p.t > 1) { particles.splice(i, 1); continue; }
        const a = nget(p.edge.a), b = nget(p.edge.b);
        if (!a || !b) continue;
        const px2 = ncx(a) + (ncx(b) - ncx(a)) * p.t;
        const py2 = ncy(a) + (ncy(b) - ncy(a)) * p.t;

        const gr = g.createRadialGradient(px2, py2, 0, px2, py2, p.r * 2.8);
        gr.addColorStop(0, p.color + 'ff');
        gr.addColorStop(1, p.color + '00');
        g.beginPath(); g.arc(px2, py2, p.r * 2.8, 0, Math.PI * 2);
        g.fillStyle = gr; g.fill();
        g.beginPath(); g.arc(px2, py2, p.r, 0, Math.PI * 2);
        g.fillStyle = p.color; g.fill();
      }

      ptimer++;
      if (ptimer % 30 === 0) spawn(EDGES[Math.floor(Math.random() * EDGES.length)]);
      if (ptimer % 70 === 0) {
        const se = EDGES.filter(e => e.sync);
        if (se.length) spawn(se[Math.floor(Math.random() * se.length)]);
      }

      t++; g.restore();
    };

    const observer = new IntersectionObserver((entries) => {
      isVisible = entries[0].isIntersecting;
      if (isVisible) {
        cancelAnimationFrame(animationFrameId);
        frame();
      }
    }, { threshold: 0.1 });

    observer.observe(cv);
    frame();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrameId);
      observer.disconnect();
    };
  }, []);

  // Canvas B Animation: AI Code Review
  useEffect(() => {
    const cv = canvasRefB.current;
    if (!cv) return;
    const wrap = cv.parentElement;
    if (!wrap) return;

    let W: number, H: number, dpr = window.devicePixelRatio || 1;
    const g = cv.getContext('2d')!;
    let t = 0, scanY = 0, ttimer = 0;
    let animationFrameId: number;

    const resize = () => {
      W = wrap.clientWidth; H = wrap.clientHeight;
      cv.width = W * dpr; cv.height = H * dpr;
      cv.style.width = W + 'px'; cv.style.height = H + 'px';
    };
    resize();
    window.addEventListener('resize', resize);

    const L_IN = [.18, .33, .5, .67, .82];
    const L_H1 = [.22, .38, .55, .72];
    const L_OUT = [.3, .5, .7];
    const tokens: any[] = [];

    const CLINES = [
      { w: .75, c: '#a78bfa55', ind: 0 },
      { w: .55, c: '#7c3aed66', ind: 1 },
      { w: .68, c: '#a78bfa33', ind: 1 },
      { w: .42, c: '#7c3aed44', ind: 2 },
      { w: .78, c: '#a78bfa33', ind: 2 },
      { w: .60, c: '#7c3aed55', ind: 1 },
      { w: .45, c: '#a78bfa44', ind: 0 },
      { w: .70, c: '#dc262688', ind: 1, flag: true },
    ];

    const RCARDS = [
      { label: 'Bug Detected', sub: 'Line 47: null deref', y: .2, tc: '#dc2626', bg: '#fee2e2', bd: '#fca5a5', icon: '⚠' },
      { label: 'Suggestion', sub: 'Use async/await', y: .5, tc: '#b45309', bg: '#fef3c7', bd: '#fde68a', icon: '💡' },
      { label: 'Approved ✓', sub: 'Looks good', y: .8, tc: '#059669', bg: '#d1fae5', bd: '#6ee7b7', icon: '✓' },
    ];

    let isVisible = false;

    const frame = () => {
      if (!isVisible) return;
      animationFrameId = requestAnimationFrame(frame);
      g.clearRect(0, 0, cv.width, cv.height);
      g.save(); g.scale(dpr, dpr);

      const edW = W * .28, edX = 10, edY = 10, edH = H - 20;
      const netX = edX + edW + 18, netW = W * .3, netY = 10, netH = H - 20;
      const outX = netX + netW + 18;

      // Editor
      rr(g, edX, edY, edW, edH, 10);
      g.fillStyle = '#f5f0ff'; g.fill();
      g.strokeStyle = '#ddd6fe'; g.lineWidth = 1.2; g.stroke();
      
      rr(g, edX, edY, edW, 24, 10);
      g.fillStyle = '#ede9fe'; g.fill();
      g.font = `500 8px 'Geist Mono',monospace`;
      g.fillStyle = '#7c3aed'; g.textAlign = 'left';
      g.fillText('  review.ts', edX + 8, edY + 15);

      scanY = (scanY + .5) % (edH - 24);
      const row = edH - 28;
      CLINES.forEach((ln, i) => {
        const ly = edY + 28 + i * (row / CLINES.length);
        const lx = edX + 22 + (ln.ind || 0) * 7;
        const lw = (edW - 26 - (ln.ind || 0) * 7) * ln.w;
        if (ln.flag) {
          g.fillStyle = 'rgba(220,38,38,.06)';
          g.fillRect(edX + 20, ly - 2, edW - 22, 10);
        }
        g.beginPath(); rr(g, lx, ly, lw, 5, 2);
        g.fillStyle = ln.flag ? '#fca5a577' : ln.c; g.fill();
      });

      // Net
      rr(g, netX, netY, netW, netH, 10);
      g.fillStyle = 'rgba(237,233,254,.4)'; g.fill();
      g.strokeStyle = 'rgba(196,181,253,.5)'; g.lineWidth = 1; g.stroke();

      const cIn = netX + netW * .18, cH1 = netX + netW * .52, cOut = netX + netW * .86;
      L_IN.forEach(y => L_H1.forEach(y2 => {
        g.beginPath(); g.moveTo(cIn, y * H); g.lineTo(cH1, y2 * H);
        g.strokeStyle = `rgba(167,139,250,${.05 + .04 * Math.sin(t * .03 + y + y2)})`; g.lineWidth = .8; g.stroke();
      }));

      // Tokens
      ttimer++;
      if (ttimer % 38 === 0) tokens.push({ ii: Math.floor(Math.random() * L_IN.length), hi: Math.floor(Math.random() * L_H1.length), oi: Math.floor(Math.random() * L_OUT.length), t: 0, spd: .012 + Math.random() * .009 });
      for (let i = tokens.length - 1; i >= 0; i--) {
        const tk = tokens[i]; tk.t += tk.spd;
        if (tk.t >= 1) { tokens.splice(i, 1); continue; }
        const f = tk.t < .5 ? tk.t * 2 : (tk.t - .5) * 2;
        const px = tk.t < .5 ? cIn + (cH1 - cIn) * f : cH1 + (cOut - cH1) * f;
        const py = tk.t < .5 ? L_IN[tk.ii] * H + (L_H1[tk.hi] * H - L_IN[tk.ii] * H) * f : L_H1[tk.hi] * H + (L_OUT[tk.oi] * H - L_H1[tk.hi] * H) * f;
        g.beginPath(); g.arc(px, py, 3, 0, Math.PI * 2); g.fillStyle = '#a78bfa'; g.fill();
      }

      // Output cards
      const ocW = W - outX - 10;
      RCARDS.forEach((rc, i) => {
        const ch = H * .22, cx = outX, cy = rc.y * H - ch / 2;
        rr(g, cx, cy, ocW, ch, 9);
        g.fillStyle = rc.bg; g.fill();
        g.strokeStyle = rc.bd; g.lineWidth = 1.2; g.stroke();
        g.font = `600 9px 'Geist Mono',monospace`; g.fillStyle = rc.tc; g.textAlign = 'left';
        g.fillText(rc.label, cx + 33, cy + ch / 2 - 2);
      });

      t++; g.restore();
    };

    const observer = new IntersectionObserver((entries) => {
      isVisible = entries[0].isIntersecting;
      if (isVisible) {
        cancelAnimationFrame(animationFrameId);
        frame();
      }
    }, { threshold: 0.1 });

    observer.observe(cv);
    frame();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrameId);
      observer.disconnect();
    };
  }, []);

  // Scroll Reveal and Magnetic Tilt
  useEffect(() => {
    const cards = containerRef.current?.querySelectorAll(`.${styles.card}`);
    if (!cards) return;

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add(styles.cardVisible);
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    cards.forEach(card => observer.observe(card));

    const handleMouseMove = (e: MouseEvent, card: HTMLElement) => {
      const rect = card.getBoundingClientRect();
      const dx = (e.clientX - rect.left - rect.width / 2) / (rect.width / 2);
      const dy = (e.clientY - rect.top - rect.height / 2) / (rect.height / 2);
      (card as HTMLElement).style.transform = `translateY(-5px) rotateX(${-dy * 3}deg) rotateY(${dx * 3}deg)`;
    };

    const handleMouseLeave = (card: HTMLElement) => {
      (card as HTMLElement).style.transform = '';
    };

    cards.forEach(card => {
      (card as HTMLElement).addEventListener('mousemove', (e) => handleMouseMove(e as MouseEvent, card as HTMLElement));
      (card as HTMLElement).addEventListener('mouseleave', () => handleMouseLeave(card as HTMLElement));
    });

    return () => {
      observer.disconnect();
      cards.forEach(card => {
        (card as HTMLElement).removeEventListener('mousemove', (e) => handleMouseMove(e as MouseEvent, card as HTMLElement));
        (card as HTMLElement).removeEventListener('mouseleave', () => handleMouseLeave(card as HTMLElement));
      });
    };
  }, []);

  return (
    <section id="works" className="py-32 border-b border-black/5">
      <div className={styles.container} ref={containerRef}>
        <h2 className="text-4xl font-bold text-[#111827] mb-12 font-[family-name:var(--font-head)]">Selected Works</h2>
        
        <div className={styles.cardsRow}>
          {/* Card A: HyperCache */}
          <article className={`${styles.card} ${styles.cardA}`}>
            <div className={styles.stripe}></div>
            <div className={styles.cHd}>
              <div className={styles.meta}>
                <span className={styles.cType}>Infrastructure · Backend</span>
                <span className={`${styles.pill} ${styles.pillLive}`}>
                  <span className={styles.pdot}></span>Production
                </span>
              </div>
              <h3 className={styles.cTitle}>HyperCache<br />Distributed System</h3>
              <p className={styles.cSub}>Sub-millisecond distributed caching layer handling global traffic at scale — built from the ground up in Rust.</p>
            </div>

            <div className={styles.cPrev}>
              <canvas ref={canvasRefA}></canvas>
            </div>

            <div className={styles.cBd}>
              <div className={styles.metrics}>
                <div className={styles.metric}><span className={styles.mval}>0.3ms</span><span className={styles.mlbl}>P99 Latency</span></div>
                <div className={styles.metric}><span className={styles.mval}>99.99%</span><span className={styles.mlbl}>Uptime SLA</span></div>
                <div className={styles.metric}><span className={styles.mval}>2M+</span><span className={styles.mlbl}>Req / sec</span></div>
              </div>
              <p className={styles.cDesc}>High-throughput caching layer with consistent hashing, automatic rebalancing on node failure, and multi-region replication.</p>
              <ul className={styles.highlights}>
                <li>Lock-free ring buffer with MPSC queue for zero-copy I/O</li>
                <li>Raft consensus for leader election and log replication</li>
                <li>Adaptive TTL with LFU + LRU hybrid eviction policy</li>
                <li>Prometheus-native metrics with OpenTelemetry tracing</li>
              </ul>
              <div>
                <p className={styles.slbl}>Tech Stack</p>
                <div className={styles.tags}>
                  <span className={styles.tag}>Rust</span><span className={styles.tag}>Tokio</span><span className={styles.tag}>Kubernetes</span>
                  <span className={styles.tag}>gRPC</span><span className={styles.tag}>Raft</span><span className={styles.tag}>Docker</span>
                </div>
              </div>
            </div>
            <div className={styles.divider}></div>
            <div className={styles.cFt}>
              <div className={styles.ftl}>
                <button className={`${styles.btn} ${styles.btnA}`}>Live Demo</button>
                <button className={`${styles.btn} ${styles.btnG}`}>Source</button>
              </div>
              <div className={styles.ftr}>
                <span className={styles.clbl}>Team</span>
                <div className={styles.avs}>
                  <div className={styles.av} style={{background:'#0369a1'}}>YO</div>
                  <div className={styles.av} style={{background:'#0284c7'}}>AC</div>
                </div>
              </div>
            </div>
          </article>

          {/* Card B: Nexus AI */}
          <article className={`${styles.card} ${styles.cardB}`}>
            <div className={styles.stripe}></div>
            <div className={styles.cHd}>
              <div className={styles.meta}>
                <span className={styles.cType}>AI / Full-Stack · SaaS</span>
                <span className={`${styles.pill} ${styles.pillBeta}`}>
                  <span className={styles.pdot}></span>Beta
                </span>
              </div>
              <h3 className={styles.cTitle}>Nexus AI<br />Code Review</h3>
              <p className={styles.cSub}>Autonomous code review platform powered by LLMs — detects vulnerabilities and enforces style.</p>
            </div>

            <div className={styles.cPrev}>
              <canvas ref={canvasRefB}></canvas>
            </div>

            <div className={styles.cBd}>
              <div className={styles.metrics}>
                <div className={styles.metric}><span className={styles.mval}>94%</span><span className={styles.mlbl}>Bug Recall</span></div>
                <div className={styles.metric}><span className={styles.mval}>8 s</span><span className={styles.mlbl}>Avg Review</span></div>
                <div className={styles.metric}><span className={styles.mval}>12K+</span><span className={styles.mlbl}>PRs Reviewed</span></div>
              </div>
              <p className={styles.cDesc}>End-to-end SaaS integrating with GitHub to perform AI-driven reviews on every PR catching security issues.</p>
              <ul className={styles.highlights}>
                <li>Fine-tuned CodeLlama + GPT-4o ensemble for precision</li>
                <li>AST-aware diff parsing with semantic context extraction</li>
                <li>Multi-tenant SaaS with GitHub OAuth & webhook pipeline</li>
                <li>Real-time streaming UI via Server-Sent Events (SSE)</li>
              </ul>
              <div>
                <p className={styles.slbl}>Tech Stack</p>
                <div className={styles.tags}>
                  <span className={styles.tag}>TypeScript</span><span className={styles.tag}>Python</span><span className={styles.tag}>FastAPI</span>
                  <span className={styles.tag}>Next.js</span><span className={styles.tag}>OpenAI</span><span className={styles.tag}>PostgreSQL</span>
                </div>
              </div>
            </div>
            <div className={styles.divider}></div>
            <div className={styles.cFt}>
              <div className={styles.ftl}>
                <button className={`${styles.btn} ${styles.btnB}`}>Live Demo</button>
                <button className={`${styles.btn} ${styles.btnG}`}>Source</button>
              </div>
              <div className={styles.ftr}>
                <span className={styles.clbl}>Solo</span>
                <div className={styles.avs}>
                  <div className={styles.av} style={{background:'linear-gradient(135deg,#5b21b6,#7c3aed)'}}>YO</div>
                </div>
              </div>
            </div>
          </article>
        </div>
      </div>
    </section>
  );
};

export default Works;
