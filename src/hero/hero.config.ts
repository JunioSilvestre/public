/**
 * @arquivo     src/hero/hero.config.ts
 * @módulo      Hero / Configuração
 * @descrição   Configuração de conteúdo do componente Hero. Define os textos do
 *              headline, sub-headline, stack tecnológica e o conteúdo do editor
 *              de código decorativo exibido na seção visual.
 *
 * @como-usar   import { HERO_CONFIG } from './hero.config';
 *              // Acesse HERO_CONFIG.headline, .subHeadline, .techStack, .editor
 *
 * @dependências ./hero.types (TechBadge)
 * @notas       Para personalizar o Hero sem alterar componentes, edite apenas
 *              este arquivo. As linhas do editor são renderizadas com syntax
 *              highlighting via a função `getWordColor` no HeroVisual.
 */
import { TechBadge } from './hero.types';

export const HERO_CONFIG = {
    headline: {
        prefix: 'Building',
        highlight: 'Scalable',
        suffix: 'and High-Performance Web Applications'
    },
    subHeadline: 'Frontend Engineer specialized in React, Next.js and modern architectures',
    techStack: [
        { label: 'React', color: '#b0c6ff', glowColor: 'rgba(176,198,255,0.8)' },
        { label: 'Next.js', color: '#00e3fd', glowColor: 'rgba(0,227,253,0.8)' },
        { label: 'TypeScript', color: '#f8acff', glowColor: 'rgba(248,172,255,0.8)' },
        { label: 'Node.js', color: '#a0bbff', glowColor: 'rgba(160,187,255,0.8)' }
    ] as TechBadge[],
    editor: {
        filename: 'Main.tsx',
        lines: [
            { num: '01', content: 'import { Engine } from \'@kinetic/core\';', types: ['keyword', 'content', 'variable', 'content', 'string'] },
            { num: '02', content: '', types: [] },
            { num: '03', content: 'const App = () => {', types: ['keyword', 'variable', 'content'] },
            { num: '04', content: '  return (', types: ['keyword', 'content'] },
            { num: '05', content: '    <Engine', types: ['variable'] },
            { num: '06', content: '      performance="ultra"', types: ['string', 'content', 'string'] },
            { num: '07', content: '      scalable={true}', types: ['string', 'content', 'keyword', 'content'], hasCursor: true },
            { num: '08', content: '    />', types: ['variable'] },
            { num: '09', content: '  );', types: ['content'] },
            { num: '10', content: '};', types: ['content'] }
        ]
    }
};
