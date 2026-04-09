export const KB_CATEGORIES = [
    { id: 'react', name: 'React', icon: '⚛️', desc: 'Componentes, hooks, estado e padrões modernos do ecossistema React.', count: 100, tag: 'Frontend', type: 'frontend', color: '#61DAFB', progress: 68 },
    { id: 'javascript', name: 'JavaScript', icon: '🟨', desc: 'Fundamentos, ES6+, async/await, closures e padrões avançados.', count: 87, tag: 'Frontend', type: 'frontend', color: '#F7DF1E', progress: 45 },
    { id: 'css', name: 'CSS / Tailwind', icon: '🎨', desc: 'Flexbox, Grid, animações, variáveis CSS e utilitários Tailwind.', count: 35, tag: 'Frontend', type: 'frontend', color: '#38BDF8', progress: 30 },
    { id: 'nodejs', name: 'Node.js', icon: '🟢', desc: 'APIs RESTful, Express, autenticação e deploy com Node.', count: 28, tag: 'Backend', type: 'backend', color: '#84CC16', progress: 55 },
    { id: 'sql', name: 'SQL & Banco de Dados', icon: '🗄️', desc: 'Queries, JOINs, índices, ORM e modelagem de dados.', count: 19, tag: 'Database', type: 'database', color: '#A78BFA', progress: 20 },
    { id: 'typescript', name: 'TypeScript', icon: '🔷', desc: 'Tipos, interfaces, genéricos e integração com React/Node.', count: 31, tag: 'Frontend', type: 'frontend', color: '#3178C6', progress: 72 },
    { id: 'git', name: 'Git & Versionamento', icon: '🔀', desc: 'Branches, merges, rebase e PR.', count: 14, tag: 'Conceitos', type: 'concepts', color: '#F97316', progress: 90 },
    { id: 'patterns', name: 'Padrões de Projeto', icon: '🏗️', desc: 'Design patterns aplicados ao JavaScript.', count: 22, tag: 'Conceitos', type: 'concepts', color: '#EC4899', progress: 15 }
];

export const PROJ_CATEGORIES = [
    { id: 'finance', name: 'Finanças & Fintech', icon: '💰', desc: 'Sistemas de pagamento, auditoria e gateways.', count: 10, color: '#10B981' },
    { id: 'health', name: 'Saúde & Healthtech', icon: '🏥', desc: 'Prontuários eletrônicos e telemedicina.', count: 10, color: '#6366F1' },
    { id: 'enterprise', name: 'Corporativo & SaaS', icon: '🏢', desc: 'ERPs, Automação e Business Intelligence.', count: 10, color: '#F59E0B' }
];

export const generateKBItems = (catName: string, icon: string) => {
    return Array.from({ length: 24 }, (_, i) => ({
        id: i + 1,
        name: `${catName} Prática #${i + 1}`,
        level: ['básico', 'intermediário', 'avançado'][i % 3],
        time: (i % 5 + 3) + ' min',
        snippet: `Exemplo estruturado de ${catName} focado em alta performance.`,
        icon: icon
    }));
};

export const generateProjItems = (id: string) => {
    return Array.from({ length: 10 }, (_, i) => ({
        id: i + 1,
        name: id === 'finance' ? `FinPay Pro #${i + 1}` : id === 'health' ? `MediCloud Core #${i + 1}` : `Enterprise SaaS #${i + 1}`,
        level: i % 2 === 0 ? 'Produção' : 'MVP',
        snippet: 'Arquitetura focada em conformidade, segurança e alta disponibilidade de dados para o setor.',
        tech: id === 'finance' ? 'Node, Redis, SQL' : 'React, AWS, IoT'
    }));
};
