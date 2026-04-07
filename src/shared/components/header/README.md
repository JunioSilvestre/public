# Módulo do Cabeçalho (Header)

## 1. Propósito

O `header` é responsável pela identidade visual, navegação principal e ações globais (login, idioma, tema). Foi construído de forma modular para ser fácil de manter e escalar.

---

## 2. Guia de Arquivos para Devs Júnior

Para entender a lógica, pense no Header como uma construção:

### ⚙️ Configurações e Tipos
- **[header.config.ts](file:///c:/Projetos/Front-End/PRJ-BASE/src/header/header.config.ts)**: O "cérebro" das configurações. Define nomes de sites, URLs base e comportamentos globais.
- **[header.tokens.ts](file:///c:/Projetos/Front-End/PRJ-BASE/src/header/header.tokens.ts)**: Onde guardamos os valores de design (cores, alturas, paddings) para não ficarem "soltos" no código.
- **[header.types.ts](file:///c:/Projetos/Front-End/PRJ-BASE/src/header/header.types.ts)**: Define as interfaces do TypeScript. Garante que ninguém passe um dado errado por engano.

### 🧩 Componentes (As Peças)
Localizados na pasta `components/`, são as partes visuais:
- **`Logo.tsx`**: Trata a imagem da marca e o link para a Home.
- **`NavBar.tsx` / `NavItem.tsx`**: A lista de links que você vê no topo.
- **`MegaMenu.tsx`**: Aquele menu grande que abre ao passar o mouse.
- **`MobileNav.tsx`**: A versão do menu para celular (menu hambúrguer).
- **`ThemeToggle.tsx`**: O botãozinho de Sol/Lua para mudar o tema.
- **`AuthCtaBtn.tsx`**: O botão de destaque (Geralmente "Login" ou "Começar").

### 🧠 Hooks (A Inteligência)
Localizados na pasta `hooks/`, guardam a lógica que não é visual:
- **`useScrollBehavior`**: Controla quando o header deve sumir ou ficar fixo ao rolar a página.
- **`useMobileNav`**: Controla se o menu do celular está aberto ou fechado.
- **`useLiveTicker`**: Faz a mágica da barra de cotações se mexer com dados reais.

### 🎭 Variantes (Estilos de Exibição)
Localizados na pasta `variants/`, definem como o header se comporta na tela:
- **`Sticky.tsx`**: Header que "gruda" no topo.
- **`Transparent.tsx`**: Header sem fundo, usado em cima de fotos bonitas.
- **`Minimal.tsx`**: Uma versão simplificada (ex: para páginas de checkout).

### 🏠 Ponto Central
- **[Header.tsx](file:///c:/Projetos/Front-End/PRJ-BASE/src/header/Header.tsx)**: O componente principal. Ele importa as peças (`components`), a inteligência (`hooks`) e monta o cabeçalho final.
- **[index.tsx](file:///c:/Projetos/Front-End/PRJ-BASE/src/header/index.tsx)**: O "guichê" de exportação. Quando alguém de fora quer usar o Header, ele passa por aqui.

---

## 3. Como Usar

O `Header` deve ser colocado no seu layout principal.

```tsx
import { Header } from '@/header';

const MyLayout = ({ children }) => (
  <>
    <Header variant="Sticky" />
    <main>{children}</main>
  </>
);
```

src/header/
├── assets/                  # Logos e recursos visuais
│   ├── logo-dark.svg
│   ├── logo-white.svg
│   └── logo.svg
├── components/              # Componentes internos do Header
│   ├── AuthCtaBtn.tsx       # Botão de Login/Registro
│   ├── LanguageSwitcher.tsx # Seletor de Idioma
│   ├── Logo.tsx             # Gerenciador do Logo
│   ├── MarketTickerBar.tsx  # Barra de cotações ao vivo
│   ├── MegaMenu.tsx         # Menu expansível rico
│   ├── MobileNav.tsx        # Navegação mobile
│   ├── MobileNavToggle.tsx  # Botão hambúrguer
│   ├── NavBar.tsx           # Barra de navegação principal
│   ├── NavItem.tsx          # Item individual do menu
│   └── ThemeToggle.tsx      # Alternador claro/escuro
├── data/                    # Configurações JSON e menus
│   ├── mega-menu.json
│   ├── nav-links.json
│   └── ticker-symbols.json
├── hooks/                   # Lógica e estados reutilizáveis
│   ├── useActiveRoute.ts
│   ├── useLiveTicker.ts
│   ├── useMobileNav.ts
│   └── useScrollBehavior.ts
├── variants/                # Versões alternativas de layout
│   ├── Minimal.tsx
│   ├── Sticky.tsx
│   └── Transparent.tsx
├── __tests__/               # Testes unitários
├── header.config.ts         # Configurações globais do header
├── header.tokens.ts         # Tokens de estilo (cores, espaçamentos)
├── Header.tsx               # Componente principal unificado
├── header.types.ts          # Interfaces e Tipos TypeScript
├── index.tsx                # Ponto de entrada (exportação pública)
└── README.md                # Documentação do módulo
