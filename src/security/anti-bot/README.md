# Módulo Anti-Bot

> Guia completo para desenvolvedores júnior sobre como proteger sua aplicação Next.js contra bots maliciosos.

---

## Sumário

1. [O que é um bot e por que ele é um problema?](#1-o-que-é-um-bot-e-por-que-ele-é-um-problema)
2. [Estrutura do módulo](#2-estrutura-do-módulo)
3. [Honeypot — a armadilha invisível](#3-honeypot--a-armadilha-invisível)
4. [reCAPTCHA — o desafio de verificação](#4-recaptcha--o-desafio-de-verificação)
5. [index.ts — como importar corretamente](#5-indexts--como-importar-corretamente)
6. [Qual usar: Honeypot, reCAPTCHA ou os dois?](#6-qual-usar-honeypot-recaptcha-ou-os-dois)
7. [Variáveis de ambiente necessárias](#7-variáveis-de-ambiente-necessárias)
8. [Exemplos completos por cenário](#8-exemplos-completos-por-cenário)
9. [Erros comuns de dev júnior](#9-erros-comuns-de-dev-júnior)
10. [Referência rápida da API](#10-referência-rápida-da-api)

---

## 1. O que é um bot e por que ele é um problema?

Um **bot** é um programa que faz requisições HTTP automaticamente, imitando o que um usuário faria no navegador. Nem todo bot é malicioso — o Googlebot, por exemplo, indexa seu site para o Google. Mas bots maliciosos podem:

| Ataque | O que faz | Dano causado |
|---|---|---|
| **Form spam** | Preenche e envia formulários automaticamente | Sua caixa de e-mail fica cheia de lixo |
| **Credential stuffing** | Testa milhares de senhas vazadas no login | Contas de usuários comprometidas |
| **Account creation** | Cria centenas de contas falsas | Polui seu banco de dados, abusa de trials gratuitos |
| **Scraping** | Copia todo o conteúdo do seu site | Perda de propriedade intelectual |
| **Carding** | Testa números de cartão de crédito roubados no checkout | Chargebacks, bloqueio pela operadora |
| **Voting bots** | Vota múltiplas vezes em enquetes | Resultados manipulados |

Este módulo implementa **duas estratégias complementares** para detectar e bloquear esses bots.

---

## 2. Estrutura do módulo

```
lib/security/anti-bot/
├── honeypot.ts    → Armadilhas passivas (sem fricção para o usuário)
├── recaptcha.ts   → Verificação ativa via CAPTCHA (Google, hCaptcha, Turnstile)
└── index.ts       → Ponto de entrada — importe tudo daqui
```

> **Regra de ouro:** Sempre importe de `@/lib/security/anti-bot` (o `index.ts`), nunca diretamente de `honeypot.ts` ou `recaptcha.ts`. Isso garante que você sempre use a API pública estável.

```ts
// ✅ Correto
import { verifyCaptcha, validateHoneypot } from "@/lib/security/anti-bot";

// ❌ Evite importar diretamente dos arquivos internos
import { verifyCaptcha } from "@/lib/security/anti-bot/recaptcha";
```

---

## 3. Honeypot — a armadilha invisível

### 3.1 O que é e como funciona

Um **honeypot** é uma isca. A ideia é criar elementos no HTML que parecem reais para um bot, mas que usuários humanos **nunca** interagem — porque são invisíveis via CSS.

Imagine um formulário de contato com um campo extra chamado `website`. Esse campo existe no HTML, mas está escondido via `display: none`. Um humano olhando a tela não vê esse campo e não preenche. Um bot que lê o HTML e preenche todos os campos cai na armadilha ao preencher `website` — e é detectado.

```
┌─────────────────────────────────────────┐
│ FORMULÁRIO VISÍVEL PARA HUMANOS         │
│                                         │
│  Nome: [________________]               │
│  E-mail: [______________]               │
│  Mensagem: [____________]               │
│                                         │
│  [Enviar]                               │
└─────────────────────────────────────────┘

No HTML (invisível para humanos, visível para bots):
<input name="website" style="display:none">   ← armadilha
<input name="_t" type="hidden" value="1709..."> ← timestamp
<input name="_tk" type="hidden" value="abc..."> ← token
```

### 3.2 As 6 estratégias implementadas

O `honeypot.ts` usa seis técnicas ao mesmo tempo, cada uma com um **score de risco**. Se o score total passar do limite (padrão: 70), o envio é bloqueado.

| Estratégia | Como detecta o bot | Score padrão |
|---|---|---|
| **Campo hidden preenchido** | Bot preenche campo CSS-hidden | 90/100 |
| **Timing muito rápido** | Bot envia em < 3 segundos | 70/100 |
| **Token ausente** | Bot não fez GET inicial, não tem token | 60/100 |
| **Token inválido** | Token foi modificado ou forjado | 80/100 |
| **Token reusado** | Bot tentou reusar o mesmo token (replay) | 90/100 |
| **Rota armadilha** | Bot ou scanner acessou URL isca | 100/100 |

> **Por que usar score em vez de bloqueio binário?**
> Um único sinal pode ser falso positivo (ex: o usuário é muito rápido digitando). A combinação de vários sinais com peso dá muito mais precisão.

### 3.3 Como usar em um formulário Next.js

**Passo 1 — Criar a instância do honeypot (uma só vez, no nível do módulo):**

```ts
// lib/security/anti-bot/instance.ts
import { HoneypotMiddleware, MemoryHoneypotStore } from "@/lib/security/anti-bot";

export const honeypot = new HoneypotMiddleware({
  secret: process.env.HONEYPOT_SECRET!, // mínimo 32 caracteres
  store:  new MemoryHoneypotStore(),
  minSubmitTimeMs: 3_000,               // 3 segundos mínimos
  scoreThreshold:  70,                  // bloqueia acima de 70
  trapRoutes: [
    "/wp-admin",   // nunca existiu no seu projeto
    "/.env",       // arquivo de ambiente
    "/phpinfo.php" // PHP não existe aqui
  ],
  debug: process.env.NODE_ENV === "development",
});
```

**Passo 2 — Gerar os campos no Server Component (GET):**

```tsx
// app/contato/page.tsx
import { honeypot } from "@/lib/security/anti-bot/instance";

export default async function ContatoPage() {
  // Gera os campos com timestamp e token assinado
  const honeypotFields = await honeypot.generateFormFields();

  return (
    <form method="POST" action="/api/contato">
      {/* Seus campos normais */}
      <input name="nome"     type="text"  required />
      <input name="email"    type="email" required />
      <textarea name="mensagem" required />

      {/* Injeta os campos honeypot — invisíveis para humanos */}
      <div dangerouslySetInnerHTML={{ __html: honeypotFields }} />

      {/* CSS de ocultação (opcional mas recomendado) */}
      <style
        dangerouslySetInnerHTML={{ __html: honeypot.generateCSS() }}
      />

      <button type="submit">Enviar</button>
    </form>
  );
}
```

**Passo 3 — Verificar no Route Handler (POST):**

```ts
// app/api/contato/route.ts
import { NextRequest, NextResponse } from "next/server";
import { honeypot } from "@/lib/security/anti-bot/instance";

export async function POST(request: NextRequest) {
  const body = await request.json();

  // ⚠️ Verifica ANTES de qualquer lógica de negócio
  const check = await honeypot.checkForm({
    ip:      request.headers.get("x-real-ip") ?? undefined,
    method:  "POST",
    path:    "/api/contato",
    headers: Object.fromEntries(request.headers),
    body,
  });

  if (!check.clean) {
    // IMPORTANTE: responde 200, não 403!
    // Se o bot recebe 403, ele sabe que foi detectado e muda de estratégia.
    // Com 200 "falso", o bot acha que funcionou e continua tentando — sem sucesso.
    return NextResponse.json({ success: true, message: "Mensagem recebida!" });
  }

  // Remove os campos honeypot antes de processar
  const dadosLimpos = honeypot.stripHoneypotFields(body);

  // Agora processa os dados reais
  await enviarEmail(dadosLimpos);

  return NextResponse.json({ success: true });
}
```

### 3.4 Verificação de rotas armadilha no middleware

Para bloquear scanners que vasculham rotas como `/.env` e `/wp-admin`:

```ts
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { honeypot } from "@/lib/security/anti-bot/instance";

export function middleware(request: NextRequest) {
  const url = new URL(request.url);

  // Verifica se é rota armadilha
  const routeCheck = honeypot.checkRoute(
    url.pathname,
    request.headers.get("x-real-ip") ?? "unknown"
  );

  if (!routeCheck.clean) {
    // Retorna 404 — o scanner não sabe se a rota existe ou não
    return new NextResponse("Not found", { status: 404 });
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

### 3.5 Configuração completa (`HoneypotConfig`)

| Opção | Tipo | Padrão | Descrição |
|---|---|---|---|
| `fieldNames` | `string[]` | `["website","url","company","fax"]` | Nomes dos campos isca |
| `timestampField` | `string` | `"_t"` | Nome do campo de timestamp |
| `tokenField` | `string` | `"_tk"` | Nome do campo de token |
| `minSubmitTimeMs` | `number` | `3000` | Tempo mínimo para preencher (ms) |
| `maxSubmitTimeMs` | `number` | `3600000` | Tempo máximo — token expira (1h) |
| `secret` | `string` | — | Secret para assinar tokens (obrigatório em produção) |
| `trapRoutes` | `string[]` | `[]` | URLs que são armadilhas |
| `scoreThreshold` | `number` | `70` | Score mínimo para bloquear (0–100) |
| `store` | `HoneypotStore` | — | Store para prevenir replay (use `MemoryHoneypotStore`) |
| `onBotDetected` | `function` | — | Callback chamado quando bot é detectado |
| `debug` | `boolean` | `false` | Logs detalhados no console |

---

## 4. reCAPTCHA — o desafio de verificação

### 4.1 O que é e quando usar

O **reCAPTCHA** (e alternativas como hCaptcha e Cloudflare Turnstile) é um serviço externo que verifica se quem está usando o formulário é humano. Diferente do honeypot (passivo), o CAPTCHA é **ativo** — o usuário precisa passar por algum tipo de verificação.

```
                   NAVEGADOR DO USUÁRIO
                         │
                    [Preenche formulário]
                         │
                    [Token gerado pelo
                     script do Google]  ← invisível para o usuário (v3)
                         │
                   SERVIDOR (Next.js)
                         │
              [Envia token para a API do Google]
                         │
               API GOOGLE RECAPTCHA
                         │
              [Retorna: score 0.0 → 1.0]
                    ┌────┴────┐
              0.9 (humano)   0.1 (bot)
```

### 4.2 Qual versão usar?

| Versão | Experiência do usuário | Precisão | Quando usar |
|---|---|---|---|
| **v2 Checkbox** | "Não sou um robô" | Média | Formulários simples, pouco tráfego |
| **v2 Invisible** | Sem interação (analisa comportamento) | Boa | Botões de submit normais |
| **v3** | Sem interação — score contínuo | Ótima | Formulários com volume médio/alto |
| **Enterprise** | Sem interação — score + motivos | Excelente | Alto volume, apps críticos |
| **hCaptcha** | Similar ao v2 | Boa | Alternativa privacidade-first |
| **Turnstile** | Sem fricção | Ótima | Alternativa Cloudflare, gratuito |

> **Recomendação para começar:** Use **reCAPTCHA v3** para a maioria dos casos. Ele não incomoda o usuário e dá um score de 0 a 1 que você usa para tomar decisões.

### 4.3 Como usar o reCAPTCHA v3

**Passo 1 — Adicionar o script no HTML (client-side):**

```tsx
// app/layout.tsx
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <head>
        <script
          src={`https://www.google.com/recaptcha/api.js?render=${process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY}`}
          async
          defer
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

**Passo 2 — Gerar o token no cliente ao submeter:**

```tsx
// app/contato/page.tsx
"use client";

declare const grecaptcha: {
  ready: (cb: () => void) => void;
  execute: (siteKey: string, opts: { action: string }) => Promise<string>;
};

export default function ContatoForm() {
  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    // Gera o token — isso chama a API do Google em background
    const token = await new Promise<string>((resolve) => {
      grecaptcha.ready(async () => {
        const t = await grecaptcha.execute(
          process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY!,
          { action: "contact" } // nome da ação — use nomes descritivos
        );
        resolve(t);
      });
    });

    const form = event.currentTarget;
    const formData = new FormData(form);

    const response = await fetch("/api/contato", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nome:     formData.get("nome"),
        email:    formData.get("email"),
        mensagem: formData.get("mensagem"),
        // Envia o token junto com os dados do formulário
        "g-recaptcha-response": token,
      }),
    });

    const data = await response.json();
    if (data.success) alert("Mensagem enviada!");
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="nome"     type="text"  required />
      <input name="email"    type="email" required />
      <textarea name="mensagem" required />
      <button type="submit">Enviar</button>
    </form>
  );
}
```

**Passo 3 — Verificar o token no servidor:**

```ts
// app/api/contato/route.ts
import { NextRequest, NextResponse } from "next/server";
import { verifyCaptcha, buildCaptchaResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  // verifyCaptcha extrai o token do body automaticamente
  const captcha = await verifyCaptcha(request, {
    provider:        "recaptcha_v3",
    secretKey:       process.env.RECAPTCHA_SECRET_KEY!,
    minScore:        0.5,           // 0.0 = bot, 1.0 = humano — bloqueia abaixo de 0.5
    expectedAction:  "contact",     // deve bater com o action do cliente
    expectedHostnames: ["meusite.com.br"],
    preventTokenReplay: true,       // bloqueia o mesmo token sendo usado duas vezes
  });

  if (!captcha.ok) {
    // buildCaptchaResponse retorna a resposta HTTP correta para cada tipo de erro
    return buildCaptchaResponse(captcha);
  }

  // captcha.score está disponível para decisões mais finas
  if (captcha.score && captcha.score < 0.7) {
    // Score baixo mas acima do mínimo: aceita mas adiciona ao watchlist
    console.warn("Suspicious submit, score:", captcha.score);
  }

  const body = await request.json();
  await enviarEmail(body);

  return NextResponse.json({ success: true });
}
```

### 4.4 Como usar o Cloudflare Turnstile (alternativa gratuita)

O Turnstile é gratuito, não tem fricção para o usuário e funciona muito bem.

```tsx
// Cliente: adiciona o widget no form
<div
  className="cf-turnstile"
  data-sitekey={process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY}
/>
<script
  src="https://challenges.cloudflare.com/turnstile/v0/api.js"
  async defer
/>
```

```ts
// Servidor: verifica com Turnstile
const captcha = await verifyCaptcha(request, {
  provider:          "turnstile",
  turnstileSecretKey: process.env.TURNSTILE_SECRET_KEY!,
  // Turnstile não tem score — apenas success/fail
});
```

### 4.5 Configuração completa (`CaptchaOptions`)

| Opção | Tipo | Padrão | Descrição |
|---|---|---|---|
| `provider` | `CaptchaProvider` | — | **Obrigatório.** Qual provedor usar |
| `secretKey` | `string` | — | Chave secreta do provedor (v2/v3/hCaptcha) |
| `minScore` | `number` | `0.5` | Score mínimo para aprovar (0.0–1.0) |
| `scoreByAction` | `Record<string, number>` | — | Score diferente por ação: `{ login: 0.7 }` |
| `expectedAction` | `string` | — | Action que deve estar no token (v3/Enterprise) |
| `expectedHostnames` | `string[]` | — | Domínios permitidos para o token |
| `preventTokenReplay` | `boolean` | `true` | Bloqueia reuso do mesmo token |
| `maxAttemptsPerIP` | `number` | `20` | Rate limit: tentativas por minuto por IP |
| `allowOnProviderError` | `boolean` | `false` | `false` = bloqueia se Google cair; `true` = permite |
| `verificationTimeoutMs` | `number` | `5000` | Timeout para chamar a API do provedor |
| `mode` | `"enforce"\|"audit"\|"off"` | `"enforce"` | `"audit"` loga mas não bloqueia |

### 4.6 Entendendo o score do reCAPTCHA v3

```
0.0 ──────────────────────────────────── 1.0
│           │           │               │
BOT      SUSPEITO   PROVÁVEL          HUMANO
         (bloquear)  HUMANO         CONFIÁVEL
                    (aceitar)
```

| Score | Significado | Ação recomendada |
|---|---|---|
| `0.0 – 0.3` | Bot quase certo | Bloquear silenciosamente |
| `0.3 – 0.5` | Suspeito | Pedir verificação adicional (v2) |
| `0.5 – 0.7` | Provavelmente humano | Aceitar, mas monitorar |
| `0.7 – 1.0` | Humano com alta confiança | Aceitar normalmente |

Use `getRiskLabel(score)` para obter uma label legível:

```ts
import { getRiskLabel } from "@/lib/security/anti-bot";

getRiskLabel(0.9)  // → "human"
getRiskLabel(0.6)  // → "likely_human"
getRiskLabel(0.4)  // → "suspicious"
getRiskLabel(0.1)  // → "bot"
```

---

## 5. index.ts — como importar corretamente

O `index.ts` é o **barrel file** do módulo. Ele re-exporta tudo de `honeypot.ts` e `recaptcha.ts` em um único ponto de entrada. Há duas formas de usar:

### Forma 1 — Importação nomeada (recomendada)

```ts
import {
  // reCAPTCHA
  verifyCaptcha,
  withCaptcha,
  buildCaptchaResponse,
  isProbableBot,
  isHighConfidenceHuman,
  getRiskLabel,

  // Honeypot
  validateHoneypot,
  withHoneypot,
  buildHoneypotResponse,
  generateHoneypotField,
  HoneypotMiddleware,
  MemoryHoneypotStore,
  HoneypotFieldName,
} from "@/lib/security/anti-bot";
```

### Forma 2 — Namespace agrupado (quando usa os dois no mesmo arquivo)

```ts
import { Captcha, Honeypot } from "@/lib/security/anti-bot";

// Fica mais legível quando usa os dois juntos
const captchaResult = await Captcha.verifyCaptcha(request, captchaOpts);
const honeypotResult = await Honeypot.validateHoneypot(req, honeypotOpts);
```

---

## 6. Qual usar: Honeypot, reCAPTCHA ou os dois?

```
                    ┌─────────────────────────┐
                    │ Qual proteção usar?      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Formulário tem volume   │
                    │ alto de submissões?     │
                    └────────────┬────────────┘
                          Não ◄──┴──► Sim
                           │               │
              ┌────────────▼───┐   ┌───────▼────────────┐
              │ Honeypot basta │   │ reCAPTCHA v3        │
              │ para começar   │   │ (+ Honeypot junto)  │
              └────────────────┘   └────────────────────┘
```

| Cenário | Recomendação |
|---|---|
| Formulário de contato simples | Honeypot sozinho |
| Login / cadastro | Honeypot + reCAPTCHA v3 |
| Checkout / pagamento | reCAPTCHA v3 com `minScore: 0.7` |
| API pública sem formulário | reCAPTCHA v3 (token via JS) |
| Você quer zero fricção e é cliente Cloudflare | Turnstile |
| Preocupação com privacidade do usuário | hCaptcha |

**Regra geral:** use Honeypot sempre (custo zero, sem fricção) e adicione reCAPTCHA nos fluxos críticos (login, cadastro, checkout).

---

## 7. Variáveis de ambiente necessárias

Adicione no seu `.env.local` (desenvolvimento) e nas variáveis de ambiente do deploy (produção):

```bash
# ── Honeypot ──────────────────────────────────────────────────────────────
# Segredo para assinar tokens. Gere com: openssl rand -base64 32
HONEYPOT_SECRET="sua-chave-secreta-de-pelo-menos-32-caracteres-aqui"

# ── reCAPTCHA v3 ──────────────────────────────────────────────────────────
# Obtenha em: https://www.google.com/recaptcha/admin
NEXT_PUBLIC_RECAPTCHA_SITE_KEY="6Le..."   # público — pode estar no JS do cliente
RECAPTCHA_SECRET_KEY="6Le..."             # privado — NUNCA exponha no cliente

# ── reCAPTCHA Enterprise (se usar) ────────────────────────────────────────
RECAPTCHA_ENTERPRISE_API_KEY="AIza..."
RECAPTCHA_PROJECT_ID="meu-projeto-gcp"
NEXT_PUBLIC_RECAPTCHA_ENTERPRISE_SITE_KEY="..."

# ── hCaptcha (se usar) ────────────────────────────────────────────────────
NEXT_PUBLIC_HCAPTCHA_SITE_KEY="..."
HCAPTCHA_SECRET_KEY="..."

# ── Cloudflare Turnstile (se usar) ────────────────────────────────────────
NEXT_PUBLIC_TURNSTILE_SITE_KEY="..."
TURNSTILE_SECRET_KEY="..."
```

> ⚠️ **Nunca use variáveis sem `NEXT_PUBLIC_` no código cliente.** Variáveis com `NEXT_PUBLIC_` ficam visíveis no bundle JavaScript — use apenas para site keys (que são públicas por design). A secret key JAMAIS deve ir para o cliente.

---

## 8. Exemplos completos por cenário

### Cenário 1 — Formulário de contato com Honeypot

```ts
// app/api/contato/route.ts
import { NextRequest, NextResponse } from "next/server";
import { honeypot } from "@/lib/security/anti-bot/instance";

export async function POST(request: NextRequest) {
  const body = await request.json() as Record<string, unknown>;

  const check = await honeypot.checkForm({
    ip:      request.headers.get("cf-connecting-ip") ?? undefined,
    method:  "POST",
    path:    "/api/contato",
    headers: Object.fromEntries(request.headers.entries()),
    body,
  });

  // Bot detectado — responde 200 falso
  if (!check.clean) {
    return NextResponse.json({ success: true });
  }

  // Remove campos honeypot e processa
  const { nome, email, mensagem } = honeypot.stripHoneypotFields(body) as {
    nome: string;
    email: string;
    mensagem: string;
  };

  await enviarEmail({ nome, email, mensagem });
  return NextResponse.json({ success: true });
}
```

### Cenário 2 — Login com reCAPTCHA v3 e score diferenciado

```ts
// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from "next/server";
import { verifyCaptcha, isProbableBot } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  // Verifica CAPTCHA antes de qualquer operação de banco de dados
  const captcha = await verifyCaptcha(request, {
    provider:       "recaptcha_v3",
    secretKey:      process.env.RECAPTCHA_SECRET_KEY!,
    expectedAction: "login",
    minScore:       0.5,
    // Login exige score mais alto que um formulário de contato
    scoreByAction: { login: 0.6 },
    preventTokenReplay: true,
  });

  if (!captcha.ok) {
    return NextResponse.json(
      { error: "Verificação falhou. Tente novamente." },
      { status: 403 }
    );
  }

  // Score muito baixo — possível ataque de credential stuffing
  if (isProbableBot(captcha, 0.4)) {
    // Adiciona delay artificial para dificultar ataques em volume
    await new Promise((r) => setTimeout(r, 2000));
  }

  const { email, password } = await request.json();
  // ... lógica de autenticação
}
```

### Cenário 3 — Cadastro com Honeypot + reCAPTCHA juntos

```ts
// app/api/auth/register/route.ts
import { NextRequest, NextResponse } from "next/server";
import { verifyCaptcha, buildCaptchaResponse } from "@/lib/security/anti-bot";
import { honeypot } from "@/lib/security/anti-bot/instance";

export async function POST(request: NextRequest) {
  const body = await request.json() as Record<string, unknown>;
  const ip   = request.headers.get("cf-connecting-ip") ?? undefined;

  // ── 1. Honeypot primeiro (custo zero) ──────────────────────────────────
  const hpCheck = await honeypot.checkForm({
    ip, method: "POST", path: "/api/auth/register",
    headers: Object.fromEntries(request.headers.entries()),
    body,
  });

  if (!hpCheck.clean) {
    // Bot simples detectado — resposta falsa
    return NextResponse.json({ success: true });
  }

  // ── 2. reCAPTCHA para bots mais sofisticados ────────────────────────────
  const captcha = await verifyCaptcha(request, {
    provider:       "recaptcha_v3",
    secretKey:      process.env.RECAPTCHA_SECRET_KEY!,
    expectedAction: "register",
    minScore:       0.5,
    preventTokenReplay: true,
  });

  if (!captcha.ok) {
    return buildCaptchaResponse(captcha);
  }

  // ── 3. Processa o cadastro ──────────────────────────────────────────────
  const dados = honeypot.stripHoneypotFields(body);
  await criarUsuario(dados);

  return NextResponse.json({ success: true });
}
```

### Cenário 4 — Wrapper `withCaptcha` (forma mais concisa)

```ts
// app/api/newsletter/route.ts
import { NextRequest, NextResponse } from "next/server";
import { withCaptcha } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  // withCaptcha cuida de toda a verificação e resposta de erro
  return withCaptcha(
    request,
    async (captchaResult) => {
      // Só chega aqui se o CAPTCHA passou
      const { email } = await request.json();
      await inscreveNewsletter(email);
      return NextResponse.json({ success: true });
    },
    {
      provider:       "recaptcha_v3",
      secretKey:      process.env.RECAPTCHA_SECRET_KEY!,
      expectedAction: "newsletter",
      minScore:       0.4, // Newsletter pode ser mais permissivo
    }
  );
}
```

---

## 9. Erros comuns de dev júnior

### ❌ Erro 1 — Retornar 403 quando detectar bot

```ts
// ERRADO — o bot sabe que foi detectado e muda de estratégia
if (!check.clean) {
  return NextResponse.json({ error: "Bot detected" }, { status: 403 });
}
```

```ts
// CORRETO — bot pensa que funcionou, mas na verdade não enviou nada
if (!check.clean) {
  return NextResponse.json({ success: true, message: "Mensagem enviada!" });
}
```

### ❌ Erro 2 — Expor a secret key no cliente

```ts
// ERRADO — NUNCA faça isso
const token = process.env.RECAPTCHA_SECRET_KEY; // em código cliente
```

```ts
// CORRETO — secret key apenas no servidor
// Cliente usa: process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY
// Servidor usa: process.env.RECAPTCHA_SECRET_KEY
```

### ❌ Erro 3 — Não remover campos honeypot antes de salvar

```ts
// ERRADO — salva campos "_t", "_tk", "website" no banco
await db.save(body);
```

```ts
// CORRETO — remove campos honeypot antes de qualquer processamento
const dadosLimpos = honeypot.stripHoneypotFields(body);
await db.save(dadosLimpos);
```

### ❌ Erro 4 — Criar nova instância do HoneypotMiddleware por request

```ts
// ERRADO — cria uma instância nova a cada request (perde o state do store)
export async function POST(request: NextRequest) {
  const hp = new HoneypotMiddleware({ secret: "..." }); // ← nova instância!
  const check = await hp.checkForm(...);
}
```

```ts
// CORRETO — instância única compartilhada (mantém o MemoryStore entre requests)
// lib/security/anti-bot/instance.ts
export const honeypot = new HoneypotMiddleware({ ... }); // criado uma vez

// route.ts
import { honeypot } from "@/lib/security/anti-bot/instance";
const check = await honeypot.checkForm(...);
```

### ❌ Erro 5 — Verificar CAPTCHA depois de acessar o banco de dados

```ts
// ERRADO — já buscou no banco antes de verificar o CAPTCHA
export async function POST(request: NextRequest) {
  const user = await db.findUser(email); // 💸 query cara
  const captcha = await verifyCaptcha(request, opts); // deveria ser primeiro!
  if (!captcha.ok) return error;
}
```

```ts
// CORRETO — verifica segurança primeiro, banco depois
export async function POST(request: NextRequest) {
  const captcha = await verifyCaptcha(request, opts); // ← primeiro
  if (!captcha.ok) return buildCaptchaResponse(captcha);
  const user = await db.findUser(email); // só chega aqui se passou
}
```

---

## 10. Referência rápida da API

### Honeypot

| Função / Classe | O que faz |
|---|---|
| `new HoneypotMiddleware(config)` | Cria uma instância configurada |
| `honeypot.checkForm(req)` | Verifica se o formulário foi enviado por bot |
| `honeypot.checkRoute(path, ip)` | Verifica se a rota é uma armadilha |
| `honeypot.generateFormFields(formId?)` | Gera HTML dos campos honeypot |
| `honeypot.generateCrawlerTrap(url)` | Gera link isca para crawlers |
| `honeypot.generateCSS()` | Gera CSS de ocultação dos campos |
| `honeypot.stripHoneypotFields(body)` | Remove campos honeypot do body |
| `honeypot.isKnownBot(ip)` | Verifica se IP já foi marcado como bot |
| `new MemoryHoneypotStore()` | Store em memória para prevenir replay |
| `createDefaultHoneypot(secret)` | Factory com configuração padrão |
| `createStrictHoneypot(secret)` | Factory mais restritiva (para login/cadastro) |

### reCAPTCHA

| Função | O que faz |
|---|---|
| `verifyCaptcha(request, opts)` | Verifica o token CAPTCHA do request |
| `withCaptcha(request, handler, opts)` | Wrapper para Route Handlers |
| `buildCaptchaResponse(result)` | Gera a resposta HTTP de erro correta |
| `isProbableBot(result, threshold?)` | `true` se score < threshold (padrão 0.4) |
| `isHighConfidenceHuman(result, threshold?)` | `true` se score ≥ threshold (padrão 0.8) |
| `getRiskLabel(score)` | `"bot"`, `"suspicious"`, `"likely_human"` ou `"human"` |
| `getTokenCacheStats()` | Retorna tamanho do cache de tokens usados |
| `clearTokenCache()` | Limpa o cache (útil em testes) |

### Tipos principais

```ts
// Resultado do Honeypot
interface HoneypotResult {
  clean: boolean;        // true = humano
  triggered?: string;    // qual armadilha foi acionada
  score: number;         // 0–100
  signals: string[];     // sinais detectados
}

// Resultado do CAPTCHA
interface CaptchaVerificationResult {
  ok: boolean;           // true = aprovado
  status: string;        // "success", "low_score", "invalid_token", etc.
  score?: number;        // 0.0–1.0 (apenas v3/Enterprise)
  action?: string;       // action declarada no token
  audit: CaptchaAuditLog; // detalhes para logging
}
```

---

## Integração com os outros módulos de segurança

Este módulo anti-bot é parte de uma stack maior. A ordem de execução recomendada no middleware é:

```
Request entra
    │
    ▼
1. networkPolicies.ts  → CORS, CSP, security headers
    │
    ▼
2. firewallRules.ts    → IP blocklist, geo-blocking, WAF
    │
    ▼
3. dnsProtection.ts    → Host header, DNS rebinding
    │
    ▼
4. vpnEnforcement.ts   → VPN corporativa / bloqueio de proxies
    │
    ▼
5. anti-bot/ (este módulo)
   ├── honeypot.ts     → Rota armadilha, timing check
   └── recaptcha.ts    → Score-based verification
    │
    ▼
6. trafficInspection.ts → DPI, behavioral analysis
    │
    ▼
7. requestSanitizer.ts  → XSS, SQLi, payload sanitization
    │
    ▼
   Lógica de negócio
```