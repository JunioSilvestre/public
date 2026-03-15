# Módulo Bot Detection

> Guia completo para desenvolvedores júnior sobre como proteger sua aplicação Next.js contra bots automatizados usando o pipeline de detecção multicamada.

---

## Sumário

1. [O que é este módulo e por que ele existe?](#1-o-que-é-este-módulo-e-por-que-ele-existe)
2. [Estrutura e mapa dos arquivos](#2-estrutura-e-mapa-dos-arquivos)
3. [Como funciona o pipeline](#3-como-funciona-o-pipeline)
4. [Behavioral Analysis — análise de comportamento](#4-behavioral-analysis--análise-de-comportamento)
5. [Honeypot Field — armadilhas de formulário](#5-honeypot-field--armadilhas-de-formulário)
6. [Captcha Handler — verificação ativa](#6-captcha-handler--verificação-ativa)
7. [Turnstile Validator — Cloudflare Turnstile](#7-turnstile-validator--cloudflare-turnstile)
8. [Bot Detection — orquestrador](#8-bot-detection--orquestrador)
9. [index.ts — como importar](#9-indexts--como-importar)
10. [Exemplos completos por cenário](#10-exemplos-completos-por-cenário)
11. [Erros comuns de dev júnior](#11-erros-comuns-de-dev-júnior)
12. [Referência rápida da API](#12-referência-rápida-da-api)

---

## 1. O que é este módulo e por que ele existe?

Bots são programas que fazem requisições HTTP automaticamente. Eles podem ser maliciosos:

| Ataque | Exemplo real | Dano |
|---|---|---|
| **Credential stuffing** | Script testa 10.000 senhas vazadas no `/api/auth/login` | Contas comprometidas |
| **Form spam** | Bot preenche seu formulário de contato 500x por hora | Inbox lotada de lixo |
| **Account farming** | Script cria 1.000 contas falsas para abusar de trial grátis | Custos e fraude |
| **Carding** | Bot testa cartões de crédito roubados no checkout | Chargebacks, bloqueio da Stripe |
| **Scraping** | Crawler copia todo o conteúdo do seu site | Perda de IP, SEO prejudicado |
| **Voting manipulation** | Bot vota 10.000 vezes numa enquete | Resultados falsos |

Este módulo implementa **cinco camadas de defesa** que trabalham juntas. Nenhuma camada sozinha é suficiente — bots sofisticados contornam defesas únicas, mas a combinação aumenta drasticamente o custo de um ataque.

---

## 2. Estrutura e mapa dos arquivos

```
lib/security/anti-bot/
│
├── index.ts                ← Importe SEMPRE daqui
│
├── bot-detection.ts        ← Orquestrador: combina todos os resultados
│
├── behavioral-analysis.ts  ← Analisa movimento de mouse, teclado, scroll
├── honeypot-field.ts       ← Campos armadilha e verificação de timing
├── captcha-handler.ts      ← Interface unificada para CAPTCHA (v3, Turnstile, hCaptcha)
└── turnstile-validator.ts  ← Adapter específico para Cloudflare Turnstile
```

> **Regra de ouro:** Sempre importe de `@/lib/security/anti-bot` (o `index.ts`).
> Nunca importe diretamente de `bot-detection.ts`, `behavioral-analysis.ts`, etc.

```ts
// ✅ Correto — importação pelo barrel
import { detectBot, BehavioralCollector } from "@/lib/security/anti-bot";

// ❌ Errado — importação direta de arquivo interno
import { detectBot } from "@/lib/security/anti-bot/bot-detection";
```

---

## 3. Como funciona o pipeline

O `bot-detection.ts` orquestra três checks em sequência. A ordem importa:

```
Request chega
     │
     ▼
┌────────────────────────────────────────────────────┐
│  CHECK 1: HONEYPOT (peso 40%)                      │
│  • Sem I/O — resposta em < 1ms                     │
│  • Campo hidden preenchido? Token inválido?        │
│  • Timing suspeito? (enviou em < 800ms?)           │
└──────────────────┬─────────────────────────────────┘
                   │  Score ≥ 70? → SHORT-CIRCUIT (para aqui)
                   ▼  Score < 70? → continua
┌────────────────────────────────────────────────────┐
│  CHECK 2: BEHAVIORAL (peso 35%)                    │
│  • Sem I/O — analisa dados enviados pelo cliente   │
│  • Mouse linear? Keystroke uniforme?               │
│  • WebDriver detectado? Headless browser?          │
└──────────────────┬─────────────────────────────────┘
                   │  Score ≥ 70? → SHORT-CIRCUIT
                   ▼  Score < 70? → continua
┌────────────────────────────────────────────────────┐
│  CHECK 3: CAPTCHA (peso 25%)                       │
│  • I/O — chamada de rede para Google/Cloudflare    │
│  • Token válido? Score suficiente?                 │
│  • Token já foi usado? (replay detection)          │
└──────────────────┬─────────────────────────────────┘
                   │
                   ▼
           SCORE FINAL (0–100)
           ┌──────────────────┐
           │ ≥ 70 → "block"   │  isBot = true
           │ 50–69 → "challenge" │
           │ 30–49 → "monitor" │
           │ < 30 → "allow"   │  isBot = false
           └──────────────────┘
```

**Por que o CAPTCHA é o último?** Ele faz uma chamada de rede para o Google/Cloudflare, que leva ~200ms. Se o honeypot já detectou o bot com 100% de certeza, gastar 200ms chamando a API seria desperdício. O `shortCircuit: true` (padrão) interrompe o pipeline cedo.

---

## 4. Behavioral Analysis — análise de comportamento

### 4.1 O que analisa

O `behavioral-analysis.ts` tem **duas partes**:

```
CLIENTE (browser)                    SERVIDOR (Next.js)
─────────────────                    ──────────────────
BehavioralCollector                  analyzeBehavior()
     │                                     │
     │  coleta eventos DOM                 │  analisa o JSON
     │  (mouse, teclado, scroll)           │  calcula humanScore
     │                                     │  retorna BehavioralResult
     └──── UserTelemetry (JSON) ───────────┘
              no POST do formulário
```

### 4.2 Sinais de humano vs. bot

| Característica | Humano | Bot |
|---|---|---|
| Movimento de mouse | Curvas naturais (Bézier) | Linhas retas ou zero |
| Timing entre teclas | Variável (50–400ms) | Uniforme (exatamente igual) |
| Velocidade de scroll | Aceleração e desaceleração | Constante ou zero |
| Tempo na página | Variável conforme leitura | Mínimo (< 500ms) |
| `navigator.webdriver` | `false` | `true` (Selenium/Playwright) |
| Plugins do browser | 2+ plugins | 0 plugins (headless) |
| Troca de aba (focus/blur) | Acontece naturalmente | Nunca acontece |

### 4.3 Como usar no formulário React

**Passo 1 — Client Component: coleta os dados**

```tsx
// app/contato/ContatoForm.tsx
"use client";

import { useRef, useEffect } from "react";
import { BehavioralCollector } from "@/lib/security/anti-bot";

export function ContatoForm() {
  // Ref para manter a instância entre renders
  const collectorRef = useRef<BehavioralCollector | null>(null);

  useEffect(() => {
    // Inicia a coleta quando o componente monta
    collectorRef.current = new BehavioralCollector();
    collectorRef.current.start();

    // Para a coleta quando o componente desmonta (limpa event listeners)
    return () => {
      collectorRef.current?.stop();
    };
  }, []);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;

    // Coleta todos os dados de comportamento no momento do submit
    const telemetry = collectorRef.current?.collect();

    await fetch("/api/contato", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nome:    (form.elements.namedItem("nome") as HTMLInputElement).value,
        email:   (form.elements.namedItem("email") as HTMLInputElement).value,
        telemetry, // ← envia junto com os dados do formulário
      }),
    });
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="nome"  type="text"  required />
      <input name="email" type="email" required />
      <button type="submit">Enviar</button>
    </form>
  );
}
```

**Passo 2 — Route Handler: analisa os dados**

```ts
// app/api/contato/route.ts
import { NextRequest, NextResponse } from "next/server";
import { detectBot, buildBotResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  // O detectBot extrai automaticamente o campo "telemetry" do body
  const result = await detectBot(request, {
    behavioral: { minHumanScore: 40 }, // score mínimo para aceitar
  });

  if (result.isBot) {
    // Resposta falsa — o bot não sabe que foi detectado
    return NextResponse.json({ success: true });
  }

  // processa normalmente...
}
```

### 4.4 O que é o humanScore?

```
0 ──────────────────────────────── 100
│        │         │         │        │
BOT   LIKELY   SUSPICIOUS LIKELY   HUMAN
      BOT               HUMAN
 0–19  20–39    40–54    55–74    75–100
```

- `humanScore: 90` → com altíssima confiança é humano
- `humanScore: 20` → provavelmente é bot
- `humanScore: 45` → suspeito, pedir verificação adicional

---

## 5. Honeypot Field — armadilhas de formulário

### 5.1 Como funciona

O `honeypot-field.ts` é um adapter sobre `honeypot.ts` que oferece verificações rápidas sem precisar instanciar o middleware completo.

Três técnicas funcionam juntas:

**1. Campo hidden preenchido**
```html
<!-- Humanos não veem este campo (CSS position: absolute, left: -9999px) -->
<!-- Bots que leem o HTML preenchem todos os campos -->
<input name="website" style="display:none" tabindex="-1" aria-hidden="true">
```

**2. Timing check**
Humanos levam segundos para preencher formulários. Bots enviam em milissegundos.

```
Tempo de preenchimento humano:
  - Formulário de login: ≥ 2.000ms
  - Formulário de contato: ≥ 3.000ms
  - Formulário de cadastro: ≥ 5.000ms
  - Checkout: ≥ 8.000ms

Bots típicos: < 100ms → detectados imediatamente
```

**3. Token de sessão**
Cada formulário recebe um token assinado com HMAC. Bots que constroem requests diretos sem fazer o GET da página não têm o token.

### 5.2 Verificação rápida (sem middleware)

```ts
// app/api/contato/route.ts
import { isHoneypotFilled, checkSubmitTiming } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  const body = await request.json();

  // Verificação síncrona — não faz I/O, resposta em < 1ms
  const fieldCheck = isHoneypotFilled(body);
  if (fieldCheck.detected) {
    // Campo armadilha foi preenchido → bot com 97% de certeza
    console.warn("Bot detectou campo:", fieldCheck.fieldName);
    return NextResponse.json({ success: true }); // resposta falsa
  }

  // Verifica se enviou rápido demais
  const timingCheck = checkSubmitTiming(body, { formType: "contact" });
  if (timingCheck.tooFast) {
    console.warn(`Submit em ${timingCheck.elapsedMs}ms (mínimo: ${timingCheck.minExpectedMs}ms)`);
    return NextResponse.json({ success: true }); // resposta falsa
  }

  // continua...
}
```

### 5.3 Verificação completa com preset por tipo de formulário

```ts
import { checkHoneypotField } from "@/lib/security/anti-bot";

const check = await checkHoneypotField(body, request, {
  formType: "login",   // aplica o preset correto automaticamente
  secret:   process.env.HONEYPOT_SECRET, // para verificar o token HMAC
});

if (!check.clean) {
  return NextResponse.json({ success: true }); // resposta falsa
}
```

### 5.4 Campos React para o formulário

```tsx
import { getHoneypotFormProps } from "@/lib/security/anti-bot";

// No Server Component (ou no topo do Client Component)
const honeypot = getHoneypotFormProps("contact");

// No JSX do formulário
return (
  <form onSubmit={handleSubmit}>
    {/* Campos armadilha — invisíveis para humanos */}
    {honeypot.hiddenInputs.map((props) => (
      <input key={props.name} {...props} onChange={() => {}} />
    ))}
    {/* Timestamp — necessário para timing check */}
    <input
      name={honeypot.timestampField.name}
      type={honeypot.timestampField.type}
      value={honeypot.timestampField.value}
      onChange={() => {}}
    />

    {/* Campos reais do formulário */}
    <input name="nome" type="text" required />
    <button type="submit">Enviar</button>
  </form>
);
```

### 5.5 Presets por tipo de formulário

| `formType` | Tempo mínimo | Threshold | Campos isca |
|---|---|---|---|
| `"search"` | 500ms | 80 (permissivo) | 1 campo |
| `"newsletter"` | 1.500ms | 75 | 2 campos |
| `"login"` | 2.000ms | 60 (restritivo) | 3 campos |
| `"contact"` | 3.000ms | 70 | 4 campos |
| `"register"` | 5.000ms | 55 | 7 campos |
| `"checkout"` | 8.000ms | 50 (máximo) | 5 campos |

---

## 6. Captcha Handler — verificação ativa

### 6.1 O que é

O `captcha-handler.ts` é um adapter sobre `recaptcha.ts` que simplifica a configuração com **presets por contexto de uso**.

Em vez de configurar `minScore`, `expectedAction` e `preventTokenReplay` manualmente em cada endpoint, você passa um `context` e os valores corretos são aplicados automaticamente.

### 6.2 Qual provedor usar?

| Provedor | `provider` | Score | Fricção | Quando usar |
|---|---|---|---|---|
| reCAPTCHA v3 | `"recaptcha_v3"` | ✓ 0.0–1.0 | Zero | Recomendado para maioria |
| reCAPTCHA v2 | `"recaptcha_v2"` | ✗ | Checkbox | Fallback quando v3 falha |
| reCAPTCHA Enterprise | `"recaptcha_enterprise"` | ✓ + reason codes | Zero | Alto volume, apps críticos |
| hCaptcha | `"hcaptcha"` | ✓ | Variável | Alternativa privacy-first |
| Turnstile | `"turnstile"` | ✗ | Zero | Cloudflare, gratuito |

### 6.3 Uso com contexto automático

```ts
import { handleCaptcha, buildCaptchaResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  const captcha = await handleCaptcha(request, {
    provider:  "recaptcha_v3",
    secretKey: process.env.RECAPTCHA_SECRET_KEY!,
    context:   "login", // ← aplica minScore: 0.7 automaticamente
    expectedHostnames: ["meusite.com.br"],
  });

  if (!captcha.ok) {
    return buildCaptchaResponse(captcha); // resposta HTTP correta para cada erro
  }

  // captcha.score disponível (ex: 0.85)
}
```

### 6.4 Score mínimo por contexto

| `context` | `minScore` | Por quê |
|---|---|---|
| `"checkout"` | 0.80 | Fraude financeira — máximo rigor |
| `"login"` | 0.70 | Credential stuffing — alto risco |
| `"password_reset"` | 0.70 | Account takeover |
| `"vote"` | 0.70 | Manipulação de resultados |
| `"register"` | 0.60 | Account farming |
| `"download"` | 0.50 | Bandwidth abuse |
| `"contact"` | 0.40 | Spam — mais permissivo |
| `"newsletter"` | 0.30 | Baixo risco |

### 6.5 Factory para reutilizar em múltiplos endpoints

```ts
// lib/security/captcha-instances.ts
import { createRecaptchaV3Handler } from "@/lib/security/anti-bot";

// Cria uma função pré-configurada — reutilize em qualquer Route Handler
export const verifyRecaptcha = createRecaptchaV3Handler(
  process.env.RECAPTCHA_SECRET_KEY!,
  ["meusite.com.br"], // hostnames esperados
);
```

```ts
// app/api/login/route.ts
import { verifyRecaptcha } from "@/lib/security/captcha-instances";
import { buildCaptchaResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  const result = await verifyRecaptcha(request, "login"); // contexto "login"
  if (!result.ok) return buildCaptchaResponse(result);
  // ...
}
```

---

## 7. Turnstile Validator — Cloudflare Turnstile

### 7.1 O que é

O `turnstile-validator.ts` é um adapter sobre `captcha-handler.ts` específico para o [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) — um CAPTCHA gratuito, sem fricção (o usuário não precisa clicar em nada) e focado em privacidade.

> **Quando usar:** Se seu projeto já usa Cloudflare (CDN, Workers, Pages), Turnstile é a melhor escolha. Gratuito, sem limites de requisição e não coleta dados do usuário como o Google.

### 7.2 Configuração client-side

```tsx
// app/layout.tsx — adiciona o script do Turnstile globalmente
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <head>
        <script
          src="https://challenges.cloudflare.com/turnstile/v0/api.js"
          async
          defer
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

```tsx
// No formulário — adiciona o widget invisível
<form onSubmit={handleSubmit}>
  {/* Widget do Turnstile — invisível, sem clique necessário */}
  <div
    className="cf-turnstile"
    data-sitekey={process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY}
    data-callback="onTurnstileSuccess" // opcional
  />

  <input name="nome" type="text" required />
  <button type="submit">Enviar</button>
</form>
```

### 7.3 Verificação server-side

```ts
import { TurnstileValidator, buildTurnstileResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const token = body["cf-turnstile-response"] as string;
  const ip    = request.headers.get("cf-connecting-ip") ?? undefined;

  const result = await TurnstileValidator.validate(token, process.env.TURNSTILE_SECRET_KEY!, {
    remoteIp:         ip,
    expectedHostname: "meusite.com.br",
  });

  if (!result.success) {
    // Bot ou token inválido
    return NextResponse.json({ success: true }); // resposta falsa
  }

  // continua...
}
```

---

## 8. Bot Detection — orquestrador

### 8.1 Quando usar o orquestrador vs. módulos individuais

| Situação | Usar |
|---|---|
| Formulário de contato simples | `checkHoneypotField()` direto |
| Login com CAPTCHA | `handleCaptcha()` direto |
| Formulário crítico (cadastro, checkout, pagamento) | `detectBot()` — pipeline completo |
| Middleware global em todas as rotas | `withBotDetection()` |

### 8.2 Uso básico do detectBot

```ts
// app/api/cadastro/route.ts
import { NextRequest, NextResponse } from "next/server";
import { detectBot, buildBotResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  const result = await detectBot(request, {
    // Configura cada módulo individualmente
    honeypot: {
      secret: process.env.HONEYPOT_SECRET!,
    },
    behavioral: {
      minHumanScore: 40, // score mínimo para aceitar
    },
    captcha: {
      provider:       "recaptcha_v3",
      secretKey:      process.env.RECAPTCHA_SECRET_KEY!,
      minScore:       0.6,
      expectedAction: "register",
    },

    // Thresholds do score final
    blockThreshold:     70, // ≥ 70 → bloqueia
    challengeThreshold: 50, // 50–69 → challenge
    monitorThreshold:   30, // 30–49 → monitora
  });

  // "block" ou "challenge" → responder sem revelar detecção
  if (result.action === "block") {
    return NextResponse.json({ success: true }); // resposta falsa
  }

  if (result.action === "challenge") {
    return NextResponse.json({ requireVerification: true }, { status: 401 });
  }

  // "allow" ou "monitor" → processa normalmente
  // result.riskScore disponível para lógica adicional
  const body = await request.json();
  await criarUsuario(body);
  return NextResponse.json({ success: true });
}
```

### 8.3 Wrapper automático (withBotDetection)

```ts
// app/api/voto/route.ts
import { withBotDetection } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  return withBotDetection(
    request,
    async (botResult) => {
      // Só chega aqui se action === "allow" ou "monitor"
      // botResult.riskScore disponível se quiser lógica adicional
      const body = await request.json();
      await registrarVoto(body.opcao);
      return NextResponse.json({ success: true });
    },
    {
      honeypot: { secret: process.env.HONEYPOT_SECRET! },
      captcha: {
        provider:  "recaptcha_v3",
        secretKey: process.env.RECAPTCHA_SECRET_KEY!,
        minScore:  0.7,
        expectedAction: "vote",
      },
    }
  );
}
```

### 8.4 Callback de auditoria

```ts
const result = await detectBot(request, {
  // ... opções ...

  onBotDetected: async (result, req) => {
    // Chamado automaticamente quando bot é detectado
    // Use para: logging, alertas, integração com SIEM
    await logger.warn("bot_detected", {
      ip:        result.audit.ip,
      score:     result.riskScore,
      action:    result.action,
      checks:    result.audit.checksRun,
      signals:   result.signals.map(s => s.violation),
      processingMs: result.audit.processingMs,
    });
  },
});
```

### 8.5 Interpretando o resultado

```ts
console.log(result.isBot);        // boolean — a decisão final
console.log(result.action);       // "allow" | "block" | "challenge" | "monitor"
console.log(result.riskScore);    // 0–100
console.log(result.audit.checksRun); // ["honeypot", "behavioral", "captcha"]
console.log(result.audit.processingMs); // tempo total em ms

// Detalhes de cada módulo (não expor ao cliente)
console.log(result.details.honeypot?.triggered);   // "FIELD_FILLED"
console.log(result.details.behavioral?.verdict);   // "likely_bot"
console.log(result.details.captcha?.score);        // 0.23
```

---

## 9. index.ts — como importar

O `index.ts` é o barrel file — ponto único de importação. Há duas formas:

### Forma 1 — Importação nomeada (recomendada)

```ts
import {
  // Orquestrador
  detectBot,
  withBotDetection,
  buildBotResponse,
  getBotRiskLabel,

  // Behavioral
  analyzeBehavior,
  BehavioralCollector,

  // Captcha
  handleCaptcha,
  buildCaptchaResponse,
  CONTEXT_MIN_SCORES,

  // Honeypot
  isHoneypotFilled,
  checkSubmitTiming,
  checkHoneypotField,
  getHoneypotFormProps,

  // Turnstile
  TurnstileValidator,
} from "@/lib/security/anti-bot";
```

### Forma 2 — Namespace agrupado

```ts
import { BotDetection, Behavioral, Captcha, HoneypotField, Turnstile }
  from "@/lib/security/anti-bot";

// Uso
const result    = await BotDetection.detectBot(request, opts);
const telemetry = Behavioral.analyzeBehavior(data);
const captcha   = await Captcha.handleCaptcha(request, captchaOpts);
const filled    = HoneypotField.isHoneypotFilled(body);
const turnstile = await Turnstile.TurnstileValidator.validate(token, secret);
```

> **Nota sobre nomes renomeados:** `getRiskLabel` existe em dois módulos com semânticas diferentes. No barrel, foram renomeados para evitar conflito:
> - `getBotRiskLabel(score: 0–100)` — vem de `bot-detection.ts`
> - `getCaptchaRiskLabel(score: 0–100)` — vem de `captcha-handler.ts` (baseado em score CAPTCHA invertido)

---

## 10. Exemplos completos por cenário

### Cenário 1 — Formulário de contato (baixo risco)

```ts
// app/api/contato/route.ts
import { NextRequest, NextResponse }       from "next/server";
import { isHoneypotFilled, checkSubmitTiming } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  const body = await request.json() as Record<string, unknown>;

  // Honeypot rápido — sem I/O
  const field = isHoneypotFilled(body);
  if (field.detected) {
    return NextResponse.json({ success: true }); // falso positivo intencional
  }

  const timing = checkSubmitTiming(body, { formType: "contact" });
  if (timing.tooFast) {
    return NextResponse.json({ success: true });
  }

  await enviarEmail(body);
  return NextResponse.json({ success: true });
}
```

### Cenário 2 — Login (risco médio)

```ts
// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from "next/server";
import { handleCaptcha, buildCaptchaResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  // Verifica CAPTCHA antes de qualquer acesso ao banco
  const captcha = await handleCaptcha(request, {
    provider:         "recaptcha_v3",
    secretKey:        process.env.RECAPTCHA_SECRET_KEY!,
    context:          "login",  // minScore: 0.7 automático
    expectedHostnames: ["meusite.com.br"],
  });

  if (!captcha.ok) {
    return buildCaptchaResponse(captcha); // 403 ou 400 conforme o erro
  }

  const { email, password } = await request.json();
  const user = await autenticar(email, password);
  return NextResponse.json({ token: user.token });
}
```

### Cenário 3 — Cadastro (alto risco, pipeline completo)

```ts
// app/api/auth/register/route.ts
import { NextRequest, NextResponse } from "next/server";
import { detectBot, buildBotResponse } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  const result = await detectBot(request, {
    honeypot:  { secret: process.env.HONEYPOT_SECRET! },
    behavioral: { minHumanScore: 40 },
    captcha: {
      provider:       "recaptcha_v3",
      secretKey:      process.env.RECAPTCHA_SECRET_KEY!,
      context:        "register",
      minScore:       0.6,
    },
    blockThreshold:     70,
    challengeThreshold: 50,
    onBotDetected: async (r) => {
      await logger.warn("register_bot", { ip: r.audit.ip, score: r.riskScore });
    },
  });

  if (result.action !== "allow" && result.action !== "monitor") {
    return buildBotResponse(result);
  }

  const body = await request.json();
  await criarUsuario(body);
  return NextResponse.json({ success: true });
}
```

### Cenário 4 — Checkout (máximo rigor)

```ts
// app/api/checkout/route.ts
import { NextRequest, NextResponse } from "next/server";
import { withBotDetection } from "@/lib/security/anti-bot";

export async function POST(request: NextRequest) {
  return withBotDetection(
    request,
    async (botResult) => {
      // Se chegou aqui, passou em todas as verificações
      const body = await request.json();
      const order = await processarPagamento(body);
      return NextResponse.json({ orderId: order.id });
    },
    {
      honeypot:  { secret: process.env.HONEYPOT_SECRET! },
      behavioral: { minHumanScore: 50 }, // mais restritivo
      captcha: {
        provider:  "recaptcha_v3",
        secretKey: process.env.RECAPTCHA_SECRET_KEY!,
        context:   "checkout", // minScore: 0.8
      },
      blockThreshold:     60, // mais restritivo que o padrão (70)
      onModuleError:      "block", // falha fechada — segurança máxima
    }
  );
}
```

---

## 11. Erros comuns de dev júnior

### ❌ Erro 1 — Retornar 403 quando detectar bot

```ts
// ERRADO — o bot sabe que foi detectado e muda de estratégia
if (result.isBot) {
  return NextResponse.json({ error: "Bot detected" }, { status: 403 });
}
```

```ts
// CORRETO — bot pensa que funcionou, continua tentando sem resultado
if (result.isBot) {
  return NextResponse.json({ success: true });
}
```

### ❌ Erro 2 — Verificar bot DEPOIS de acessar o banco

```ts
// ERRADO — consulta cara feita antes de verificar o bot
export async function POST(request: NextRequest) {
  const user = await db.findUser(email); // ← bot pode forçar 10.000 queries
  const result = await detectBot(request, opts);
  if (result.isBot) return fakeResponse();
}
```

```ts
// CORRETO — bot checado primeiro, banco só depois
export async function POST(request: NextRequest) {
  const result = await detectBot(request, opts);
  if (result.isBot) return fakeResponse();
  const user = await db.findUser(email); // ← só chega aqui se passou
}
```

### ❌ Erro 3 — Esquecer de enviar a telemetria do cliente

```ts
// ERRADO — behavioral check sempre retorna score 50 (neutro) sem dados
await fetch("/api/login", {
  method: "POST",
  body: JSON.stringify({ email, password }), // ← sem telemetry
});
```

```ts
// CORRETO — inclui a telemetria coletada pelo BehavioralCollector
const telemetry = collectorRef.current?.collect();
await fetch("/api/login", {
  method: "POST",
  body: JSON.stringify({ email, password, telemetry }), // ← com telemetry
});
```

### ❌ Erro 4 — Criar nova instância do BehavioralCollector em cada render

```tsx
// ERRADO — nova instância a cada render = perde o histórico de eventos
function ContatoForm() {
  const collector = new BehavioralCollector(); // ← recriado a cada render!
  collector.start();
}
```

```tsx
// CORRETO — instância persistente via useRef
function ContatoForm() {
  const collectorRef = useRef<BehavioralCollector | null>(null);

  useEffect(() => {
    collectorRef.current = new BehavioralCollector();
    collectorRef.current.start();
    return () => collectorRef.current?.stop();
  }, []); // ← executa uma única vez
}
```

### ❌ Erro 5 — Expor a secret key do CAPTCHA no cliente

```ts
// ERRADO — variável sem NEXT_PUBLIC_ não deveria existir no código cliente
const result = await fetch("...", {
  body: JSON.stringify({ secret: process.env.RECAPTCHA_SECRET_KEY }), // ← NUNCA!
});
```

```ts
// CORRETO — secret key fica APENAS no servidor
// Cliente usa: process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY (pública)
// Servidor usa: process.env.RECAPTCHA_SECRET_KEY (privada)
```

---

## 12. Referência rápida da API

### Orquestrador (bot-detection.ts)

| Função | O que faz |
|---|---|
| `detectBot(request, opts)` | Executa o pipeline completo, retorna `BotDetectionResult` |
| `withBotDetection(request, handler, opts)` | Wrapper que chama `handler` apenas se não for bot |
| `buildBotResponse(result)` | Gera `NextResponse` correta (200 falso em produção) |
| `getBotRiskLabel(score)` | `"Crítico"`, `"Alto risco"`, `"Médio"`, `"Baixo"`, `"Mínimo"` |
| `isDefinitelyBot(result)` | `true` se `riskScore ≥ 90` ou WebDriver detectado |

### Behavioral Analysis (behavioral-analysis.ts)

| Função / Classe | O que faz |
|---|---|
| `new BehavioralCollector()` | Cria coletor client-side |
| `collector.start()` | Inicia coleta de eventos DOM |
| `collector.collect()` | Retorna `UserTelemetry` para enviar ao servidor |
| `collector.stop()` | Para coleta e remove event listeners |
| `analyzeBehavior(telemetry, opts)` | Analisa telemetria, retorna `BehavioralResult` |
| `getVerdictLabel(verdict)` | `"Humano confirmado"`, `"Suspeito"`, etc. |
| `combineScores({ behavioralScore, captchaScore })` | Combina os dois scores com pesos |

### Captcha Handler (captcha-handler.ts)

| Função | O que faz |
|---|---|
| `handleCaptcha(request, opts)` | Verifica token com preset por contexto |
| `createRecaptchaV3Handler(secret, hostnames)` | Factory para reCAPTCHA v3 |
| `createTurnstileHandler(secret)` | Factory para Turnstile |
| `createHCaptchaHandler(secret, siteKey)` | Factory para hCaptcha |
| `buildCaptchaResponse(result)` | Gera `NextResponse` de erro correta |
| `isCaptchaProbableBot(result)` | `true` se score < 0.4 |
| `captchaRiskScore(result)` | Converte resultado para 0–100 |
| `CONTEXT_MIN_SCORES` | Tabela de scores mínimos por contexto |

### Honeypot Field (honeypot-field.ts)

| Função | O que faz |
|---|---|
| `isHoneypotFilled(body)` | Verifica se campo isca foi preenchido (síncrono) |
| `checkSubmitTiming(body, opts)` | Verifica se enviou rápido demais |
| `checkHoneypotField(body, request, opts)` | Verificação completa com token |
| `getHoneypotInputProps(fieldName)` | Props React para campo invisible |
| `getHoneypotFormProps(formType)` | Todos os campos do preset como props React |
| `honeypotRiskScore(result)` | Converte para 0–100 |
| `isDefinitelyHoneypotBot(result)` | `true` com altíssima certeza |

### Turnstile Validator (turnstile-validator.ts)

| Função / Objeto | O que faz |
|---|---|
| `TurnstileValidator.validate(token, secret, opts)` | Verifica token na API Cloudflare |
| `TurnstileValidator.verifyRequest(request, opts)` | Verifica a partir de `NextRequest` |
| `isTurnstileSuccess(response)` | `true` se `response.success === true` |
| `getTurnstileErrors(response)` | Retorna string de erros para logging |
| `turnstileRiskScore(response)` | Converte para 0–100 (`timeout-or-duplicate` → 85) |

---

## Integração na stack de segurança

Este módulo é a quinta camada da stack. A ordem de execução no middleware:

```
Request
  │
  1. networkPolicies.ts    → CORS, CSP, security headers
  2. firewallRules.ts      → IP blocklist, geo-blocking, WAF
  3. dnsProtection.ts      → Host header, DNS rebinding
  4. vpnEnforcement.ts     → VPN corporativa / proxies anônimos
  5. anti-bot/ (este)      → Honeypot, behavioral, CAPTCHA
  6. trafficInspection.ts  → DPI, análise comportamental server
  7. requestSanitizer.ts   → XSS, SQLi, payload sanitization
  │
  Lógica de negócio
```