# Módulo de Segurança — Guia Completo

> **Para quem é este guia?**
> Para desenvolvedores júnior que precisam entender o que cada arquivo faz,
> por que ele existe e como usá-lo sem quebrar nada.
>
> **TL;DR para quem tem pressa:**
> Todo request HTTP passa por uma fila de verificações antes de chegar
> no seu handler. Cada arquivo desta pasta é uma dessas verificações.

---

## Índice

1. [Como a pipeline funciona](#1-como-a-pipeline-funciona)
2. [Conceitos fundamentais](#2-conceitos-fundamentais)
3. [XSS — Proteção de conteúdo](#3-xss--proteção-de-conteúdo)
4. [Controle de acesso por IP](#4-controle-de-acesso-por-ip)
5. [Rate Limiting e DDoS](#5-rate-limiting-e-ddos)
6. [Autenticidade da requisição](#6-autenticidade-da-requisição)
7. [Políticas de rede](#7-políticas-de-rede)
8. [Orquestrador central](#8-orquestrador-central)
9. [Como adicionar uma nova regra](#9-como-adicionar-uma-nova-regra)
10. [Erros comuns de júnior](#10-erros-comuns-de-júnior)

---

## 1. Como a pipeline funciona

Imagine um porteiro de prédio com uma lista de verificações. Cada pessoa
(requisição) que chega passa por todas as verificações em ordem.
Se qualquer uma reprovar, a pessoa vai embora sem entrar.

```
Request HTTP
     │
     ▼
┌─────────────────────────────────────────┐
│         securityMiddleware.ts           │  ← o porteiro-chefe
│  (orquestra todos os outros em ordem)   │
└──────────┬──────────────────────────────┘
           │
           ├──► 1. CORS          (de onde veio?)
           ├──► 2. IP Filter     (quem é esse IP?)
           ├──► 3. Integrity     (o pacote foi adulterado?)
           ├──► 4. Rate Limit    (está mandando rápido demais?)
           ├──► 5. DDoS          (parece um ataque em volume?)
           ├──► 6. Bot           (é um robô?)
           ├──► 7. Geo           (veio de onde no mundo?)
           └──► 8. CSRF          (é mesmo o nosso usuário fazendo isso?)
                    │
                    ▼
              Seu handler
              (finalmente!)
```

**Regra de ouro:** verificações baratas vêm antes. Checar se um IP está
numa lista negra custa quase nada. Checar assinatura HMAC custa mais.
Por isso a ordem importa.

---

## 2. Conceitos fundamentais

Antes de ler os arquivos, entenda estes termos:

| Termo | O que significa na prática |
|---|---|
| **Middleware** | Função que roda entre a chegada do request e o handler. Pode bloquear, modificar ou deixar passar. |
| **Allowlist** | Lista de coisas *permitidas*. Tudo que não está na lista é bloqueado. |
| **Blocklist** | Lista de coisas *proibidas*. Tudo que não está na lista é permitido. |
| **CIDR** | Forma de escrever um range de IPs. `192.168.1.0/24` = todos os IPs de 192.168.1.0 até 192.168.1.255 |
| **TTL** | Time to Live — tempo que uma informação fica válida antes de expirar. |
| **Store** | Onde os contadores e estados são salvos. Em dev: memória. Em prod: Redis. |
| **Score de risco** | Número de 0 a 100. Quanto maior, mais suspeito o IP. 90+ leva ban. |
| **Fail open** | Se o sistema de segurança quebrar, a requisição passa (disponibilidade > segurança). |
| **Fail closed** | Se o sistema de segurança quebrar, a requisição é bloqueada (segurança > disponibilidade). |
| **HMAC** | Assinatura criptográfica. Garante que um dado não foi alterado em trânsito. |
| **Nonce** | Número aleatório usado apenas uma vez. Previne que requests sejam reenviados. |

---

## 3. XSS — Proteção de conteúdo

XSS (Cross-Site Scripting) é quando um atacante injeta código JavaScript
malicioso em páginas que outros usuários vão ver. Ex: comentário com
`<script>roubarSuaSenha()</script>` que o banco de dados salva e serve
de volta para outros usuários.

### `html-sanitizer.ts`

**O problema que resolve:** Você quer mostrar HTML do usuário na página
(ex: editor de texto rico, comentários formatados), mas HTML do usuário
pode conter `<script>` ou `<img onerror="roubarDados()">`.

**O que faz:** Usa a biblioteca DOMPurify para remover tudo que é
perigoso do HTML, mantendo apenas tags seguras como `<b>`, `<p>`,
`<a href>` com URLs seguras.

**Quando usar:**
```typescript
// ❌ NUNCA faça isso com HTML vindo do usuário ou de API externa:
element.innerHTML = dadosDoUsuario;

// ✅ Sempre sanitize primeiro:
import { sanitizeHtml } from './html-sanitizer';
element.innerHTML = sanitizeHtml(dadosDoUsuario);

// Para comentários simples (só texto, sem formatação):
element.innerHTML = sanitizeHtml(comentario, 'strict');

// Para artigos de blog (links e imagens permitidos):
element.innerHTML = sanitizeHtml(artigo, 'content');

// Para editor WYSIWYG (tabelas, alinhamento, tudo):
element.innerHTML = sanitizeHtml(conteudoEditor, 'richText');
```

**Os 5 perfis disponíveis:**

| Perfil | Permite | Uso típico |
|---|---|---|
| `inlineOnly` | Só `<b>`, `<i>`, `<em>` | Labels, tooltips curtos |
| `strict` | Tags inline + `<span>` | Comentários, bios |
| `content` | Tudo acima + links, imagens | Artigos, posts de blog |
| `richText` | Tudo acima + tabelas, vídeo | Editor WYSIWYG, CMS |
| `svgSafe` | Tags SVG seguras | Ícones embutidos |

---

### `xss-protection.ts`

**O problema que resolve:** Às vezes você não quer renderizar HTML —
você quer inserir texto em contextos diferentes: dentro de um
atributo HTML, dentro de um bloco `<script>`, dentro de CSS.
Cada contexto precisa de um tipo diferente de escape.

**Por que não dá pra usar sempre o mesmo escape:**
- `&lt;` é seguro dentro de HTML, mas dentro de JavaScript vira
  literalmente `&lt;` na tela — errado.
- `\"` é seguro em JavaScript, mas não protege dentro de CSS.

**Guia rápido de qual função usar onde:**

```typescript
import {
  escapeHtml,       // conteúdo de elemento HTML
  escapeHtmlAttr,   // valor de atributo HTML
  escapeUrl,        // href, src, action
  escapeJs,         // dentro de bloco <script>
  escapeCss,        // valor de propriedade CSS
  escapeJsonForHtml,// JSON dentro de <script type="application/json">
  safeHtml,         // template literal automático
} from './xss-protection';

// ── Contexto HTML ──────────────────────────────────────────────
// Você está montando HTML como string (ex: SSR, email template)
const html = `<p>${escapeHtml(nomeDoUsuario)}</p>`;

// ── Contexto atributo ──────────────────────────────────────────
// ERRADO — "onclick" pode fechar o atributo e injetar evento:
const errado = `<div title="${nomeDoUsuario}">`;
// CORRETO:
const certo  = `<div title="${escapeHtmlAttr(nomeDoUsuario)}">`;

// ── Contexto URL ───────────────────────────────────────────────
// Bloqueia javascript:, data:, vbscript: automaticamente
const link = `<a href="${escapeUrl(urlDoUsuario)}">clique</a>`;

// ── Contexto JavaScript ────────────────────────────────────────
// Você está inserindo dados em um bloco <script> (SSR)
const script = `<script>var nome = "${escapeJs(nomeDoUsuario)}";</script>`;

// ── Template literal automático (mais seguro — escape automático) ──
// Cada ${} é escapado automaticamente — você não pode esquecer
const html2 = safeHtml`<p>Olá ${nomeDoUsuario}, seu email é ${email}</p>`;

// ── JSON em script ─────────────────────────────────────────────
// JSON.stringify normal produz </script> que fecha o bloco!
// Isso causa XSS em Next.js, Nuxt, Angular SSR.
const script2 = `
  <script type="application/json">
    ${escapeJsonForHtml(dadosIniciais)}
  </script>
`;
```

---

### `dom-xss-guard.ts`

**O problema que resolve:** Mesmo com o HTML sanitizado, ainda é
possível causar XSS ao usar APIs do DOM diretamente no JavaScript
do browser. `element.innerHTML = algo` pode executar scripts
dependendo do contexto.

**Regra simples:** nunca use as APIs "perigosas" do DOM diretamente.
Use sempre as versões seguras deste arquivo:

| API perigosa | Substituto seguro |
|---|---|
| `element.innerHTML = html` | `safeSetInnerHTML(element, html)` |
| `element.insertAdjacentHTML(pos, html)` | `safeInsertAdjacentHTML(element, pos, html)` |
| `element.setAttribute('href', url)` | `safeSetURLAttribute(element, 'href', url)` |
| `element.setAttribute('onclick', fn)` | **Proibido.** Use `addEventListener` |
| `element.setAttribute('style', css)` | `safeSetStyle(element, css)` |
| `document.createElement('script')` | `safeCreateElement('script')` → retorna null |
| `window.open(url)` | `safeOpenWindow(url)` |
| `window.location.href = url` | `safeNavigate(url)` |
| `document.write(html)` | `safeDocumentWrite(html)` → sempre lança erro |

```typescript
import { safeSetInnerHTML, safeSetURLAttribute, safeNavigate } from './dom-xss-guard';

// Exemplo real — renderizar HTML de uma API:
const container = document.getElementById('conteudo');
safeSetInnerHTML(container, respostasDaAPI.html);

// Exemplo real — definir link dinâmico:
const link = document.querySelector('a.perfil');
safeSetURLAttribute(link, 'href', usuario.profileUrl);
// Se usuario.profileUrl for "javascript:alert(1)", vai virar "#" automaticamente

// Auditoria — verifica um trecho do DOM por atributos perigosos:
const problemas = auditDOMForXSS(document.body);
if (problemas.length > 0) console.error('XSS potencial:', problemas);
```

---

## 4. Controle de acesso por IP

### `ipAllowlist.ts`

**O problema que resolve:** Certos endpoints só devem ser acessíveis
por IPs específicos. Ex: o painel admin só pode ser acessado do
escritório. A API de integração só pode ser chamada pelo servidor
do parceiro.

**Como funciona:** Você registra IPs ou ranges CIDR. Qualquer request
de IP não listado é bloqueado (modo `strict`) ou apenas logado
(modo `log`).

```typescript
import { IPAllowlist, MemoryAllowlistStore } from './ipAllowlist';

const adminAllowlist = new IPAllowlist({
  mode:  'strict',
  store: new MemoryAllowlistStore(),
});

// Adiciona o escritório permanentemente
await adminAllowlist.addPermanent(
  '203.0.113.0/24',       // toda a subnet do escritório
  'Escritório São Paulo', // descrição para auditoria
  'admin@empresa.com',    // quem adicionou
);

// Acesso temporário para desenvolvedor externo (expira em 8h)
await adminAllowlist.addTemporary(
  '198.51.100.5',
  'Dev externo João — Sprint 42',
  8 * 60 * 60 * 1000,     // 8 horas em ms
  'gerente@empresa.com',
);

// IP vinculado a um usuário específico (banking — segurança extra)
await adminAllowlist.bindToUser(
  '203.0.113.10',
  userId,
  'IP residencial do cliente',
);
```

**Os 3 modos:**

| Modo | Comportamento | Quando usar |
|---|---|---|
| `strict` | Bloqueia IPs não listados | Produção — admin, APIs privadas |
| `log` | Permite mas registra não-listados | Migração — antes de ativar strict |
| `report` | Permite mas chama `onUnknownIP` | Monitoramento sem bloqueio |

---

### `ipBlocklist.ts`

**O problema que resolve:** O oposto da allowlist. Você quer bloquear
IPs específicos que estão causando problemas: scrapers agressivos,
IPs de ataques conhecidos, nós Tor, etc.

**Diferencial importante — backoff exponencial:** Um atacante que
recebe um ban de 1 hora pode simplesmente esperar e tentar de novo.
O backoff exponencial torna isso progressivamente mais custoso:

```
1ª violação: banido por 1 hora
2ª violação: banido por 2 horas
3ª violação: banido por 4 horas
4ª violação: banido por 8 horas
5ª violação: banido PERMANENTEMENTE
```

```typescript
import { IPBlocklist, MemoryBlocklistStore } from './ipBlocklist';

const blocklist = new IPBlocklist({
  store:                    new MemoryBlocklistStore(),
  defaultBanTTL:            3_600_000,  // 1 hora
  backoffMultiplier:        2,          // dobra a cada reincidência
  permanentBanAfterStrikes: 5,          // permanente após 5 strikes
});

// Ban manual (permanente por padrão)
await blocklist.ban(
  '198.51.100.50',
  'bruteforce',
  'Tentou 500 logins em 10 minutos',
  'admin@empresa.com',
);

// Ban temporário (com backoff automático)
await blocklist.banTemporary(
  ip,
  'scraper',
  'Acessou 10.000 páginas em 1 minuto',
);

// Carregar feed externo de IPs maliciosos (ex: lista Tor)
await blocklist.loadFeed({
  name:       'tor-project',
  url:        'https://check.torproject.org/torbulkexitlist',
  refreshMs:  3_600_000, // atualiza a cada hora
  confidence: 95,
  category:   'tor',
});

// Reportar violação (integração com outros middlewares)
await blocklist.reportViolation(ip, 'bruteforce', 'Falhou autenticação 10x');
```

---

### `ipFilter.ts`

**O problema que resolve:** É uma camada mais inteligente que combina
allowlist, blocklist e *scoring de reputação*. Em vez de uma decisão
binária (bloquear/permitir), o ipFilter acumula evidências ao longo
do tempo e toma decisões graduais.

**Como o score funciona:**

```
Score 0-49:   IP limpo — ALLOW
Score 50-74:  IP suspeito — CHALLENGE (pede CAPTCHA)
Score 75-89:  IP ruim — BLOCK (403)
Score 90+:    IP malicioso — BAN automático (por 1 hora)
```

**O problema do CGNAT:** Uma operadora de celular pode colocar
milhares de usuários no mesmo IP (ex: todos clientes da operadora X
em SP usam o mesmo IP saindo para internet). Se você bana esse IP,
você bana TODOS os clientes dessa operadora. O ipFilter detecta
isso e protege:

```typescript
// Se 10+ fingerprints de browser diferentes acessam o mesmo IP
// → provavelmente é CGNAT → não bana automaticamente
```

```typescript
import { IPFilter, createBalancedIPFilter } from './ipFilter';

const filter = createBalancedIPFilter(store);

// No seu handler de login — reporta falha de autenticação:
app.post('/api/auth/login', async (req, res) => {
  const isValid = await verificarSenha(req.body);
  if (!isValid) {
    // Aumenta o score de risco deste IP
    await filter.reportViolation(req.ip, 'AUTH_BRUTEFORCE');
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }
  // ...
});
```

---

## 5. Rate Limiting e DDoS

### `rateLimit.ts`

**O problema que resolve:** Sem rate limiting, qualquer pessoa pode
chamar sua API 10.000 vezes por segundo. Isso pode ser um ataque,
um bug no cliente, ou alguém testando seu sistema.

**Os 5 algoritmos — qual usar quando:**

| Algoritmo | Ideal para | Não use quando |
|---|---|---|
| `fixed-window` | Limites globais simples | Precisão importa (tem burst no boundary) |
| `sliding-window` | **Recomendado geral** — preciso, sem burst | Memória é muito limitada |
| `token-bucket` | Usuários que fazem bursts legítimos | Taxa constante é obrigatória |
| `leaky-bucket` | Proteger API downstream com taxa fixa | Usuários fazem bursts legítimos |
| `concurrent` | Uploads, WebSockets, operações lentas | Requests rápidos |

**Exemplo prático:**

```typescript
import { createDefaultRateLimiter } from './rateLimit';

const limiter = createDefaultRateLimiter(store, {
  onLimitReached: async (result, req) => {
    // Penaliza o IP no ipFilter quando excede o limite
    await ipFilter.reportViolation(req.ip!, 'RATE_LIMIT_EXCEEDED');
  },
});

// O limiter já vem com regras padrão para rotas comuns:
// /api/auth/login:    5 requests/min (protege brute force)
// /api/auth/register: 3 requests/min
// /api/payments:      10 requests/min (token bucket, burst de 3)
// /api/graphql:       200 requests/min por usuário
// /api/export:        3 por 5 minutos (cada export custa 10 tokens)
// /api/upload:        3 uploads simultâneos (concurrent limit)
```

**Headers que o cliente recebe:**

```
RateLimit-Limit: 100        ← seu limite total
RateLimit-Remaining: 73     ← quantos restam
RateLimit-Reset: 1735000000 ← quando reseta (Unix timestamp)
Retry-After: 42             ← segundos para aguardar (só quando bloqueado)
```

---

### `ddosProtection.ts`

**O problema que resolve:** Rate limiting por IP não é suficiente
para um DDoS distribuído — o ataque vem de milhares de IPs
diferentes, cada um mandando poucos requests. O DDoS protection
olha o *padrão geral* além do IP individual.

**Componentes especiais:**

**Circuit Breaker** — imagine um disjuntor elétrico. Se uma rota
está recebendo muitos erros 500 (servidor sobrecarregado), o circuit
breaker "abre" e começa a rejeitar requests imediatamente, dando
tempo para o sistema se recuperar. Após alguns segundos, testa
novamente. Se OK, fecha o circuito.

```
Estado FECHADO: requisições passam normalmente
    ↓ (50% de erros 5xx em 30s)
Estado ABERTO: requisições rejeitadas imediatamente (503)
    ↓ (após 15s)
Estado HALF-OPEN: testa 5 requisições
    ↓ (se OK)
Estado FECHADO: volta ao normal
```

**Proteção adaptativa** — aprende o tráfego normal e detecta
quando está 3x acima do baseline:

```
Baseline: 100 req/s (média das últimas 5 horas)
Ataque detectado quando: > 300 req/s
Modo de ataque: limites reduzidos em 70% automaticamente
```

```typescript
import { createDDoSProtection } from './ddosProtection';

const ddos = createDDoSProtection({ store });

// Após cada request, registra o status da resposta
// para o circuit breaker funcionar:
app.use((req, res, next) => {
  res.on('finish', () => {
    ddos.recordResponse(req.path, res.statusCode);
  });
  next();
});

// O tarpitting atrasa requisições suspeitas sem revelar o bloqueio
// (o bot fica esperando, consumindo recursos do lado dele)
ddos.config.tarpit = { enabled: true, minDelayMs: 2000, maxDelayMs: 10000 };
```

---

## 6. Autenticidade da requisição

### `csrfProtection.ts`

**O problema que resolve:** CSRF (Cross-Site Request Forgery) é quando
um site malicioso faz seu browser enviar requests para outro site
onde você está logado, sem você saber.

**Exemplo de ataque:**
1. Você está logado no banco `banco.com`
2. Você acessa `site-malicioso.com`
3. O site malicioso tem HTML: `<form action="https://banco.com/transferir" method="POST">`
4. Seu browser envia os cookies do banco automaticamente
5. O banco recebe o request como se fosse você

**A solução:** cada formulário recebe um token secreto que o site
malicioso não consegue obter. O servidor verifica o token antes
de processar.

**As 3 estratégias:**

| Estratégia | Como funciona | Quando usar |
|---|---|---|
| `synchronizer-token` | Token guardado no servidor, validado por sessão | SSR (EJS, Pug, Django) |
| `double-submit-cookie` | Token no cookie + token no header, comparados | SPAs sem backend stateful |
| `signed-double-submit` | Double submit + assinatura HMAC | **Recomendado** — protege contra cookie injection |

```typescript
import { createSPACSRF } from './csrfProtection';

// Para React/Vue/Angular que chamam APIs:
const csrf = createSPACSRF(
  process.env.CSRF_SECRET!,
  ['https://meuapp.com', 'https://staging.meuapp.com'],
);

// No React, você obtém o token assim:
// 1. O cookie __Host-csrf é definido pelo servidor em GET requests
// 2. Você lê o cookie no JavaScript
// 3. Envia no header de cada request mutante (POST/PUT/DELETE):

// fetch('/api/dados', {
//   method: 'POST',
//   headers: { 'x-csrf-token': lerCookieCSRF() },
//   body: JSON.stringify(dados),
// });
```

---

### `requestIntegrity.ts`

**O problema que resolve:** Garante que o request chegou exatamente
como foi enviado, sem adulteração em trânsito, e que não é um
replay (mesmo request enviado duas vezes).

**Camadas de verificação:**

1. **Assinatura HMAC** — o cliente assina o body com um segredo compartilhado.
   Se o body foi alterado no caminho, a assinatura não bate.

2. **Timestamp + Nonce** — previne replay attacks. Se um request
   interceptado for reenviado 10 minutos depois, o timestamp estará
   fora da janela de 5 minutos e será rejeitado.

3. **Prototype Pollution** — detecta payloads JSON com chaves
   `__proto__`, `constructor`, `prototype` que podem corromper objetos JavaScript.

4. **Idempotency Key** — para pagamentos e operações financeiras.
   Se o cliente enviar o mesmo request duas vezes por falha de rede,
   o servidor processa apenas uma vez.

```typescript
import { createPaymentIntegrity, createWebhookIntegrity } from './requestIntegrity';

// Para endpoint de pagamento — máxima segurança:
const paymentIntegrity = createPaymentIntegrity(
  process.env.REQUEST_SECRET!,
  idempotencyStore,
  nonceStore,
);
// Exige: assinatura + timestamp + nonce + Idempotency-Key header

// Para receber webhooks do Stripe/GitHub:
const webhookIntegrity = createWebhookIntegrity(
  process.env.WEBHOOK_SECRET!,
);
// Exige: header x-signature-sha256: sha256=<valor>
// Compatível com o formato do GitHub e Stripe
```

---

## 7. Políticas de rede

### `cors.ts`

**O problema que resolve:** Por padrão, o browser bloqueia JavaScript
de `app.exemplo.com` de fazer requests para `api.exemplo.com`.
O CORS é o mecanismo que diz ao browser quais origens externas
são permitidas.

**A misconfiguration mais comum:** aceitar qualquer origem com
`Access-Control-Allow-Origin: *` e também enviar cookies.
Isso não funciona (o browser rejeita) e quase sempre indica
um bug de segurança.

```typescript
import { createPrivateAPICORS, createPublicAPICORS } from './cors';

// API privada (com autenticação):
const cors = createPrivateAPICORS([
  'https://app.meusite.com',
  'https://admin.meusite.com',
]);
// credentials: true, origens explícitas, headers de auth permitidos

// API pública (sem autenticação, dados abertos):
const corsPublico = createPublicAPICORS();
// Access-Control-Allow-Origin: * (mas sem cookies)
// Apenas GET e HEAD

// Desenvolvimento local:
const corsDev = createDevCORS();
// Aceita localhost:3000, 5173, 4200, etc.
// LANÇA ERRO se usado em NODE_ENV=production
```

---

### `geoBlock.ts`

**O problema que resolve:** Bloquear acesso de países específicos
por compliance (OFAC — sanções dos EUA), por localização do produto
(serviço só para o Brasil), ou por origem conhecida de ataques.

**Como o país é detectado (em ordem de confiança):**

```
1. CF-IPCountry (header do Cloudflare) — 90% de confiança
2. CloudFront-Viewer-Country — 85%
3. Fastly e Akamai headers — 80-85%
4. Nginx GeoIP module — 70%
5. Headers customizados (HAProxy) — 40-50%
6. Lookup externo (MaxMind, ipinfo.io) — depende
```

```typescript
import { createSingleCountryGeo, createOFACGeo, createHighSecurityGeo } from './geoBlock';

// Produto 100% brasileiro:
const geo = createSingleCountryGeo('BR', meuMaxMindLookup);

// Compliance financeiro (OFAC):
// Bloqueia Cuba, Irã, Coreia do Norte, Síria, Rússia, Belarus e outros
const geoOfac = createOFACGeo(meuLookup);

// Pagamentos — apenas BR e PT, sem VPN, sem Tor:
const geoSeguro = createHighSecurityGeo(['BR', 'PT'], meuLookup);

// Integração com lookup externo (ipinfo.io):
const geoComLookup = new GeoBlockMiddleware({
  mode:             'allowlist',
  allowedCountries: ['BR', 'PT', 'US'],
  blockTor:         true,
  externalLookup:   async (ip) => {
    const resp = await fetch(`https://ipinfo.io/${ip}/json?token=${TOKEN}`);
    const data = await resp.json();
    return {
      country:    data.country,
      confidence: 80,
      isTor:      data.privacy?.tor,
      isVPN:      data.privacy?.vpn,
    };
  },
});
```

---

### `botProtection.ts`

**O problema que resolve:** Bots automatizados representam mais de
40% do tráfego da internet. Alguns são legítimos (Google, Bing),
mas muitos são maliciosos (scrapers, credential stuffers, form spammers).

**Como detecta bots:**

```
1. User-Agent — lista de 60+ padrões de bots conhecidos
   (curl, python-requests, selenium, headless chrome, etc.)

2. Headless browser — browsers "invisíveis" usados para automação
   têm diferenças sutis nos headers que browsers reais enviam:
   - Ausência de sec-fetch-site
   - Ausência de sec-ch-ua em Chrome moderno
   - Accept: */* (cliente Python) vs Accept real de browser

3. Header anomalies — browsers reais sempre enviam
   Accept-Language, Accept-Encoding, etc.
   Requests programáticos frequentemente omitem.

4. Honeypot routes — rotas como /.env, /wp-admin, /phpinfo.php
   Nenhum usuário real acessa. Se alguém acessar, é scanner.

5. Honeypot form fields — campos invisíveis no formulário.
   Usuários reais não preenchem campos que não aparecem na tela.
   Bots que preenchem tudo são detectados.
```

---

### `portRestrictions.ts`

**O problema que resolve:** Serviços internos rodam em portas específicas
(Redis na 6379, MongoDB na 27017, Node.js debug na 9229). Se alguém
conseguir fazer seu servidor fazer requests para essas portas,
pode controlar serviços internos (ataque SSRF).

**Duas proteções principais:**

**1. Bloqueio de portas perigosas:**
```
Porta 22   (SSH)    → bloqueada
Porta 6379 (Redis)  → bloqueada
Porta 9229 (Node debug) → bloqueada em PRODUÇÃO
Porta 27017 (MongoDB) → bloqueada
```

**2. SSRF via parâmetros:**
```
GET /api/fetch?url=http://redis:6379/FLUSHALL

Se url=http://redis:6379/ → porta 6379 → bloqueado!
```

```typescript
import { createProductionPortRestrictions, createURLPortValidator } from './portRestrictions';

// Middleware para produção (só 80 e 443, sem debug ports):
const pr = createProductionPortRestrictions({ forceHTTPS: true });

// Validador standalone para endpoints que recebem URLs:
const isURLSafe = createURLPortValidator();

app.post('/api/webhook/configure', (req, res) => {
  const webhookURL = req.body.url;

  // Verifica se a URL não tem porta maliciosa antes de salvar:
  if (!isURLSafe(webhookURL)) {
    return res.status(400).json({ error: 'URL com porta não permitida' });
  }

  // Salva e usa a URL...
});
```

---

## 8. Orquestrador central

### `securityMiddleware.ts`

**O problema que resolve:** Sem este arquivo, você precisaria importar
e configurar cada middleware separadamente em cada rota. Com ele,
você configura uma vez e aplica em tudo.

**É o único arquivo que você precisa importar na maioria dos casos.**

```typescript
import {
  createSecurityPipeline,
  createExpressSecurityPipeline,
  createMemorySharedStore,
} from './securityMiddleware';

// ── Setup mínimo (desenvolvimento) ────────────────────────────
const security = createSecurityPipeline({
  store: createMemorySharedStore(),
});

app.use(createExpressSecurityPipeline(security));

// ── Setup completo (produção) ──────────────────────────────────
const security = createSecurityPipeline({
  store: createRedisSharedStore(redisClient),  // sua impl Redis

  // Habilita fases opcionais:
  phases: {
    geo:  true,   // bloqueio geográfico
    csrf: true,   // proteção CSRF
    cors: true,   // política CORS
  },

  // Configurações de cada fase:
  geo:  { mode: 'allowlist', allowedCountries: ['BR', 'PT'] },
  csrf: { strategy: 'signed-double-submit', secret: process.env.CSRF_SECRET! },
  cors: { allowedOrigins: ['https://app.meusite.com'] },

  // Observabilidade:
  onViolation: (event) => {
    logger.warn('security-violation', event);
    if (event.penaltyScore >= 40) {
      alertas.enviar(`IP suspeito: ${event.ip} — ${event.reason}`);
    }
  },

  onRequest: (result) => {
    metrics.histogram('security.latency', result.totalLatencyMs);
    metrics.increment(`security.${result.blockedBy ?? 'allowed'}`);
  },
});

// ── Registra o resultado dos handlers para o circuit breaker ──
app.use((req, res, next) => {
  res.on('finish', () => {
    security.recordHandlerResult(req.path, res.statusCode);
  });
  next();
});

// ── Em handlers, reporte violações de negócio ─────────────────
app.post('/api/auth/login', async (req, res) => {
  const ok = await autenticar(req.body);
  if (!ok) {
    await security.reportViolation(req.ip, 'AUTH_BRUTEFORCE');
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }
});
```

**O `securityMiddleware.ts` faz automaticamente:**
- Integra todos os módulos acima numa pipeline ordenada
- Propaga CORS headers para respostas de erro (sem isso, o browser
  reporta erro de CORS em vez do erro real)
- Penaliza o score de IP a cada violação de qualquer módulo
- Chama `onViolation` para cada bloqueio (seu SIEM/log centralizado)

---

## 9. Como adicionar uma nova regra

**Cenário:** você quer bloquear um IP específico que está fazendo scraping.

```typescript
// Opção 1 — Ban via API do módulo (runtime, sem restart):
await ipBlocklist.ban(
  '198.51.100.99',
  'scraper',
  'Fez 50.000 requests em 10 minutos',
  'joao@empresa.com',
);

// Opção 2 — Via pipeline central:
await security.banIP('198.51.100.99');

// Opção 3 — Via reportViolation (para análise):
await security.reportViolation('198.51.100.99', 'SCRAPING_DETECTED', 60);
// Score sobe 60 pontos → provavelmente bane automaticamente (threshold 90)
```

**Cenário:** você quer adicionar um endpoint novo com limite específico.

```typescript
// No rateLimit.ts, adicione ao routeRules:
'/api/export/relatorio': [
  {
    limit:    1,         // 1 export por vez
    windowMs: 300_000,  // por 5 minutos
    algorithm: 'concurrent', // 1 concurrent = não pode fazer 2 ao mesmo tempo
    dimension:  'user',
  },
],
```

---

## 10. Erros comuns de júnior

### ❌ Usar `as any` para contornar erros de tipo

```typescript
// ERRADO — silencia o erro mas não resolve o problema:
crypto.subtle.sign('HMAC', key, data as any);

// CORRETO — garante ArrayBuffer real:
const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
crypto.subtle.sign('HMAC', key, buf);
```

### ❌ Usar `MemoryStore` em produção

```typescript
// ❌ ERRADO para produção — perde dados ao reiniciar, não compartilha entre instâncias:
const store = new MemoryRateLimitStore();

// ✅ CORRETO para produção:
const store = createRedisStore(redisClient); // implemente usando ioredis
```

### ❌ Esquecer de registrar violações de negócio

```typescript
// ❌ ERRADO — o ipFilter não sabe que houve uma tentativa de fraude:
app.post('/api/comprar', async (req, res) => {
  const result = await processarPagamento(req.body);
  if (result.fraude) {
    return res.status(400).json({ error: 'Pagamento recusado' });
  }
});

// ✅ CORRETO — alimenta o score de reputação:
app.post('/api/comprar', async (req, res) => {
  const result = await processarPagamento(req.body);
  if (result.fraude) {
    await security.reportViolation(req.ip!, 'PAYMENT_FRAUD', 55);
    return res.status(400).json({ error: 'Pagamento recusado' });
  }
});
```

### ❌ Não chamar `recordHandlerResult`

```typescript
// ❌ ERRADO — o circuit breaker do DDoS nunca aprende os erros:
app.use(createExpressSecurityPipeline(security));

// ✅ CORRETO:
app.use(createExpressSecurityPipeline(security));
app.use((req, res, next) => {
  res.on('finish', () => {
    security.recordHandlerResult(req.path, res.statusCode);
  });
  next();
});
```

### ❌ Usar `dry-run` em produção e esquecer

```typescript
// ❌ CUIDADO — dry-run NÃO bloqueia nada, só loga:
const blocklist = new IPBlocklist({ mode: 'dry-run' });
// Se você esquecer de trocar para 'active', nenhum IP é bloqueado!

// ✅ Use variável de ambiente para controlar:
const blocklist = new IPBlocklist({
  mode: process.env.BLOCKLIST_DRY_RUN === 'true' ? 'dry-run' : 'active',
});
```

### ❌ Confundir sanitização com escape

```typescript
// sanitizeHtml() → remove tags perigosas, mantém HTML seguro
// Use quando: HTML precisa ser renderizado como HTML

// escapeHtml() → converte TUDO em texto literal
// Use quando: o conteúdo é TEXTO e não deve ser interpretado como HTML

// ❌ Usar escapeHtml em HTML que precisa ser renderizado:
element.innerHTML = escapeHtml(htmlDoEditor);
// Resultado: o usuário vê "&lt;b&gt;negrito&lt;/b&gt;" ao invés de texto em negrito

// ✅ Correto:
element.innerHTML = sanitizeHtml(htmlDoEditor, 'richText');
```

---

## Referências rápidas

| Você quer... | Use este módulo |
|---|---|
| Proteger um endpoint de admin | `ipAllowlist.ts` (modo strict) |
| Bloquear um IP ruim manualmente | `ipBlocklist.ts` → `ban()` |
| Limitar requests por usuário | `rateLimit.ts` (dimensão 'user') |
| Proteger um formulário de CSRF | `csrfProtection.ts` |
| Mostrar HTML do usuário com segurança | `html-sanitizer.ts` → `sanitizeHtml()` |
| Validar URL em parâmetro (anti-SSRF) | `portRestrictions.ts` → `createURLPortValidator()` |
| Bloquear acesso de fora do Brasil | `geoBlock.ts` → `createSingleCountryGeo('BR')` |
| Receber webhooks do Stripe/GitHub | `requestIntegrity.ts` → `createWebhookIntegrity()` |
| Tudo de uma vez, simples | `securityMiddleware.ts` → `createSecurityPipeline()` |