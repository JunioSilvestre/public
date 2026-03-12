# =============================================================================
# setup-fintech-public.ps1
#
# ESCOPO: Site publico de apresentacao - mercado financeiro
# - Elegancia visual, responsividade, animacoes
# - 3 idiomas (en / pt / es)
# - Seguranca reforcada (CSP, sanitizacao, rate-limit, anti-bot)
# - Componentes do DS e shared serao reaproveitados pelo sistema privado
# - Arquitetura MFE: cada dominio completamente auto-contido
# - Header tem AuthCtaBtn RESERVADO - sera ativado na fase 2 (auth)
# - SEM tenant (nao se aplica a esta fase)
#
# O QUE E a11y?
# a11y = Accessibility (acessibilidade). Garante que o site funcione para TODOS,
# incluindo pessoas com deficiencia visual, motora ou cognitiva.
# Obrigatorio por lei em mercados financeiros regulados:
#   - ADA (EUA): processos por inacessibilidade sao frequentes no setor financeiro
#   - LBI (Brasil): Lei Brasileira de Inclusao exige acessibilidade digital
# Na pratica resolve: navegacao por teclado, leitores de tela (NVDA, VoiceOver),
# contraste minimo de cores (WCAG 4.5:1), animacoes seguras (epilepsia).
# =============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Dir  { param($p) New-Item -ItemType Directory -Force -Path $p,  Out-Null }
function New-File { param($p) New-Item -ItemType File     -Force -Path $p,  Out-Null }

Write-Host "`n  Fintech Public Site - Setup" -ForegroundColor Cyan
Write-Host "  Visual-first,  3 Languages,  Financial Grade Security`n" -ForegroundColor DarkGray

# =============================================================================
# CONFIG - raiz do projeto
# =============================================================================

New-File "tsconfig.json"
New-File "tsconfig.paths.json"
New-File "vite.config.ts"
New-File "tailwind.config.ts"
New-File "postcss.config.ts"
New-File "package.json"
New-File ".env"
New-File ".env.production"
New-File ".env.staging"
New-File ".eslintrc.cjs"
New-File ".prettierrc"
New-File "jest.config.ts"
New-File "playwright.config.ts"
New-File ".gitignore"

# =============================================================================
# PUBLIC/ - arquivos estaticos servidos diretamente pelo servidor
# =============================================================================

New-Dir  "public"
New-File "public/robots.txt"
New-File "public/sitemap.xml"
New-File "public/manifest.json"
New-File "public/security.txt"              # contato de seguranca (RFC 9116)
New-File "public/_headers"                  # Content-Security-Policy, HSTS etc
New-Dir  "public/fonts"                     # fontes self-hosted (performance + privacidade)
New-Dir  "public/icons"                     # favicon, apple-touch-icon, PWA icons
New-Dir  "public/og"                        # imagens Open Graph por pagina

# =============================================================================
# SRC - entry points
# =============================================================================

New-File "src/main.tsx"
New-File "src/App.tsx"
New-File "src/vite-env.d.ts"

# =============================================================================
#  MFE: HEADER
#  Logo,  Nav,  Mega menu,  Mobile nav,  Ticker de cotacoes,  [Auth btn reservado]
# =============================================================================

New-Dir  "src/header"
New-File "src/header/index.tsx"
New-File "src/header/Header.tsx"
New-File "src/header/header.types.ts"
New-File "src/header/header.tokens.ts"
New-File "src/header/header.config.ts"

New-Dir  "src/header/components"
New-File "src/header/components/Logo.tsx"
New-File "src/header/components/NavBar.tsx"
New-File "src/header/components/NavItem.tsx"
New-File "src/header/components/MegaMenu.tsx"
New-File "src/header/components/MobileNav.tsx"
New-File "src/header/components/MobileNavToggle.tsx"
New-File "src/header/components/MarketTickerBar.tsx"    # cotacoes demo para visitante
New-File "src/header/components/LanguageSwitcher.tsx"   # en / pt / es
New-File "src/header/components/ThemeToggle.tsx"        # light / dark
New-File "src/header/components/AuthCtaBtn.tsx"         # RESERVADO - ativado na fase 2

New-Dir  "src/header/hooks"
New-File "src/header/hooks/useScrollBehavior.ts"        # sticky, hide-on-scroll
New-File "src/header/hooks/useMobileNav.ts"             # open/close, lock body scroll
New-File "src/header/hooks/useActiveRoute.ts"           # highlight item atual
New-File "src/header/hooks/useLiveTicker.ts"            # dados de mercado para ticker

New-Dir  "src/header/variants"
New-File "src/header/variants/Transparent.tsx"          # sobre o hero (homepage)
New-File "src/header/variants/Sticky.tsx"               # apos scroll
New-File "src/header/variants/Minimal.tsx"              # paginas internas

New-Dir  "src/header/assets"
New-File "src/header/assets/logo.svg"
New-File "src/header/assets/logo-dark.svg"
New-File "src/header/assets/logo-white.svg"

New-Dir  "src/header/data"
New-File "src/header/data/nav-links.json"
New-File "src/header/data/mega-menu.json"
New-File "src/header/data/ticker-symbols.json"

New-Dir  "src/header/__tests__"
New-File "src/header/__tests__/Header.test.tsx"
New-File "src/header/__tests__/MobileNav.test.tsx"
New-File "src/header/__tests__/MarketTickerBar.test.tsx"

# =============================================================================
#  MFE: HERO
#  Primeira impressao - animacoes de entrada, stats ao vivo, chart demo
# =============================================================================

New-Dir  "src/hero"
New-File "src/hero/index.tsx"
New-File "src/hero/Hero.tsx"
New-File "src/hero/hero.types.ts"
New-File "src/hero/hero.tokens.ts"          # gradientes, glassmorphism, glow

New-Dir  "src/hero/components"
New-File "src/hero/components/HeroHeadline.tsx"         # texto animado
New-File "src/hero/components/HeroKicker.tsx"           # tag acima do titulo
New-File "src/hero/components/HeroSubtitle.tsx"
New-File "src/hero/components/HeroCta.tsx"
New-File "src/hero/components/HeroTrustBar.tsx"         # logos de parceiros
New-File "src/hero/components/HeroStatCard.tsx"         # numero animado
New-File "src/hero/components/HeroChartPreview.tsx"     # grafico demo interativo
New-File "src/hero/components/HeroBackground.tsx"       # gradient mesh animado
New-File "src/hero/components/HeroVideoBackground.tsx"  # video em loop
New-File "src/hero/components/HeroGlowOrbs.tsx"         # efeito de luz
New-File "src/hero/components/HeroScrollCue.tsx"        # indicador de scroll

New-Dir  "src/hero/hooks"
New-File "src/hero/hooks/useCountUp.ts"                 # animacao 0 → valor
New-File "src/hero/hooks/useParallax.ts"
New-File "src/hero/hooks/useLiveStats.ts"               # stats ao vivo
New-File "src/hero/hooks/useHeroEntrance.ts"            # sequencia de entrada

New-Dir  "src/hero/variants"
New-File "src/hero/variants/Centered.tsx"
New-File "src/hero/variants/SplitWithChart.tsx"
New-File "src/hero/variants/VideoFull.tsx"
New-File "src/hero/variants/GradientMesh.tsx"

New-Dir  "src/hero/animations"
New-File "src/hero/animations/entrance.ts"
New-File "src/hero/animations/textReveal.ts"
New-File "src/hero/animations/numberCount.ts"
New-File "src/hero/animations/glowPulse.ts"

New-Dir  "src/hero/assets"
New-File "src/hero/assets/hero-chart-preview.svg"
New-File "src/hero/assets/hero-device-mockup.png"
New-File "src/hero/assets/hero-bg-video.mp4"

New-Dir  "src/hero/data"
New-File "src/hero/data/stats.json"
New-File "src/hero/data/trust-logos.json"

New-Dir  "src/hero/__tests__"
New-File "src/hero/__tests__/Hero.test.tsx"
New-File "src/hero/__tests__/useCountUp.test.ts"

# =============================================================================
#  MFE: MARKETS
#  Preview de cotacoes ao vivo para visitante - demonstracao do produto
#  WebSocket com dados publicos. Badge "veja mais apos cadastro"
# =============================================================================

New-Dir  "src/markets"
New-File "src/markets/index.tsx"
New-File "src/markets/Markets.tsx"
New-File "src/markets/markets.types.ts"
New-File "src/markets/markets.tokens.ts"                # verde/vermelho financeiro

New-Dir  "src/markets/components"
New-File "src/markets/components/MarketOverview.tsx"
New-File "src/markets/components/IndexCard.tsx"         # S&P, Nasdaq, IBOV...
New-File "src/markets/components/MiniSparkline.tsx"
New-File "src/markets/components/PriceChange.tsx"       # +2.3% com cor e seta
New-File "src/markets/components/MarketStatusBadge.tsx" # OPEN / CLOSED / PRE-MARKET
New-File "src/markets/components/AssetRow.tsx"
New-File "src/markets/components/TopMovers.tsx"
New-File "src/markets/components/HeatMap.tsx"
New-File "src/markets/components/CurrencyPair.tsx"
New-File "src/markets/components/DemoWatermark.tsx"     # CTA para cadastro

New-Dir  "src/markets/hooks"
New-File "src/markets/hooks/useMarketData.ts"
New-File "src/markets/hooks/useLivePrices.ts"
New-File "src/markets/hooks/useWebSocket.ts"
New-File "src/markets/hooks/useMarketStatus.ts"

New-Dir  "src/markets/services"
New-File "src/markets/services/market-api.ts"
New-File "src/markets/services/websocket-client.ts"
New-File "src/markets/services/price-formatter.ts"

New-Dir  "src/markets/variants"
New-File "src/markets/variants/TickerScroll.tsx"        # faixa em loop
New-File "src/markets/variants/GridCards.tsx"
New-File "src/markets/variants/CompactTable.tsx"        # estilo Bloomberg

New-Dir  "src/markets/data"
New-File "src/markets/data/demo-fallback.json"          # dados estaticos se WS falhar
New-File "src/markets/data/asset-classes.json"

New-Dir  "src/markets/__tests__"
New-File "src/markets/__tests__/PriceChange.test.tsx"
New-File "src/markets/__tests__/useWebSocket.test.ts"

# =============================================================================
#  MFE: CHARTS
#  Graficos financeiros interativos - demonstracao para visitante
# =============================================================================

New-Dir  "src/charts"
New-File "src/charts/index.tsx"
New-File "src/charts/charts.types.ts"
New-File "src/charts/charts.tokens.ts"
New-File "src/charts/charts.config.ts"

New-Dir  "src/charts/components"
New-File "src/charts/components/CandlestickChart.tsx"
New-File "src/charts/components/AreaChart.tsx"
New-File "src/charts/components/LineChart.tsx"
New-File "src/charts/components/BarChart.tsx"
New-File "src/charts/components/TreemapChart.tsx"       # heatmap de portfolio
New-File "src/charts/components/SparklineChart.tsx"
New-File "src/charts/components/GaugeChart.tsx"         # indicador de score/risco
New-File "src/charts/components/ChartTooltip.tsx"
New-File "src/charts/components/ChartLegend.tsx"
New-File "src/charts/components/TimeframeSelector.tsx"  # 1D 1W 1M 3M 1Y ALL
New-File "src/charts/components/ChartSkeleton.tsx"
New-File "src/charts/components/ChartError.tsx"

New-Dir  "src/charts/hooks"
New-File "src/charts/hooks/useChartData.ts"
New-File "src/charts/hooks/useChartTheme.ts"            # light/dark tokens
New-File "src/charts/hooks/useTimeframe.ts"
New-File "src/charts/hooks/useZoom.ts"

New-Dir  "src/charts/utils"
New-File "src/charts/utils/formatters.ts"               # K, M, B
New-File "src/charts/utils/color-coding.ts"             # verde/vermelho por variacao
New-File "src/charts/utils/ohlc-transform.ts"

New-Dir  "src/charts/adapters"
New-File "src/charts/adapters/recharts.ts"
New-File "src/charts/adapters/tradingview.ts"

New-Dir  "src/charts/__tests__"
New-File "src/charts/__tests__/CandlestickChart.test.tsx"
New-File "src/charts/__tests__/formatters.test.ts"

# =============================================================================
#  MFE: SOLUTIONS
#  Apresentacao do produto - o que o usuario tera apos login
# =============================================================================

New-Dir  "src/solutions"
New-File "src/solutions/index.tsx"
New-File "src/solutions/Solutions.tsx"
New-File "src/solutions/solutions.types.ts"
New-File "src/solutions/solutions.tokens.ts"

New-Dir  "src/solutions/components"
New-File "src/solutions/components/SolutionCard.tsx"
New-File "src/solutions/components/SolutionIcon.tsx"
New-File "src/solutions/components/SolutionTabs.tsx"
New-File "src/solutions/components/SolutionMediaPanel.tsx"
New-File "src/solutions/components/FeatureList.tsx"
New-File "src/solutions/components/MetricCallout.tsx"
New-File "src/solutions/components/ComparisonTable.tsx"
New-File "src/solutions/components/IntegrationBadge.tsx"

New-Dir  "src/solutions/hooks"
New-File "src/solutions/hooks/useSolutionTabs.ts"
New-File "src/solutions/hooks/useAnimateOnView.ts"      # IntersectionObserver

New-Dir  "src/solutions/variants"
New-File "src/solutions/variants/Grid3Col.tsx"
New-File "src/solutions/variants/AlternatingMedia.tsx"
New-File "src/solutions/variants/TabsWithPreview.tsx"

New-Dir  "src/solutions/assets/icons"
New-Dir  "src/solutions/assets/screenshots"
New-Dir  "src/solutions/assets/illustrations"

New-Dir  "src/solutions/data"
New-File "src/solutions/data/solutions.json"
New-File "src/solutions/data/integrations.json"

New-Dir  "src/solutions/__tests__"
New-File "src/solutions/__tests__/SolutionTabs.test.tsx"

# =============================================================================
#  MFE: PRICING
# =============================================================================

New-Dir  "src/pricing"
New-File "src/pricing/index.tsx"
New-File "src/pricing/Pricing.tsx"
New-File "src/pricing/pricing.types.ts"
New-File "src/pricing/pricing.tokens.ts"

New-Dir  "src/pricing/components"
New-File "src/pricing/components/PricingCard.tsx"
New-File "src/pricing/components/PricingToggle.tsx"
New-File "src/pricing/components/PricingBadge.tsx"
New-File "src/pricing/components/PricingFeatureRow.tsx"
New-File "src/pricing/components/PricingCta.tsx"
New-File "src/pricing/components/PricingFaq.tsx"
New-File "src/pricing/components/PricingComparisonTable.tsx"
New-File "src/pricing/components/EnterpriseBanner.tsx"
New-File "src/pricing/components/SavingsBadge.tsx"

New-Dir  "src/pricing/hooks"
New-File "src/pricing/hooks/usePricingToggle.ts"
New-File "src/pricing/hooks/usePricingCalculator.ts"    # ROI calculator

New-Dir  "src/pricing/variants"
New-File "src/pricing/variants/Cards.tsx"
New-File "src/pricing/variants/FullComparisonTable.tsx"
New-File "src/pricing/variants/Minimal.tsx"

New-Dir  "src/pricing/data"
New-File "src/pricing/data/plans.json"
New-File "src/pricing/data/features-matrix.json"
New-File "src/pricing/data/faq.json"

New-Dir  "src/pricing/__tests__"
New-File "src/pricing/__tests__/PricingToggle.test.tsx"
New-File "src/pricing/__tests__/PricingCard.test.tsx"

# =============================================================================
#  MFE: SOCIAL PROOF
#  Depoimentos, logos, imprensa, premios - alto impacto em produto financeiro
# =============================================================================

New-Dir  "src/social-proof"
New-File "src/social-proof/index.tsx"
New-File "src/social-proof/SocialProof.tsx"
New-File "src/social-proof/social-proof.types.ts"

New-Dir  "src/social-proof/components"
New-File "src/social-proof/components/TestimonialCard.tsx"
New-File "src/social-proof/components/TestimonialCarousel.tsx"
New-File "src/social-proof/components/StarRating.tsx"
New-File "src/social-proof/components/ClientLogoBar.tsx"    # scroll infinito
New-File "src/social-proof/components/AwardBadge.tsx"
New-File "src/social-proof/components/PressCard.tsx"
New-File "src/social-proof/components/MetricHighlight.tsx"  # "R$ 2bi sob gestao"
New-File "src/social-proof/components/TrustScore.tsx"

New-Dir  "src/social-proof/hooks"
New-File "src/social-proof/hooks/useInfiniteScroll.ts"
New-File "src/social-proof/hooks/useCarousel.ts"

New-Dir  "src/social-proof/variants"
New-File "src/social-proof/variants/Masonry.tsx"
New-File "src/social-proof/variants/Carousel.tsx"
New-File "src/social-proof/variants/LogosOnly.tsx"

New-Dir  "src/social-proof/assets/avatars"
New-Dir  "src/social-proof/assets/logos"
New-Dir  "src/social-proof/assets/press"

New-Dir  "src/social-proof/data"
New-File "src/social-proof/data/testimonials.json"
New-File "src/social-proof/data/clients.json"
New-File "src/social-proof/data/press.json"
New-File "src/social-proof/data/awards.json"

New-Dir  "src/social-proof/__tests__"
New-File "src/social-proof/__tests__/TestimonialCarousel.test.tsx"

# =============================================================================
#  MFE: TRUST & SECURITY
#  Selos regulatorios, compliance, certificacoes - MANDATORIO em fintech
# =============================================================================

New-Dir  "src/trust-security"
New-File "src/trust-security/index.tsx"
New-File "src/trust-security/TrustSecurity.tsx"
New-File "src/trust-security/trust.types.ts"

New-Dir  "src/trust-security/components"
New-File "src/trust-security/components/SecurityBadgesRow.tsx"
New-File "src/trust-security/components/ComplianceBanner.tsx"   # "Regulado por..."
New-File "src/trust-security/components/RegulatorySeal.tsx"     # CVM, SEC, FCA, FINRA
New-File "src/trust-security/components/CertificationCard.tsx"  # ISO 27001, SOC 2
New-File "src/trust-security/components/EncryptionBadge.tsx"    # AES-256, TLS 1.3
New-File "src/trust-security/components/UptimeBadge.tsx"        # 99.99% SLA
New-File "src/trust-security/components/RiskDisclosure.tsx"     # texto legal obrigatorio
New-File "src/trust-security/components/InsuranceBadge.tsx"

New-Dir  "src/trust-security/assets/seals"
New-Dir  "src/trust-security/assets/regulators"

New-Dir  "src/trust-security/data"
New-File "src/trust-security/data/certifications.json"
New-File "src/trust-security/data/regulators.json"
New-File "src/trust-security/data/disclosures.json"    # textos legais por jurisdicao

# =============================================================================
#  MFE: CONTACT
# =============================================================================

New-Dir  "src/contact"
New-File "src/contact/index.tsx"
New-File "src/contact/Contact.tsx"
New-File "src/contact/contact.types.ts"

New-Dir  "src/contact/components"
New-File "src/contact/components/ContactForm.tsx"
New-File "src/contact/components/DemoRequestForm.tsx"
New-File "src/contact/components/NewsletterForm.tsx"
New-File "src/contact/components/FormField.tsx"
New-File "src/contact/components/FormSuccess.tsx"
New-File "src/contact/components/FormError.tsx"
New-File "src/contact/components/CalendlyEmbed.tsx"

New-Dir  "src/contact/hooks"
New-File "src/contact/hooks/useContactForm.ts"
New-File "src/contact/hooks/useDemoRequest.ts"
New-File "src/contact/hooks/useNewsletter.ts"

New-Dir  "src/contact/validation"
New-File "src/contact/validation/contact.schema.ts"
New-File "src/contact/validation/demo.schema.ts"
New-File "src/contact/validation/newsletter.schema.ts"

New-Dir  "src/contact/services"
New-File "src/contact/services/submit-contact.ts"
New-File "src/contact/services/submit-demo.ts"
New-File "src/contact/services/subscribe.ts"
New-File "src/contact/services/crm-hubspot.ts"

New-Dir  "src/contact/variants"
New-File "src/contact/variants/WithSidebar.tsx"
New-File "src/contact/variants/DemoFocused.tsx"

New-Dir  "src/contact/__tests__"
New-File "src/contact/__tests__/DemoRequestForm.test.tsx"
New-File "src/contact/__tests__/validation.test.ts"

# =============================================================================
#  MFE: CONVERSION
#  CTAs, exit-intent, cookie consent LGPD/GDPR
# =============================================================================

New-Dir  "src/conversion"
New-File "src/conversion/index.tsx"
New-File "src/conversion/conversion.types.ts"

New-Dir  "src/conversion/components"
New-File "src/conversion/components/PrimaryCta.tsx"
New-File "src/conversion/components/StickyCtaBar.tsx"
New-File "src/conversion/components/FloatingCtaButton.tsx"
New-File "src/conversion/components/ExitIntentModal.tsx"
New-File "src/conversion/components/AnnouncementBar.tsx"
New-File "src/conversion/components/PromoBanner.tsx"
New-File "src/conversion/components/CookieConsent.tsx"     # LGPD/GDPR obrigatorio
New-File "src/conversion/components/DemoCtaBanner.tsx"

New-Dir  "src/conversion/hooks"
New-File "src/conversion/hooks/useExitIntent.ts"
New-File "src/conversion/hooks/usePopupDelay.ts"
New-File "src/conversion/hooks/useStickyVisibility.ts"
New-File "src/conversion/hooks/useCookieConsent.ts"

New-Dir  "src/conversion/__tests__"
New-File "src/conversion/__tests__/CookieConsent.test.tsx"
New-File "src/conversion/__tests__/ExitIntentModal.test.tsx"

# =============================================================================
#  MFE: FOOTER
#  Links, legal, regulatory, selos, disclaimer de risco
# =============================================================================

New-Dir  "src/footer"
New-File "src/footer/index.tsx"
New-File "src/footer/Footer.tsx"
New-File "src/footer/footer.types.ts"
New-File "src/footer/footer.tokens.ts"

New-Dir  "src/footer/components"
New-File "src/footer/components/FooterLogo.tsx"
New-File "src/footer/components/FooterNav.tsx"
New-File "src/footer/components/FooterSocial.tsx"
New-File "src/footer/components/FooterNewsletter.tsx"
New-File "src/footer/components/FooterLegalText.tsx"
New-File "src/footer/components/FooterRegulatorySeals.tsx"
New-File "src/footer/components/FooterRiskDisclaimer.tsx"
New-File "src/footer/components/FooterCertBadges.tsx"
New-File "src/footer/components/FooterCopyright.tsx"

New-Dir  "src/footer/variants"
New-File "src/footer/variants/Full.tsx"
New-File "src/footer/variants/Minimal.tsx"
New-File "src/footer/variants/RegulatoryHeavy.tsx"

New-Dir  "src/footer/assets/badges"

New-Dir  "src/footer/data"
New-File "src/footer/data/nav-columns.json"
New-File "src/footer/data/social-links.json"
New-File "src/footer/data/legal-links.json"
New-File "src/footer/data/regulatory-text.json"

New-Dir  "src/footer/__tests__"
New-File "src/footer/__tests__/Footer.test.tsx"

# =============================================================================
#  DESIGN SYSTEM: /ds
#  Tokens, temas, atoms, molecules - fonte da verdade visual
#  Reaproveitado integralmente pelo sistema privado (pos-login)
# =============================================================================

New-Dir  "src/ds"
New-File "src/ds/index.ts"

New-Dir  "src/ds/tokens"
New-File "src/ds/tokens/colors.ts"
New-File "src/ds/tokens/colors.financial.ts"    # verde ganho, vermelho perda, amarelo neutro
New-File "src/ds/tokens/colors.semantic.ts"     # success, warning, error, info
New-File "src/ds/tokens/typography.ts"
New-File "src/ds/tokens/spacing.ts"
New-File "src/ds/tokens/shadows.ts"             # sm, md, lg, glow
New-File "src/ds/tokens/radii.ts"
New-File "src/ds/tokens/breakpoints.ts"
New-File "src/ds/tokens/zindex.ts"
New-File "src/ds/tokens/motion.ts"              # duracoes e easings
New-File "src/ds/tokens/index.ts"

New-Dir  "src/ds/themes"
New-File "src/ds/themes/light.ts"
New-File "src/ds/themes/dark.ts"
New-File "src/ds/themes/high-contrast.ts"       # WCAG AAA
New-File "src/ds/themes/mui-overrides.ts"
New-File "src/ds/themes/index.ts"

New-Dir  "src/ds/atoms"
New-File "src/ds/atoms/Button.tsx"
New-File "src/ds/atoms/Badge.tsx"
New-File "src/ds/atoms/Tag.tsx"
New-File "src/ds/atoms/Icon.tsx"
New-File "src/ds/atoms/Avatar.tsx"
New-File "src/ds/atoms/Divider.tsx"
New-File "src/ds/atoms/Spinner.tsx"
New-File "src/ds/atoms/Skeleton.tsx"
New-File "src/ds/atoms/Tooltip.tsx"
New-File "src/ds/atoms/Input.tsx"
New-File "src/ds/atoms/index.ts"

New-Dir  "src/ds/molecules"
New-File "src/ds/molecules/SectionHeader.tsx"   # titulo + subtitulo + kicker
New-File "src/ds/molecules/StatCard.tsx"        # numero + label + trend
New-File "src/ds/molecules/PriceTag.tsx"        # valor com cor de variacao
New-File "src/ds/molecules/TrendIndicator.tsx"  # seta + percentual
New-File "src/ds/molecules/Accordion.tsx"
New-File "src/ds/molecules/Modal.tsx"
New-File "src/ds/molecules/Drawer.tsx"
New-File "src/ds/molecules/Tabs.tsx"
New-File "src/ds/molecules/Toast.tsx"
New-File "src/ds/molecules/index.ts"

New-Dir  "src/ds/layouts"
New-File "src/ds/layouts/Container.tsx"
New-File "src/ds/layouts/Section.tsx"
New-File "src/ds/layouts/Grid.tsx"
New-File "src/ds/layouts/Stack.tsx"
New-File "src/ds/layouts/index.ts"

# =============================================================================
#  SHARED: /shared
#  Providers, hooks e utils GENERICOS - sem logica de negocio
#  Reaproveitados pelo site publico E pelo sistema privado
# =============================================================================

New-Dir  "src/shared"

New-Dir  "src/shared/providers"
New-File "src/shared/providers/AppProviders.tsx"
New-File "src/shared/providers/ThemeProvider.tsx"
New-File "src/shared/providers/I18nProvider.tsx"
New-File "src/shared/providers/AnalyticsProvider.tsx"
New-File "src/shared/providers/FeatureFlagProvider.tsx"
New-File "src/shared/providers/SecurityProvider.tsx"
New-File "src/shared/providers/index.ts"

New-Dir  "src/shared/hooks"
New-File "src/shared/hooks/useBreakpoint.ts"
New-File "src/shared/hooks/useScrollPosition.ts"
New-File "src/shared/hooks/useTheme.ts"
New-File "src/shared/hooks/useI18n.ts"
New-File "src/shared/hooks/useFeatureFlag.ts"
New-File "src/shared/hooks/useViewport.ts"
New-File "src/shared/hooks/useReducedMotion.ts"
New-File "src/shared/hooks/useOutsideClick.ts"
New-File "src/shared/hooks/index.ts"

New-Dir  "src/shared/utils"
New-File "src/shared/utils/cn.ts"                   # classnames helper
New-File "src/shared/utils/currency.ts"             # formata moeda por locale
New-File "src/shared/utils/percentage.ts"
New-File "src/shared/utils/date.ts"
New-File "src/shared/utils/number.ts"               # K, M, B formatters
New-File "src/shared/utils/sanitize.ts"             # sanitiza inputs (XSS)
New-File "src/shared/utils/env.ts"
New-File "src/shared/utils/index.ts"

New-Dir  "src/shared/types"
New-File "src/shared/types/common.ts"
New-File "src/shared/types/market.ts"               # Price, Asset, OHLC
New-File "src/shared/types/analytics.ts"
New-File "src/shared/types/index.ts"

# =============================================================================
#  SECURITY: /security
#  Seguranca reforçada no cliente
#  Site financeiro e alvo de phishing, ataques e clonagem visual
# =============================================================================

New-Dir  "src/security"
New-File "src/security/index.ts"

New-Dir  "src/security/headers"
New-File "src/security/headers/csp.ts"          # Content-Security-Policy builder
New-File "src/security/headers/hsts.ts"         # Strict-Transport-Security
New-File "src/security/headers/permissions.ts"  # Permissions-Policy
New-File "src/security/headers/index.ts"

New-Dir  "src/security/sanitize"
New-File "src/security/sanitize/input.ts"       # sanitiza campos de formulario
New-File "src/security/sanitize/html.ts"        # DOMPurify wrapper
New-File "src/security/sanitize/url.ts"         # valida e sanitiza URLs
New-File "src/security/sanitize/index.ts"

New-Dir  "src/security/rate-limit"
New-File "src/security/rate-limit/form-submit.ts"
New-File "src/security/rate-limit/api-calls.ts"
New-File "src/security/rate-limit/index.ts"

New-Dir  "src/security/anti-bot"
New-File "src/security/anti-bot/honeypot.ts"    # campo oculto anti-spam
New-File "src/security/anti-bot/recaptcha.ts"   # reCAPTCHA v3
New-File "src/security/anti-bot/index.ts"

New-Dir  "src/security/__tests__"
New-File "src/security/__tests__/sanitize.test.ts"
New-File "src/security/__tests__/csp.test.ts"

# =============================================================================
#  I18N: /i18n - ingles, portugues, espanhol
# =============================================================================

New-Dir  "src/i18n"
New-File "src/i18n/index.ts"
New-File "src/i18n/config.ts"

New-Dir  "src/i18n/locales"
New-File "src/i18n/locales/en.json"
New-File "src/i18n/locales/pt.json"
New-File "src/i18n/locales/es.json"

New-Dir  "src/i18n/hooks"
New-File "src/i18n/hooks/useTranslation.ts"
New-File "src/i18n/hooks/useLocale.ts"
New-File "src/i18n/hooks/useLocalizedFormat.ts" # data/moeda/numero por locale
New-File "src/i18n/hooks/index.ts"

New-Dir  "src/i18n/__tests__"
New-File "src/i18n/__tests__/useTranslation.test.ts"

# =============================================================================
#  SEO: /seo
# =============================================================================

New-Dir  "src/seo"
New-File "src/seo/index.ts"
New-File "src/seo/seo.config.ts"
New-File "src/seo/seo.types.ts"

New-Dir  "src/seo/metadata"
New-File "src/seo/metadata/defaults.ts"
New-File "src/seo/metadata/home.ts"
New-File "src/seo/metadata/pricing.ts"
New-File "src/seo/metadata/solutions.ts"
New-File "src/seo/metadata/index.ts"

New-Dir  "src/seo/schema"
New-File "src/seo/schema/organization.ts"
New-File "src/seo/schema/financialService.ts"   # schema.org/FinancialService
New-File "src/seo/schema/website.ts"
New-File "src/seo/schema/faq.ts"
New-File "src/seo/schema/breadcrumb.ts"
New-File "src/seo/schema/index.ts"

New-Dir  "src/seo/components"
New-File "src/seo/components/MetaTags.tsx"
New-File "src/seo/components/CanonicalLink.tsx"
New-File "src/seo/components/Breadcrumb.tsx"
New-File "src/seo/components/index.ts"

# =============================================================================
#  ANALYTICS: /analytics - GA4, PostHog, Meta Pixel + consent LGPD/GDPR
# =============================================================================

New-Dir  "src/analytics"
New-File "src/analytics/index.ts"
New-File "src/analytics/analytics.config.ts"
New-File "src/analytics/analytics.types.ts"

New-Dir  "src/analytics/providers"
New-File "src/analytics/providers/google.ts"
New-File "src/analytics/providers/posthog.ts"
New-File "src/analytics/providers/meta-pixel.ts"
New-File "src/analytics/providers/hotjar.ts"
New-File "src/analytics/providers/index.ts"

New-Dir  "src/analytics/events"
New-File "src/analytics/events/page-view.ts"
New-File "src/analytics/events/cta-click.ts"
New-File "src/analytics/events/form-submit.ts"
New-File "src/analytics/events/demo-request.ts"
New-File "src/analytics/events/chart-interaction.ts"
New-File "src/analytics/events/scroll-depth.ts"
New-File "src/analytics/events/index.ts"

New-Dir  "src/analytics/consent"
New-File "src/analytics/consent/consent-manager.ts"
New-File "src/analytics/consent/gdpr.ts"
New-File "src/analytics/consent/lgpd.ts"
New-File "src/analytics/consent/index.ts"

New-Dir  "src/analytics/hooks"
New-File "src/analytics/hooks/usePageView.ts"
New-File "src/analytics/hooks/useTrackEvent.ts"
New-File "src/analytics/hooks/useScrollDepth.ts"
New-File "src/analytics/hooks/index.ts"

# =============================================================================
#  A11Y: /a11y - Acessibilidade WCAG 2.1 AA
#
#  Por que e obrigatorio em fintech:
#  - ADA (EUA): processos frequentes no setor financeiro por inacessibilidade
#  - LBI (Brasil): Lei Brasileira de Inclusao exige acessibilidade digital
#  - Usuarios com deficiencia visual usam NVDA, VoiceOver, JAWS
#  - Navegacao completa por teclado (sem mouse) deve funcionar
#  - Contraste minimo 4.5:1 para texto (WCAG AA)
#  - Animacoes devem respeitar prefers-reduced-motion (epilepsia)
# =============================================================================

New-Dir  "src/a11y"
New-File "src/a11y/index.ts"

New-Dir  "src/a11y/components"
New-File "src/a11y/components/SkipToContent.tsx"    # link que pula para o <main>
New-File "src/a11y/components/FocusTrap.tsx"        # prende foco dentro de modais
New-File "src/a11y/components/VisuallyHidden.tsx"   # visivel para screen reader
New-File "src/a11y/components/LiveRegion.tsx"       # anuncia mudancas dinamicas
New-File "src/a11y/components/index.ts"

New-Dir  "src/a11y/hooks"
New-File "src/a11y/hooks/useFocusTrap.ts"           # gerencia foco em modais
New-File "src/a11y/hooks/useKeyboardNav.ts"         # navegacao por teclado em menus
New-File "src/a11y/hooks/useAnnouncer.ts"           # anuncia acoes para screen readers
New-File "src/a11y/hooks/useReducedMotion.ts"       # desativa animacoes se solicitado
New-File "src/a11y/hooks/index.ts"

New-Dir  "src/a11y/validators"
New-File "src/a11y/validators/contrast.ts"          # checa ratio de contraste WCAG
New-File "src/a11y/validators/aria-audit.ts"
New-File "src/a11y/validators/index.ts"

# =============================================================================
#  PERFORMANCE: /performance
# =============================================================================

New-Dir  "src/performance"
New-File "src/performance/index.ts"

New-Dir  "src/performance/monitoring"
New-File "src/performance/monitoring/web-vitals.ts" # LCP, INP, CLS
New-File "src/performance/monitoring/reporter.ts"
New-File "src/performance/monitoring/index.ts"

New-Dir  "src/performance/images"
New-File "src/performance/images/loader.ts"
New-File "src/performance/images/lazy.ts"
New-File "src/performance/images/index.ts"

New-Dir  "src/performance/hooks"
New-File "src/performance/hooks/useWebVitals.ts"
New-File "src/performance/hooks/useLazyLoad.ts"
New-File "src/performance/hooks/index.ts"

# =============================================================================
#  FLAGS: /flags - Feature flags e A/B testing
# =============================================================================

New-Dir  "src/flags"
New-File "src/flags/index.ts"
New-File "src/flags/flags.ts"
New-File "src/flags/flags.types.ts"

New-Dir  "src/flags/experiments"
New-File "src/flags/experiments/hero-variant.ts"
New-File "src/flags/experiments/pricing-layout.ts"
New-File "src/flags/experiments/cta-copy.ts"
New-File "src/flags/experiments/index.ts"

New-Dir  "src/flags/providers"
New-File "src/flags/providers/launchdarkly.ts"
New-File "src/flags/providers/growthbook.ts"
New-File "src/flags/providers/index.ts"

New-Dir  "src/flags/hooks"
New-File "src/flags/hooks/useFlag.ts"
New-File "src/flags/hooks/useExperiment.ts"
New-File "src/flags/hooks/index.ts"

# =============================================================================
#  FALLBACKS: /fallbacks
# =============================================================================

New-Dir  "src/fallbacks"
New-File "src/fallbacks/index.ts"

New-Dir  "src/fallbacks/components"
New-File "src/fallbacks/components/ErrorBoundary.tsx"
New-File "src/fallbacks/components/ErrorPage.tsx"
New-File "src/fallbacks/components/NotFound.tsx"
New-File "src/fallbacks/components/OfflinePage.tsx"
New-File "src/fallbacks/components/PageLoader.tsx"
New-File "src/fallbacks/components/SkeletonHero.tsx"
New-File "src/fallbacks/components/SkeletonChart.tsx"
New-File "src/fallbacks/components/SkeletonCard.tsx"
New-File "src/fallbacks/components/index.ts"

# =============================================================================
#  PAGES + LAYOUTS + ROUTES - camada fina, so compoe os MFEs
# =============================================================================

New-Dir  "src/pages"
New-File "src/pages/HomePage.tsx"      # hero + markets + solutions + social-proof + pricing
New-File "src/pages/PricingPage.tsx"
New-File "src/pages/SolutionsPage.tsx"
New-File "src/pages/ContactPage.tsx"
New-File "src/pages/LegalPage.tsx"
New-File "src/pages/NotFoundPage.tsx"
New-File "src/pages/index.ts"

New-Dir  "src/layouts"
New-File "src/layouts/PublicLayout.tsx"     # header + main + footer
New-File "src/layouts/CampaignLayout.tsx"   # header minimal, sem footer completo
New-File "src/layouts/MinimalLayout.tsx"    # sem nav
New-File "src/layouts/index.ts"

New-Dir  "src/routes"
New-File "src/routes/public.tsx"
New-File "src/routes/index.tsx"

# =============================================================================
#  E2E TESTS
# =============================================================================

New-Dir  "e2e"
New-File "e2e/home.spec.ts"
New-File "e2e/pricing.spec.ts"
New-File "e2e/contact.spec.ts"
New-File "e2e/a11y.spec.ts"         # audit automatico de acessibilidade
New-File "e2e/performance.spec.ts"  # LCP, CLS thresholds
New-File "e2e/security.spec.ts"     # CSP headers, XSS checks
New-File "e2e/i18n.spec.ts"         # testa en / pt / es

# =============================================================================

Write-Host ""
Write-Host "  Done." -ForegroundColor Green
Write-Host ""
Write-Host "  MFEs (auto-contidos):" -ForegroundColor White
Write-Host "    header          logo, nav, ticker, mobile, [auth btn reservado fase 2]" -ForegroundColor Cyan
Write-Host "    hero            stats animados, chart preview, video, parallax" -ForegroundColor Cyan
Write-Host "    markets         cotacoes ao vivo, websocket, heatmap, demo badge" -ForegroundColor Cyan
Write-Host "    charts          candlestick, area, treemap, sparkline, adapters" -ForegroundColor Cyan
Write-Host "    solutions       tabs, media, metricas, comparativo de produto" -ForegroundColor Cyan
Write-Host "    pricing         planos, toggle, matriz, FAQ, ROI calculator" -ForegroundColor Cyan
Write-Host "    social-proof    depoimentos, logos, imprensa, premios" -ForegroundColor Cyan
Write-Host "    trust-security  selos, compliance, reguladores, disclaimer" -ForegroundColor Cyan
Write-Host "    contact         demo form, newsletter, hubspot, calendly" -ForegroundColor Cyan
Write-Host "    conversion      cta, banners, exit-intent, cookie consent LGPD" -ForegroundColor Cyan
Write-Host "    footer          nav, legal, regulatory, disclaimer, selos" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Infra (reaproveitada pelo sistema privado):" -ForegroundColor White
Write-Host "    ds              tokens, temas, atoms, molecules, layouts" -ForegroundColor DarkGray
Write-Host "    shared          providers, hooks, utils, types genericos" -ForegroundColor DarkGray
Write-Host "    security        CSP, sanitize, rate-limit, anti-bot, honeypot" -ForegroundColor DarkGray
Write-Host "    i18n            en / pt / es - datas e moedas por locale" -ForegroundColor DarkGray
Write-Host "    analytics       GA4, PostHog, Meta Pixel + consent LGPD/GDPR" -ForegroundColor DarkGray
Write-Host "    seo             metadata, schema.org/FinancialService, sitemap" -ForegroundColor DarkGray
Write-Host "    a11y            WCAG AA, teclado, screen reader, contraste" -ForegroundColor DarkGray
Write-Host "    performance     web vitals LCP/INP/CLS, lazy load, imagens" -ForegroundColor DarkGray
Write-Host "    flags           feature flags, A/B experiments" -ForegroundColor DarkGray
Write-Host "    fallbacks       error boundary, 404, offline, skeletons" -ForegroundColor DarkGray
Write-Host ""