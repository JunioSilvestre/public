/**
 * @arquivo    validation/url.ts
 * @modulo     Utilitários / Validação
 * @descricao  Valida URLs e endereços web verificando protocolo, formato,
 *             segurança e acessibilidade. Utilizada para validar inputs
 *             de usuários que inserem links, webhooks, avatares e outros
 *             recursos externos, prevenindo redirecionamentos maliciosos
 *             e referências a recursos inválidos.
 *
 * @funcionalidades
 *   - validarURL(url):           validação básica de URL bem formada
 *   - validarURLSegura(url):     exige protocolo HTTPS
 *   - validarURLImagem(url):     verifica extensão (.jpg, .png, .gif, .webp, .svg)
 *   - validarURLWebhook(url):    exige HTTPS + domínio público (não localhost)
 *   - extrairDominio(url):       "https://www.exemplo.com/path" → "www.exemplo.com"
 *   - normalizarURL(url):        adiciona "https://" se protocolo ausente
 *   - bloquearURLsInternas(url): retorna false para localhost, 127.x.x.x, etc.
 *
 * @exemplos_de_uso
 *   - validarURL("https://exemplo.com")       → true
 *   - validarURL("ftp://arquivo.com")         → true (FTP é protocolo válido)
 *   - validarURL("javascript:alert(1)")       → false (protocolo bloqueado)
 *   - validarURL("exemplo")                   → false (sem protocolo)
 *   - validarURLSegura("http://inseguro.com") → false (exige HTTPS)
 *   - normalizarURL("exemplo.com")            → "https://exemplo.com"
 *
 * @protocolos_bloqueados
 *   javascript:, data:, vbscript:, file:, ftp: (em modo webhook)
 *
 * @tratamentos_especiais
 *   - URL com espaços → retorna false (deve ser encoded primeiro)
 *   - URL com caracteres Unicode → aceita internacionalização (IDN)
 *   - localhost e IPs internos → bloqueados em modo webhook
 *   - Valor nulo/undefined → retorna false
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
