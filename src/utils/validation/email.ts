/**
 * @arquivo    validation/email.ts
 * @modulo     Utilitários / Validação
 * @descricao  Valida endereços de e-mail conforme as especificações RFC 5321 e
 *             RFC 5322. Fornece validação de diferentes rigoridades (básica para
 *             feedback imediato ao usuário e estrita para validação final antes
 *             de envio), além de verificações adicionais como domínios descartáveis
 *             e verificação de MX record (quando disponível).
 *
 * @funcionalidades
 *   - validarEmail(email):          validação padrão (RFC 5322 simplificado)
 *   - validarEmailEstrito(email):   validação rigorosa com checagem de TLD
 *   - normalizarEmail(email):       lowercase + remoção de alias Gmail (+tag)
 *   - obterDominio(email):          "usuario@gmail.com" → "gmail.com"
 *   - obterUsuario(email):          "usuario@gmail.com" → "usuario"
 *   - ehEmailDescartavel(email):    verifica se domínio é temporário/descartável
 *
 * @regras_de_validacao
 *   - Deve conter exatamente um "@"
 *   - Parte local (antes do @): 1-64 caracteres
 *   - Domínio (após o @): 1-253 caracteres
 *   - TLD deve ter pelo menos 2 caracteres
 *   - Caracteres permitidos: letras, dígitos, ponto, hífen, sublinhado, +
 *   - Não pode começar ou terminar com ponto na parte local
 *   - Não pode ter dois pontos consecutivos
 *
 * @exemplos_de_uso
 *   - validarEmail("usuario@exemplo.com.br") → true
 *   - validarEmail("invalido@")              → false
 *   - validarEmail("")                       → false
 *   - validarEmail(null)                     → false
 *   - normalizarEmail("Usuario+TAG@Gmail.COM")→ "usuario@gmail.com"
 *
 * @tratamentos_especiais
 *   - Valor nulo ou undefined → retorna false
 *   - String com espaços → retorna false (espaços não são permitidos em e-mails)
 *   - E-mail com subdomínios: "user@mail.company.com.br" → válido
 *   - Emails internacionalizados (IDN) → suportados apenas na validação básica
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
