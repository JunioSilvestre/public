/**
 * @arquivo    constants/regex.ts
 * @modulo     Utilitários / Constantes
 * @descricao  Repositório centralizado de todas as expressões regulares (RegExp)
 *             utilizadas na aplicação. Agrupa padrões de validação, extração e
 *             substituição de texto para e-mails, documentos (CPF, CNPJ),
 *             telefones, senhas, URLs, CEPs e outros formatos comuns.
 *             Evita a redefinição de regex idênticos em múltiplos arquivos
 *             e facilita a manutenção e os testes unitários dos padrões.
 *
 * @exemplos_de_uso
 *   - Validação de e-mail:        /^[^\s@]+@[^\s@]+\.[^\s@]+$/
 *   - Validação de CPF (somente dígitos): /^\d{11}$/
 *   - Validação de CNPJ (somente dígitos): /^\d{14}$/
 *   - Validação de telefone brasileiro: /^\d{10,11}$/
 *   - Validação de CEP: /^\d{5}-?\d{3}$/
 *   - Validação de URL: /^https?:\/\/.+/
 *   - Senha com requisitos mínimos (maiúscula, número, especial): combinação de grupos
 *   - Remoção de caracteres não numéricos: /\D/g
 *   - Detecção de tags HTML maliciosas: /<[^>]*>/g
 *
 * @responsabilidade
 *   Ser a fonte única de verdade para todos os padrões de expressão regular
 *   da aplicação, promovendo reuso e prevenindo divergências entre camadas.
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
