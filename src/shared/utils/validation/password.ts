/**
 * @arquivo    validation/password.ts
 * @modulo     Utilitários / Validação
 * @descricao  Define as regras de validação e avaliação de força de senhas
 *             aplicadas nos formulários de cadastro, alteração de senha e
 *             redefinição. Retorna erros descritivos para feedback ao usuário
 *             e um score de força (fraca, média, forte, muito forte) para
 *             exibição em indicador visual no formulário.
 *
 * @regras_minimas_obrigatorias
 *   - Comprimento mínimo: 8 caracteres
 *   - Comprimento máximo: 128 caracteres
 *   - Pelo menos 1 letra maiúscula (A-Z)
 *   - Pelo menos 1 letra minúscula (a-z)
 *   - Pelo menos 1 número (0-9)
 *   - Pelo menos 1 caractere especial (!@#$%^&*...)
 *   - Sem espaços em branco
 *
 * @funcionalidades
 *   - validarSenha(senha):          retorna { valido, erros: string[] }
 *   - calcularForcaSenha(senha):    retorna score de 0-100 e nível textual
 *   - verificarSenhasIguais(s1, s2):retorna true se as senhas coincidem
 *   - detectarSenhaComum(senha):    verifica contra lista de senhas populares
 *   - detectarPadraoSequencial(s):  detecta "123456", "abcdef", "qwerty" etc.
 *
 * @niveis_de_forca
 *   - 0-24:  "Muito Fraca" 🔴
 *   - 25-49: "Fraca"       🟠
 *   - 50-74: "Média"       🟡
 *   - 75-89: "Forte"       🟢
 *   - 90-100:"Muito Forte" 🟢✨
 *
 * @exemplos_de_uso
 *   - validarSenha("abc")             → { valido: false, erros: ["Mínimo 8 caracteres", ...] }
 *   - validarSenha("Senha@123")       → { valido: true, erros: [] }
 *   - calcularForcaSenha("senha123")  → { score: 40, nivel: "Fraca" }
 *   - calcularForcaSenha("P@ss!W0rd2026") → { score: 92, nivel: "Muito Forte" }
 *
 * @tratamentos_especiais
 *   - Valor nulo ou undefined → retorna { valido: false, erros: ["Senha obrigatória"] }
 *   - Senha com apenas espaços → reprovada (sem espaços permitidos)
 *   - Senha com caracteres Unicode (emojis) → aceitos se respeitarem o tamanho
 *   - Casing de línguas latinas (letras acentuadas) → contam como letras, não especiais
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
