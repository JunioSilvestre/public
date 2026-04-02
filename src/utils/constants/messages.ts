/**
 * @arquivo    constants/messages.ts
 * @modulo     Utilitários / Constantes
 * @descricao  Centraliza todas as mensagens exibidas ao usuário (erros de
 *             validação, feedbacks de sucesso, títulos de modal, textos de
 *             toast e mensagens de estado vazio). Garante consistência
 *             linguística em toda a interface e facilita internacionalização
 *             futura (i18n), pois todas as strings estão em um único lugar.
 *
 * @categorias
 *   - MENSAGENS.VALIDACAO.*  : erros retornados nos formulários
 *   - MENSAGENS.SUCESSO.*    : confirmações de ação concluída
 *   - MENSAGENS.ERRO.*       : erros de operação e sistema
 *   - MENSAGENS.VAZIO.*      : textos para estados "sem dados"
 *   - MENSAGENS.CONFIRMACAO.*: perguntas de confirmação (modais)
 *
 * @exemplos_de_uso
 *   - MENSAGENS.VALIDACAO.CAMPO_OBRIGATORIO → "Este campo é obrigatório."
 *   - MENSAGENS.VALIDACAO.EMAIL_INVALIDO    → "Informe um e-mail válido."
 *   - MENSAGENS.VALIDACAO.SENHA_FRACA       → "A senha não atende aos requisitos mínimos."
 *   - MENSAGENS.SUCESSO.SALVO               → "Dados salvos com sucesso!"
 *   - MENSAGENS.SUCESSO.ENVIADO             → "Formulário enviado com sucesso!"
 *   - MENSAGENS.ERRO.GENERICO              → "Ocorreu um erro. Tente novamente."
 *   - MENSAGENS.ERRO.TIMEOUT               → "Tempo limite da requisição excedido."
 *   - MENSAGENS.VAZIO.LISTA                → "Nenhum registro encontrado."
 *   - MENSAGENS.CONFIRMACAO.DELETAR        → "Tem certeza que deseja excluir este item?"
 *
 * @responsabilidade
 *   Ser a fonte única de verdade para todos os textos de feedback da aplicação.
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
