/**
 * @arquivo    constants/routes.ts
 * @modulo     Utilitários / Constantes
 * @descricao  Centraliza todas as rotas (paths) da aplicação frontend como
 *             constantes tipadas. Evita strings de rota duplicadas e dispersas
 *             pelo código, garantindo consistência na navegação, geração de
 *             links e proteção de rotas. Qualquer alteração de rota precisa
 *             ser feita em um único lugar.
 *
 * @exemplos_de_uso
 *   - ROTAS.HOME              → "/"
 *   - ROTAS.LOGIN             → "/login"
 *   - ROTAS.CADASTRO          → "/cadastro"
 *   - ROTAS.ESQUECI_SENHA     → "/esqueci-senha"
 *   - ROTAS.DASHBOARD         → "/dashboard"
 *   - ROTAS.PERFIL            → "/perfil"
 *   - ROTAS.CONFIGURACOES     → "/configuracoes"
 *   - ROTAS.NAO_ENCONTRADO    → "/404"
 *   - ROTAS.ACESSO_NEGADO     → "/403"
 *
 *   Rotas com parâmetros dinâmicos:
 *   - ROTAS.PRODUTO_DETALHE(id)  → "/produtos/123"
 *   - ROTAS.PEDIDO_DETALHE(id)   → "/pedidos/456"
 *
 * @responsabilidade
 *   Ser a fonte única de verdade para todos os paths de navegação da
 *   aplicação, complementando o arquivo de roteamento (src/router).
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
