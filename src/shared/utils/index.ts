/**
 * @arquivo    utils/index.ts
 * @modulo     Utilitários / Ponto de Entrada
 * @descricao  Arquivo barrel (index) que re-exporta todos os utilitários
 *             organizados por categoria. Permite importações limpas e
 *             agnósticas à estrutura interna de pastas, simplificando
 *             os imports em toda a aplicação.
 *
 * @uso
 *   Em vez de:
 *     import { formatarData } from '../../utils/format/date';
 *     import { validarCPF } from '../../utils/validation/document';
 *
 *   Use:
 *     import { formatarData, validarCPF } from '../../utils';
 *
 * @categorias_exportadas
 *   - constants:   format, limits, regex, routes, messages
 *   - format:      currency, date, document, number, string
 *   - guards:      isArray, isBoolean, isDate, isNumber, isObject, isString
 *   - helpers:     clipboard, cookie, debounce, deepClone, generateId, retry, storage, throttle
 *   - mask:        cep, creditCard, currency, document, phone
 *   - parse:       date, number
 *   - sanitize:    html, object, string
 *   - transform:   apiToClient, clientToApi
 *   - validation:  cep, document, email, password, phone, url
 *   - error:       errorBoundary, httpError, validationError
 *
 * @autor   JunioSilvestre
 * @versao  1.0.0
 */
