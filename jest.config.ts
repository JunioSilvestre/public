import type { Config } from 'jest';
import nextJest from 'next/jest.js';

const createJestConfig = nextJest({
  // Fornece o caminho para o seu app Next.js para carregar next.config.js e .env no ambiente de teste
  dir: './',
});

// Adicione qualquer configuração customizada do Jest aqui
const config: Config = {
  coverageProvider: 'v8',
  testEnvironment: 'jsdom',
  // Adiciona mais setup options antes de cada teste
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],

  // Mapeia os aliases de caminho para os diretórios corretos
  moduleNameMapper: {
    '^@/(.*)$/': '<rootDir>/src/$1',
  },
  // Ignora a transformação de módulos específicos
  transformIgnorePatterns: [
    '/node_modules/',
    '^.+\.module\.(css|sass|scss)$',
  ],
};

// createJestConfig é exportado desta forma para garantir que a página em `next/jest` possa carregar a configuração do Next.js, que é assíncrona
export default createJestConfig(config);
