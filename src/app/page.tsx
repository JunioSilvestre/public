/**
 * @arquivo     src/app/page.tsx
 * @módulo      App / Página Inicial
 * @descrição   Página raiz da aplicação (rota "/"). Renderiza o componente Hero
 *              e uma área de demonstração interativa de sanitização XSS.
 *              O formulário permite ao usuário digitar HTML/JS arbitrário e ver
 *              o resultado renderizado de forma segura via `sanitizeHtml()`.
 *
 * @como-usar   Acesse "/" no navegador. A área de teste XSS é apenas para
 *              demonstração em desenvolvimento — remova-a em produção.
 *
 * @dependências @/security/xss (sanitizeHtml), @/hero (Hero)
 * @notas       "use client" é necessário porque o componente usa hooks de estado (useState).
 */
"use client";

import { useState } from 'react';
import { sanitizeHtml } from '@/security/xss';
import Hero from '@/hero';

export default function HomePage() {
  const [inputValue, setInputValue] = useState('');
  const [submittedContent, setSubmittedContent] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittedContent(inputValue);
  };

  return (
    <>
      <Hero />
      <main className="flex min-h-[50vh] flex-col items-center p-24 bg-[#121318]">
        <h1 className="text-2xl font-bold mb-8">Teste de Segurança XSS</h1>

        <form onSubmit={handleSubmit} className="w-full max-w-lg mb-8">
          <div className="flex flex-col">
            <label htmlFor="userInput" className="mb-2 font-semibold">
              Digite um conteúdo (tente injetar um script):
            </label>
            <input
              id="userInput"
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              className="border rounded p-2 text-black"
              placeholder='Ex: <b>Olá</b><script>alert("XSS")</script>'
            />
            <button type="submit" className="mt-4 bg-blue-500 text-white p-2 rounded">
              Enviar
            </button>
          </div>
        </form>

        {submittedContent && (
          <div className="w-full max-w-lg border p-4 rounded">
            <h2 className="font-bold mb-2">Conteúdo Renderizado com Segurança:</h2>
            {/* A mágica acontece aqui! Usamos dangerouslySetInnerHTML com o nosso sanitizador. */}
            <div
              id="output"
              dangerouslySetInnerHTML={{ __html: sanitizeHtml(submittedContent) }}
            />
          </div>
        )}
      </main>
    </>
  );
}
