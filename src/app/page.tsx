"use client";

import { useState } from 'react';
import { sanitizeHtml } from '@/security/xss'; // Usando alias de caminho

export default function HomePage() {
  const [inputValue, setInputValue] = useState('');
  const [submittedContent, setSubmittedContent] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittedContent(inputValue);
  };

  return (
    <main className="flex min-h-screen flex-col items-center p-24">
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
  );
}
