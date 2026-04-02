/**
 * src/hero/__tests__/Hero.test.tsx
 */
import { render, screen } from '@testing-library/react';
import Hero from '../Hero';

describe('Hero Component', () => {
    it('deve renderizar o título principal', () => {
        render(<Hero />);
        expect(screen.getByText(/Building/i)).toBeInTheDocument();
    });

    it('deve renderizar o botão de call to action', () => {
        render(<Hero />);
        expect(screen.getByText(/VIEW PROJECTS/i)).toBeInTheDocument();
    });
});
