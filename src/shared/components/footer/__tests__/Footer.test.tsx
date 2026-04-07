/**
 * src/footer/__tests__/Footer.test.tsx
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import { Footer } from '../Footer';

describe('Footer Component', () => {
    test('renders copyright text with the current year', () => {
        render(<Footer />);
        const currentYear = new Date().getFullYear().toString();
        const copyrightElement = screen.getByText(new RegExp(currentYear));
        expect(copyrightElement).toBeDefined();
    });

    test('renders social media links', () => {
        render(<Footer />);
        const socialNav = screen.getByLabelText(/Social media links/i);
        expect(socialNav).toBeDefined();

        // Check for specific platforms by aria-label
        expect(screen.getByLabelText(/Instagram/i)).toBeDefined();
        expect(screen.getByLabelText(/Facebook/i)).toBeDefined();
        expect(screen.getByLabelText(/LinkedIn/i)).toBeDefined();
    });

    test('has correct background color style from CSS Module', () => {
        const { container } = render(<Footer />);
        const footerElement = container.querySelector('footer');
        expect(footerElement).toHaveClass('footer');
    });
});
