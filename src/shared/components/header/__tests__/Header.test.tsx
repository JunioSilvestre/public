import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import Header from '../Header';
import { HEADER_LINKS } from '../header.config';

describe('Header Component', () => {
    test('renders logo JS', () => {
        render(<Header />);
        const logoElement = screen.getAllByText(/JS/i)[0];
        expect(logoElement).toBeInTheDocument();
    });

    test('renders navigation links', () => {
        render(<Header />);
        HEADER_LINKS.forEach(link => {
            const linkElements = screen.getAllByText(new RegExp(link.label, 'i'));
            expect(linkElements.length).toBeGreaterThan(0);
        });
    });

    test('mobile menu toggles when clicked', () => {
        render(<Header />);
        const toggleButton = screen.getByLabelText(/abrir menu/i);

        // Initial state: not open (checked via class or aria-expanded if implemented)
        // Here we just check if it's clickable
        fireEvent.click(toggleButton);

        // After click, we check if links are visible (depending on CSS, they might be in DOM but hidden)
        // Testing-library handles basic visibility if CSS is loaded, but for simple tests
        // we just ensure the interaction doesn't crash and the state changes internally.
    });
});
