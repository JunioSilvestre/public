/**
 * @file        src/header/header.config.ts
 * @module      Header / Configuration
 * @description Header component configuration for the Portfolio.
 *              Includes links for About, Works, Contact, and the Get Started button.
 */

import { NavLink } from './header.types';

/**
 * Default navigation links in the header.
 * Adjusted for anchor links (Smooth Scroll).
 */
export const HEADER_LINKS: NavLink[] = [
    { id: '1', label: 'About', href: '#about' },
    { id: '2', label: 'Works', href: '#works' },
    { id: '3', label: 'Contact', href: '#contact' },
    { id: '4', label: 'Get Started', href: '#contact', isPrimary: true },
];

/**
 * Global Header configuration.
 */
export const HEADER_CONFIG = {
    /** Brand name displayed in the logo. */
    logoText: 'JS',
    /** Screen width in pixels below which the mobile layout is activated. */
    breakpoint: 768,
    /** Base height of the header. */
    height: '72px',
};
