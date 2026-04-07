"use client";

/**
 * @file        src/contact/Contact.tsx
 * @module      Contact / Main Component
 * @description Interactive contact section with a form and support information.
 */

import React, { useState, useEffect } from 'react';
import styles from './Contact.module.css';
import { CONTACT_CONFIG } from './contact.config';

export const Contact: React.FC = () => {
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Initialize Feather Icons if available
  useEffect(() => {
    const replaceIcons = () => {
      // @ts-ignore
      if (typeof window !== 'undefined' && window.feather) {
        // @ts-ignore
        window.feather.replace();
      }
    };

    replaceIcons();
    // Retry after a short delay to ensure CDN script loaded
    const timer = setTimeout(replaceIcons, 1000);
    const interval = setInterval(replaceIcons, 3000); // Extra safety interval
    
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, [isSubmitted]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    // Submission simulation
    setTimeout(() => {
      setIsLoading(false);
      setIsSubmitted(true);

      // Reset after 6 seconds
      setTimeout(() => {
        setIsSubmitted(false);
      }, 6000);
    }, 1200);
  };

  return (
    <section id="contact" className={styles.section}>
      <div className={styles.container}>
        
        {/* Left Side - Information */}
        <div className={styles.infoSide}>
          <div>
            <h2 className={styles.title}>
              {CONTACT_CONFIG.title.split(' ')[0]} <span className={styles.titleAccent}>{CONTACT_CONFIG.title.split(' ')[1]}</span>
            </h2>
            <p className={styles.description}>
              {CONTACT_CONFIG.description}
            </p>
          </div>

          <div className={styles.infoList}>
            {Object.entries(CONTACT_CONFIG.info).map(([key, item]) => (
              <div key={key} className={styles.infoItem}>
                <div className={styles.iconBox}>
                  <i data-feather={item.icon} className="w-5 h-5"></i>
                </div>
                <div>
                  <p className={styles.infoLabel}>{item.label}</p>
                  {item.href ? (
                    <a href={item.href} className={styles.infoValue}>{item.value}</a>
                  ) : (
                    <p className={styles.infoValue}>{item.value}</p>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className={styles.socialBox}>
            <p className={styles.socialLabel}>Connect with me</p>
            <div className={styles.socialLinks}>
              {CONTACT_CONFIG.socials.map((social, i) => (
                <a 
                  key={i} 
                  href={social.href} 
                  className={styles.socialIcon} 
                  title={social.name}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <i className={social.icon}></i>
                </a>
              ))}
            </div>
          </div>

        </div>

        {/* Right Side - Form */}
        <div className={styles.card}>
          <form 
            onSubmit={handleSubmit} 
            className={`${styles.form} ${isSubmitted ? styles.hidden : ''}`}
          >
            <div className={styles.fieldGroup}>
              <label className={styles.label}>{CONTACT_CONFIG.form.fields.name.label}</label>
              <input 
                type="text" 
                required 
                className={styles.input} 
                placeholder={CONTACT_CONFIG.form.fields.name.placeholder} 
              />
            </div>

            <div className={styles.fieldGroup}>
              <label className={styles.label}>{CONTACT_CONFIG.form.fields.email.label}</label>
              <input 
                type="email" 
                required 
                className={styles.input} 
                placeholder={CONTACT_CONFIG.form.fields.email.placeholder} 
              />
            </div>

            <div className={styles.fieldGroup}>
              <label className={styles.label}>{CONTACT_CONFIG.form.fields.message.label}</label>
              <textarea 
                required 
                className={styles.textarea} 
                placeholder={CONTACT_CONFIG.form.fields.message.placeholder}
              ></textarea>
            </div>

            <button 
              type="submit" 
              disabled={isLoading}
              className={styles.submitBtn}
            >
              {isLoading ? (
                <span>Sending...</span>
              ) : (
                <>
                  <span>{CONTACT_CONFIG.form.submitLabel}</span>
                  <i data-feather="send" className="w-5 h-5"></i>
                </>
              )}
            </button>
          </form>

          {/* Success Message */}
          <div className={`${styles.success} ${!isSubmitted ? styles.hidden : ''}`}>
             <div className={styles.successIcon}>
               <i data-feather="check-circle" className="w-16 h-16 mx-auto"></i>
             </div>
             <h3 className={styles.successTitle}>{CONTACT_CONFIG.form.successMsg.title}</h3>
             <p className={styles.successText}>{CONTACT_CONFIG.form.successMsg.sub}</p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Contact;
