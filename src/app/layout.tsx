import type { Metadata } from "next";
import "@/shared/styles/globals.css";
import Header from "@/shared/components/header";
import Footer from "@/shared/components/footer";
import Script from "next/script";

export const metadata: Metadata = {
  title: "Senior Software Engineer | Portfolio",
  description: "High-performance web architectures and modern frontend engineering.",
  robots: { index: true, follow: true },
};

import { AuthProvider } from '@/shared/providers/AuthProvider';

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
