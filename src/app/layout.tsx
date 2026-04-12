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
      <head>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" />
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.css" />
        <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons" />
      </head>
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
