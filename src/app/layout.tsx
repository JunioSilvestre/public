import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "@/styles/globals.css";
import Header from "@/header";
import Footer from "@/footer";
import Script from "next/script";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Senior Software Engineer | Portfolio",
  description: "High-performance web architectures and modern frontend engineering.",
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css" />
      </head>
      <body className={inter.className}>
        <Header />
        <main style={{ paddingTop: '72px' }}>{children}</main>
        <Footer />
        <Script 
          src="https://unpkg.com/feather-icons" 
          strategy="afterInteractive" 
        />
      </body>
    </html>
  );
}
