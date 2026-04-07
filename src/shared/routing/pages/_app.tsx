import type { AppProps } from 'next/app';
import '../styles/globals.css';

export default function MyApp({ Component, pageProps }: AppProps) {
  return (
    <div className="mx-auto max-w-[1440px]">
      <Component {...pageProps} />
    </div>
  );
}