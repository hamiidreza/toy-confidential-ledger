import type { Metadata } from "next";
import { Unbounded, Montserrat } from "next/font/google";
import "./globals.css";

const headingFont = Unbounded({
  subsets: ["latin"],
  weight: ["400"],
  variable: "--font-heading",
});

const bodyFont = Montserrat({
  subsets: ["latin"],
  weight: ["500", "700"],
  variable: "--font-body",
});

export const metadata: Metadata = {
  title: "anonymous payment",
  description: "anonymous payment dApp.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${headingFont.variable} ${bodyFont.variable}`}
      suppressHydrationWarning
    >
      <body className="relative">
        <video
          autoPlay
          loop
          muted
          playsInline
          className="fixed inset-0 w-full h-full object-cover -z-10"
        >
          <source src="/bg.mp4" type="video/mp4" />
        </video>

        <div className="fixed inset-0 bg-black/60 -z-10"></div>

        {children}
      </body>
    </html>
  );
}
