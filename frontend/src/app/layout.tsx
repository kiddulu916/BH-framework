import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import QueryProvider from "@/components/providers/QueryProvider";
import { PerformanceMonitorComponent } from "@/components/atoms/PerformanceMonitor";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Bug Hunting Framework - Target Profile Builder",
  description: "Create and manage target profiles for ethical security testing",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${inter.variable} antialiased`}
      >
        <QueryProvider>
          {children}
          <PerformanceMonitorComponent />
        </QueryProvider>
      </body>
    </html>
  );
}
