"use client";

import { ReactNode, useEffect } from "react";

interface Props {
  children: ReactNode;
}

export default function AuthTokenProvider({ children }: Props) {
  useEffect(() => {
    const token = process.env.NEXT_PUBLIC_JWT_TOKEN;
    if (token) {
      try {
        localStorage.setItem("BACKEND_JWT_TOKEN", token);
      } catch (_) {}
      // Set cookie that expires in 7 days
      const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toUTCString();
      document.cookie = `BACKEND_JWT_TOKEN=${token}; expires=${expires}; path=/`;
    }
  }, []);

  return <>{children}</>;
} 