'use client';

import React, { useState, useEffect } from 'react';

interface HydrationProviderProps {
  children: React.ReactNode;
}

const HydrationProvider: React.FC<HydrationProviderProps> = ({ children }) => {
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  if (!isMounted) {
    return null; // Or a loading spinner
  }

  return <>{children}</>;
};

export default HydrationProvider; 