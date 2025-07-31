'use client';

import { ReactNode, useEffect } from 'react';
import { NavigationMenuOverlay } from './NavigationMenuOverlay';
import { SettingsOverlay } from './SettingsOverlay';

interface OverlayManagerProps {
  children: ReactNode;
  activeOverlay: 'navigation' | 'settings' | null;
  setActiveOverlay: (overlay: 'navigation' | 'settings' | null) => void;
}

export function OverlayManager({ children, activeOverlay, setActiveOverlay }: OverlayManagerProps) {
  // Handle ESC key to close overlays
  useEffect(() => {
    const handleEscKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && activeOverlay) {
        setActiveOverlay(null);
      }
    };

    document.addEventListener('keydown', handleEscKey);
    return () => document.removeEventListener('keydown', handleEscKey);
  }, [activeOverlay, setActiveOverlay]);

  return (
    <div className={`relative ${activeOverlay ? 'overflow-hidden' : ''}`}>
      {/* Main content with blur effect when overlay is active */}
      <div className={activeOverlay ? 'blur-sm transition-all duration-300' : ''}>
        {children}
      </div>

      {/* Navigation Menu Overlay */}
      {activeOverlay === 'navigation' && (
        <NavigationMenuOverlay onClose={() => setActiveOverlay(null)} />
      )}

      {/* Settings Overlay */}
      {activeOverlay === 'settings' && (
        <SettingsOverlay onClose={() => setActiveOverlay(null)} />
      )}
    </div>
  );
} 