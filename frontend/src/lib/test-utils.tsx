import React, { ReactElement } from 'react';
import { render, RenderOptions } from '@testing-library/react';
import HydrationProvider from '@/components/providers/HydrationProvider';

const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
  return (
    <HydrationProvider>
      {children}
    </HydrationProvider>
  );
};

const customRender = (
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>,
) => render(ui, { wrapper: AllTheProviders, ...options });

export * from '@testing-library/react';
export { customRender as render }; 