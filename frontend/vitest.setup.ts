import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock the 'use-sync-external-store/shim/with-selector' module
// This is a workaround for Zustand compatibility issues in a JSDOM environment with React 18
vi.mock('use-sync-external-store/shim/with-selector', () => ({
  useSyncExternalStoreWithSelector: (subscribe, getSnapshot, _, selector) => {
    const state = getSnapshot();
    return selector(state);
  },
})); 