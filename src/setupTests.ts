import '@testing-library/jest-dom';

// NOTE ON GLOBAL OBJECTS:
// Our tests run in a jsdom environment (simulated browser), not pure Node.js.
// This means the Node-specific `global` object is NOT available.
// Always use `globalThis` (the ECMAScript standard) instead of `global`.
// For mocking globals in tests, prefer Vitest's vi.stubGlobal() API.

// Polyfill for atob/btoa in case of older Node.js versions
// Node 20+ includes these natively, but this ensures compatibility
if (typeof globalThis.atob === 'undefined') {
  globalThis.atob = (data: string) => Buffer.from(data, 'base64').toString('binary');
}

if (typeof globalThis.btoa === 'undefined') {
  globalThis.btoa = (data: string) => Buffer.from(data, 'binary').toString('base64');
}
