import { vi } from 'vitest'

// Ensure a stable localStorage implementation for unit tests.
// Some environments (or bundled globals) may not provide the full Storage API.
function createMemoryStorage(): Storage {
  const store = new Map<string, string>()

  return {
    get length() {
      return store.size
    },
    clear() {
      store.clear()
    },
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null
    },
    removeItem(key: string) {
      store.delete(key)
    },
    setItem(key: string, value: string) {
      store.set(key, String(value))
    },
  } as Storage
}

const ls: any = (globalThis as any).localStorage
const needsPolyfill = !ls || typeof ls !== 'object' || typeof ls.getItem !== 'function' || typeof ls.setItem !== 'function'

if (needsPolyfill) {
  vi.stubGlobal('localStorage', createMemoryStorage())
}
