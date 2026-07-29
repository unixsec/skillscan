// Loaded before EVERY test file via vite.config.ts's `test.setupFiles`.
//
// Everything here exists because it is needed by more than one test file. Two
// component-test authors in a row (milestone F Task 7, then Task 8/9) hit the
// same two environment gaps and each stubbed them locally; the duplicates are
// gone and this is now the one place to fix them.

// Extends vitest's `expect` with jest-dom matchers (toBeInTheDocument, etc.).
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

// GAP 1: this jsdom build exposes a `localStorage` OBJECT with no methods on
// it, so `localStorage.getItem(...)` throws "is not a function". I18nProvider
// reads the stored locale during its initial render (i18n/I18nContext.tsx's
// readInitialLocale), so without this stub every test that renders a component
// inside I18nProvider - i.e. every component test, since `t()` needs the
// provider - dies before anything renders.
const localStorageBacking = new Map<string, string>()

vi.stubGlobal('localStorage', {
  getItem: (key: string) => localStorageBacking.get(key) ?? null,
  setItem: (key: string, value: string) => {
    localStorageBacking.set(key, value)
  },
  removeItem: (key: string) => {
    localStorageBacking.delete(key)
  },
  clear: () => localStorageBacking.clear(),
  key: (index: number) => [...localStorageBacking.keys()][index] ?? null,
  get length() {
    return localStorageBacking.size
  },
})

// GAP 2: React Testing Library only auto-registers its own `afterEach(cleanup)`
// when vitest runs with `globals: true`, which this project deliberately does
// not (tests import `describe`/`it`/`expect` explicitly). Without this, every
// `render()` stacks into the SAME document and a later `getByText` matches the
// PREVIOUS test's markup - a failure mode that surfaces as a passing test
// asserting stale content, not as an error.
afterEach(() => {
  cleanup()
  // The locale is persisted through the stub above; leaving it set would let
  // one test that switches to English silently change the language for every
  // test after it in the same file.
  localStorageBacking.clear()
})
