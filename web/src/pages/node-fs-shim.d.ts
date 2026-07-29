// Ambient shim for `node:fs`/`node:path`/`node:url`, used by test-time source
// scans that read the REAL repo source instead of trusting a hand copy:
// Inventory.test.tsx's pin test (reads lifecycle.py to check
// RETIRE_ELIGIBLE_STATES) and lifecycleStateGuard.test.ts (walks web/src
// looking for a lifecycle state rendered outside LifecycleBadge).
//
// This app's tsconfig (tsconfig.app.json) intentionally scopes `"types"` to
// `["vite/client"]` only, with no @types/node - app code runs in the browser
// and has no business seeing `process`/`Buffer`/etc. Vitest itself runs on
// real Node, where these three functions work fine at runtime; the gap is
// purely that tsc (run as `tsc -p tsconfig.app.json`, which also type-checks
// test files under `src`) has no ambient declarations for them.
//
// Deliberately NOT `"types": ["node"]` in tsconfig.app.json: that would pull
// in @types/node's entire global ambient surface (`process`, `Buffer`,
// `__dirname`, ...) project-wide, letting a stray reference to one of those
// typecheck as if it existed in browser code anywhere else in `src`. This
// file only declares the functions actually used, and ONLY as named
// exports of their own modules - nothing global leaks.
//
// IMPORTANT: this file must have NO top-level `import`/`export` of its own.
// The moment it does, TypeScript treats it as a module and every `declare
// module 'x' {...}` below becomes an AUGMENTATION of an already-resolvable
// module `x` (and fails with "cannot be found", since these aren't
// resolvable at all here) rather than a fresh ambient declaration.
declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf-8'): string
  export interface Dirent {
    name: string
    isDirectory(): boolean
  }
  export function readdirSync(path: string, options: { withFileTypes: true }): Dirent[]
}

declare module 'node:path' {
  function join(...parts: string[]): string
  function dirname(p: string): string
  function relative(from: string, to: string): string
  const path: { join: typeof join; dirname: typeof dirname; relative: typeof relative }
  export default path
}

declare module 'node:url' {
  export function fileURLToPath(url: string): string
}
