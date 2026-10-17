/** Sign final native runtime files before the enclosing Desktop application is signed. */

import { createHash } from 'node:crypto'
import { closeSync, openSync, readSync } from 'node:fs'
import { join } from 'node:path'
import { inventoryDesktopRuntime } from '../src/runtime-tree.ts'
import type { MacOSSigningEnvironment } from './desktop-release-environment.mjs'
import { cachedMacOSSignature, pruneMacOSSignatureCache } from './macos-signature-cache.ts'
import { macOSCachePolicy } from './macos-cache-policy.ts'
import { signMacOSRuntimeCode, signMacOSRuntimeCodeAdHoc, verifyMacOSRuntimeCode } from './verify-macos-signature.mjs'

const MACH_O_MAGICS = new Set(['cafebabe', 'cafebabf', 'cefaedfe', 'cffaedfe', 'feedface', 'feedfacf', 'bebafeca', 'bfbafeca'])

function magic(path: string): string {
  const descriptor = openSync(path, 'r')
  try {
    const header = Buffer.alloc(4)
    return readSync(descriptor, header, 0, 4, 0) === 4 ? header.toString('hex') : ''
  } finally { closeSync(descriptor) }
}

/** Per-file code signer shared by the release and ad-hoc runtime walks. */
type MacOSRuntimeCodeSigner = (path: string, identifier: string, entitlements: string | undefined) => Promise<void>

/**
 * Walk and sign every materialized Mach-O file, awaiting all signers on failure.
 * @param root - Self-contained production runtime without symlinks.
 * @param appId - Application identifier used to derive per-file signing identifiers.
 * @param arch - Target runtime architecture, independent of the signing host.
 * @param sign - Per-file signer; release builds also verify each signature.
 * @returns Number of signed native files.
 */
async function signMacOSRuntimeFiles(
  root: string, appId: string, arch: 'arm64' | 'x64', sign: MacOSRuntimeCodeSigner,
): Promise<number> {
  const files = inventoryDesktopRuntime(root).map(file => file.path).filter(path => MACH_O_MAGICS.has(magic(join(root, path))))
  let next = 0
  const workers = Array.from({ length: Math.min(4, files.length) }, async () => {
    for (;;) {
      const path = files[next++]
      if (path === undefined) return
      const identifier = `${appId}.runtime.${createHash('sha256').update(path).digest('hex')}`
      const isNode = path === 'dependencies/node/bin/node'
      const needsJit = isNode
        || /^node_modules\/@deepseek-ai\/libreoffice-kit-darwin-(?:arm64|x64)\/bin\/libreoffice-kit$/u.test(path)
      const entitlementsFile = isNode && arch === 'x64'
        ? 'node-x64-entitlements.plist' : 'jit-entitlements.plist'
      const entitlements = needsJit ? join(import.meta.dirname, entitlementsFile) : undefined
      await sign(join(root, path), identifier, entitlements)
    }
  })
  const results = await Promise.allSettled(workers)
  const errors = results.filter(result => result.status === 'rejected').map(result => result.reason as unknown)
  if (errors.length > 0) throw new AggregateError(errors, 'desktop runtime: native signing failed')
  return files.length
}

/**
 * Sign and verify every materialized Mach-O file, awaiting all signers on failure.
 * @param root - Self-contained production runtime without symlinks.
 * @param appId - Release application identifier.
 * @param expected - Required signing identity.
 * @param arch - Target runtime architecture, independent of the signing host.
 * @param cacheDirectory - Optional content-addressed cache; requires the keychain-owned signing probe.
 * @returns Number of signed native files.
 */
export async function signMacOSRuntime(
  root: string, appId: string, expected: MacOSSigningEnvironment, arch: 'arm64' | 'x64', cacheDirectory?: string,
): Promise<number> {
  const policy = cacheDirectory === undefined ? undefined : macOSCachePolicy(process.env.DSH_DESKTOP_MACOS_SIGNING_PROBE ?? '')
  let hits = 0
  let misses = 0
  const count = await signMacOSRuntimeFiles(root, appId, arch, async (file, identifier, entitlements) => {
    const thin = ['cefaedfe', 'cffaedfe', 'feedface', 'feedfacf'].includes(magic(file))
    if (cacheDirectory !== undefined && policy !== undefined && thin) {
      if (await cachedMacOSSignature(file, cacheDirectory, policy(identifier, expected, entitlements))) hits++
      else misses++
    } else {
      await signMacOSRuntimeCode(file, identifier, expected, entitlements)
      verifyMacOSRuntimeCode(file, expected)
    }
  })
  if (cacheDirectory !== undefined) {
    pruneMacOSSignatureCache(cacheDirectory)
    console.info(`desktop macOS signing cache: ${hits} hits, ${misses} misses, ${count - hits - misses} uncached`)
  }
  return count
}

/**
 * Ad-hoc sign every materialized Mach-O file for a local, non-distributed build.
 * @param root - Self-contained local runtime without symlinks.
 * @param appId - Local application identifier; only the JIT entitlements are granted to the Node interpreter.
 * @param arch - Target runtime architecture, independent of the signing host.
 * @returns Number of signed native files.
 */
export async function signMacOSRuntimeAdHoc(root: string, appId: string, arch: 'arm64' | 'x64'): Promise<number> {
  return signMacOSRuntimeFiles(root, appId, arch, (path, identifier, entitlements) =>
    signMacOSRuntimeCodeAdHoc(path, identifier, entitlements))
}
