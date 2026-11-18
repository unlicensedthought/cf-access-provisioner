/**
 * @file auth.ts
 * @description Constant-time bearer comparison. An empty token never matches.
 */

/**
 * Compare two strings without an early exit on the first differing byte.
 * Lengths are folded into the result so a length mismatch still walks the
 * whole longer string.
 *
 * @param provided - untrusted value from the request
 * @param expected - the configured secret
 * @returns true only when both are non-empty and identical
 */
export function timingSafeTokenMatch(provided: string, expected: string): boolean {
  if (!provided || !expected) return false;
  const enc = new TextEncoder();
  const a = enc.encode(provided);
  const b = enc.encode(expected);
  const n = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
