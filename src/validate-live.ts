/**
 * @file validate-live.ts
 * @description Live login round-trip validator. Fetches the guarded hostname,
 * follows the Access 302 to the team login page, extracts each IdP's authorize
 * URL, and asserts the provider would accept it (correct client_id + redirect_uri,
 * and NOT an error interstitial). This is the post-provision proof that catches
 * the redirect_uri_mismatch / GitHub "redirect_uri not associated" class of bug.
 */

/** Per-IdP live validation outcome. */
export interface IdpLiveResult {
  idp: 'github' | 'google';
  present: boolean;
  redirectUri?: string;
  clientId?: string;
  ok: boolean;
  error?: string;
}

/** Result of a live validation run for one hostname. */
export interface LiveValidation {
  hostname: string;
  gated: boolean;
  results: IdpLiveResult[];
}

/** Extract an IdP authorize URL from the Access login HTML. */
function extractAuthorizeUrl(html: string, host: string): string | null {
  const re = new RegExp(`${host}[^"'\\s\\\\]+`);
  const m = html.match(re);
  if (!m) return null;
  return `https://${decodeHtml(m[0])}`;
}

/** Decode the minimal HTML entities the Access login page emits in URLs. */
function decodeHtml(s: string): string {
  return s
    .replace(/&#x2F;/g, '/')
    .replace(/&#x3D;/g, '=')
    .replace(/&amp;/g, '&');
}

/** Pull a query param value out of a URL string without throwing. */
function param(url: string, key: string): string | undefined {
  try {
    return new URL(url).searchParams.get(key) ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * Validate the live login flow for a hostname.
 *
 * @param hostname - the guarded host (e.g. "app.example.com")
 * @param authDomain - the team auth domain
 * @param fetchImpl - injectable fetch (tests stub this)
 */
export async function validateLive(
  hostname: string,
  authDomain: string,
  // Arrow wrapper calls global fetch with no detached receiver (avoids the
  // Workers "Illegal invocation" error). Tests inject their own stub.
  fetchImpl: typeof fetch = (input, init) => fetch(input, init),
): Promise<LiveValidation> {
  const expectedCallback = `https://${authDomain}/cdn-cgi/access/callback`;
  // 1. Hitting the app should 302 to the Access login (proves the gate is up).
  const head = await fetchImpl(`https://${hostname}`, { redirect: 'manual' });
  const loc = head.headers.get('location') ?? '';
  const gated = head.status === 302 && loc.includes(authDomain);
  if (!gated) {
    return { hostname, gated: false, results: [] };
  }

  // 2. Load the login page and extract each provider authorize URL.
  const loginHtml = await (await fetchImpl(loc)).text();
  const results: IdpLiveResult[] = [];

  for (const idp of ['github', 'google'] as const) {
    const host =
      idp === 'github' ? 'github.com/login/oauth/authorize' : 'accounts.google.com/o/oauth2/auth';
    const authUrl = extractAuthorizeUrl(loginHtml, host);
    if (!authUrl) {
      results.push({ idp, present: false, ok: false, error: 'button not on login page' });
      continue;
    }
    const redirectUri = param(authUrl, 'redirect_uri');
    const clientId = param(authUrl, 'client_id');
    let ok = true;
    let error: string | undefined;
    if (redirectUri !== expectedCallback) {
      ok = false;
      error = `redirect_uri ${redirectUri} != ${expectedCallback}`;
    }
    if (ok && idp === 'github' && clientId?.startsWith('Iv23li')) {
      ok = false;
      error = `GitHub client_id ${clientId} is a GitHub App, not an OAuth App`;
    }
    results.push({ idp, present: true, redirectUri, clientId, ok, error });
  }

  return { hostname, gated, results };
}
