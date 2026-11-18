import { describe, expect, it, vi } from 'vitest';
import { validateLive } from '../validate-live';

const TEAM = 'team.cloudflareaccess.com';
const CB = encodeURIComponent(`https://${TEAM}/cdn-cgi/access/callback`);

/** Build a login page with GitHub + Google authorize URLs (HTML-entity encoded). */
function loginHtml(ghClientId: string, ggClientId: string) {
  const gh = `https://github.com/login/oauth/authorize?client_id=${ghClientId}&redirect_uri=${CB}&scope=read:user`;
  const gg = `https://accounts.google.com/o/oauth2/auth?client_id=${ggClientId}&redirect_uri=${CB}&scope=openid`;
  const enc = (s: string) =>
    // Real Access login pages keep '/' and '=' literal and join params with
    // &amp;; the redirect_uri value is already %-encoded (encodeURIComponent).
    s.replace(/&/g, '&amp;');
  return `<html><a href="${enc(gh)}">GitHub</a><a href="${enc(gg)}">Google</a></html>`;
}

function stubFetch(loginPage: string, gated = true) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const u = String(input);
    if (u === 'https://app.example.com' && init?.redirect === 'manual') {
      return new Response(null, {
        status: gated ? 302 : 200,
        headers: gated ? { location: `https://${TEAM}/cdn-cgi/access/login/app` } : {},
      });
    }
    return new Response(loginPage, { status: 200 });
  }) as unknown as typeof fetch;
}

describe('validateLive', () => {
  it('passes when both IdPs use the OAuth App + correct callback', async () => {
    const f = stubFetch(loginHtml('Ov23liTESTCLIENT0000', '123.apps.googleusercontent.com'));
    const r = await validateLive('app.example.com', TEAM, f);
    expect(r.gated).toBe(true);
    expect(r.results.every((x) => x.ok)).toBe(true);
  });

  it('flags GitHub when it is a GitHub App (Iv23li)', async () => {
    const f = stubFetch(loginHtml('Iv23liTESTAPP000000', '123.apps.googleusercontent.com'));
    const r = await validateLive('app.example.com', TEAM, f);
    const gh = r.results.find((x) => x.idp === 'github');
    expect(gh?.ok).toBe(false);
    expect(gh?.error).toMatch(/GitHub App/);
  });

  it('flags a redirect_uri mismatch', async () => {
    const bad = loginHtml('Ov23x', 'x').replace(CB, encodeURIComponent('https://evil/cb'));
    const f = stubFetch(bad);
    const r = await validateLive('app.example.com', TEAM, f);
    expect(r.results.some((x) => !x.ok && /redirect_uri/.test(x.error ?? ''))).toBe(true);
  });

  it('reports not-gated when the host does not 302 to Access', async () => {
    const f = stubFetch(loginHtml('Ov23x', 'x'), false);
    const r = await validateLive('app.example.com', TEAM, f);
    expect(r.gated).toBe(false);
    expect(r.results).toEqual([]);
  });
});
