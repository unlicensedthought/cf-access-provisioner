import { describe, expect, it } from 'vitest';
import type { AccessIdp, AccessPolicy } from '../cf-access';
import { assertHardened, assertIdps, HardeningError, sessionHours } from '../harden';
import { parseAccessConfig } from '../schemas';

const TEAM = 'team.cloudflareaccess.com';
const CALLBACK = `https://${TEAM}/cdn-cgi/access/callback`;
const cfg = (over = {}) => parseAccessConfig({ domain: 'a.example.com', app_name: 'A', allowlist_group: 'allowed-users', ...over });

describe('sessionHours', () => {
  it('parses h and m forms', () => {
    expect(sessionHours('24h')).toBe(24);
    expect(sessionHours('168h')).toBe(168);
    expect(sessionHours('30m')).toBe(0.5);
    expect(sessionHours('1h30m')).toBe(1.5);
  });
});

describe('assertHardened', () => {
  const goodPolicies: AccessPolicy[] = [
    { name: 'Allow', decision: 'allow', include: [{ group: { id: 'g1' } }] },
  ];

  it('passes a hardened config', () => {
    expect(() => assertHardened(cfg(), goodPolicies)).not.toThrow();
  });

  it('rejects session > 24h', () => {
    expect(() => assertHardened(cfg({ session_duration: '720h' }), goodPolicies)).toThrow(
      HardeningError,
    );
  });

  it('rejects an email_domain wildcard policy', () => {
    const pol: AccessPolicy[] = [
      {
        name: 'Broad',
        decision: 'allow',
        include: [{ email_domain: { domain: 'example.com' } }],
      },
    ];
    expect(() => assertHardened(cfg(), pol)).toThrow(/email_domain/);
  });

  it('rejects an everyone policy', () => {
    const pol: AccessPolicy[] = [{ name: 'Pub', decision: 'allow', include: [{ everyone: {} }] }];
    expect(() => assertHardened(cfg(), pol)).toThrow(/everyone/);
  });

  it('flags a service token policy that is not non_identity', () => {
    const pol: AccessPolicy[] = [
      { name: 'Allow', decision: 'allow', include: [{ group: { id: 'g' } }] },
      { name: 'Svc', decision: 'allow', include: [{ service_token: { token_id: 't' } }] },
    ];
    expect(() => assertHardened(cfg(), pol)).toThrow(/service_token/);
  });
});

describe('assertIdps', () => {
  const oauthGithub: AccessIdp = {
    id: 'gh',
    name: 'GitHub',
    type: 'github',
    config: { client_id: 'Ov23liTESTCLIENT0000', redirect_url: CALLBACK },
  };
  const google: AccessIdp = {
    id: 'gg',
    name: 'Google',
    type: 'google',
    config: { client_id: '123.apps.googleusercontent.com', redirect_url: CALLBACK },
  };

  it('passes GitHub OAuth App + Google with correct callback', () => {
    expect(() =>
      assertIdps(cfg({ allowed_idps: ['github', 'google'] }), [oauthGithub, google], TEAM),
    ).not.toThrow();
  });

  it('fails when GitHub is a GitHub App (Iv23li)', () => {
    const ghApp: AccessIdp = {
      ...oauthGithub,
      config: { client_id: 'Iv23liTESTAPP000000', redirect_url: CALLBACK },
    };
    expect(() => assertIdps(cfg({ allowed_idps: ['github'] }), [ghApp], TEAM)).toThrow(
      /GitHub App/,
    );
  });

  it('fails on a callback mismatch', () => {
    const bad: AccessIdp = {
      ...google,
      config: { client_id: 'x', redirect_url: 'https://evil/cb' },
    };
    expect(() => assertIdps(cfg({ allowed_idps: ['google'] }), [bad], TEAM)).toThrow(
      /redirect_url/,
    );
  });

  it('fails when a requested idp is missing', () => {
    expect(() => assertIdps(cfg({ allowed_idps: ['github'] }), [google], TEAM)).toThrow(
      /idp_missing|no github/,
    );
  });

  it('ignores otp (no oauth client)', () => {
    expect(() =>
      assertIdps(cfg({ allowed_idps: ['otp'] }), [{ id: 'o', name: '', type: 'onetimepin' }], TEAM),
    ).not.toThrow();
  });
});
