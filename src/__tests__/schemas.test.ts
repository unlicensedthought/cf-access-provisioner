import { describe, expect, it } from 'vitest';
import { parseAccessConfig } from '../schemas';

describe('parseAccessConfig', () => {
  it('accepts a minimal config and applies hardened defaults', () => {
    const cfg = parseAccessConfig({ domain: 'app.example.com', app_name: 'App', allowlist_group: 'allowed-users' });
    expect(cfg.session_duration).toBe('24h');
    expect(cfg.cookie.http_only).toBe(true);
    expect(cfg.cookie.same_site).toBe('lax');
    expect(cfg.auto_redirect).toBe(false);
    expect(cfg.allowed_idps).toEqual([]);
    expect(cfg.allowlist_group).toBe('allowed-users');
  });

  it('accepts explicit idps + override emails', () => {
    const cfg = parseAccessConfig({
      domain: 'edge.example.com',
      app_name: 'Edge',
      allowlist_group: 'allowed-users',
      allowed_idps: ['github', 'google', 'otp'],
      override_emails: ['me@example.com'],
    });
    expect(cfg.allowed_idps).toEqual(['github', 'google', 'otp']);
    expect(cfg.override_emails).toEqual(['me@example.com']);
  });

  it('rejects an unknown idp', () => {
    expect(() =>
      parseAccessConfig({ domain: 'a.b.com', app_name: 'A', allowlist_group: 'g', allowed_idps: ['saml'] }),
    ).toThrow();
  });

  it('rejects a bad domain', () => {
    expect(() => parseAccessConfig({ domain: 'notahost', app_name: 'A', allowlist_group: 'g' })).toThrow();
  });

  it('bans email_domain wildcard entries in override_emails', () => {
    expect(() =>
      parseAccessConfig({ domain: 'a.b.com', app_name: 'A', allowlist_group: 'g', override_emails: ['@example.com'] }),
    ).toThrow(/wildcard/i);
  });

  it('requires the allowlist group: there is no default to point an app at', () => {
    expect(() => parseAccessConfig({ domain: 'a.b.com', app_name: 'A' })).toThrow(/allowlist_group/);
  });

  it('rejects an override that is not an email, and a wildcard with a star', () => {
    expect(() =>
      parseAccessConfig({ domain: 'a.b.com', app_name: 'A', allowlist_group: 'g', override_emails: ['nope'] }),
    ).toThrow(/not an email/);
    expect(() =>
      parseAccessConfig({ domain: 'a.b.com', app_name: 'A', allowlist_group: 'g', override_emails: ['*@example.com'] }),
    ).toThrow(/wildcard/i);
  });

  it('rejects unknown keys (strict)', () => {
    expect(() => parseAccessConfig({ domain: 'a.b.com', app_name: 'A', allowlist_group: 'g', surprise: 1 })).toThrow();
  });
});
