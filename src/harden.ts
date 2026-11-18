/**
 * @file harden.ts
 * @description Static hardening + IdP guards. Fail loud (throw) on any misconfig
 * so a bad config never reaches production. Encodes the session's learnings:
 * no email_domain wildcards, deny-by-default, cookie hardening, capped session,
 * and GitHub-must-be-an-OAuth-App (Ov23) not a GitHub App (Iv23li).
 */

import type { AccessIdp, AccessPolicy } from './cf-access';
import type { SpaAccessConfig } from './schemas';

/** Max allowed session duration in hours (hardening cap). */
export const MAX_SESSION_HOURS = 24;

/** A single hardening violation. */
export interface HardeningViolation {
  rule: string;
  detail: string;
}

/** Thrown when hardening or IdP guards fail; carries every violation. */
export class HardeningError extends Error {
  /**
   * Build the error from every violation found.
   *
   * @param violations - The hardening violations that tripped the guard.
   */
  constructor(readonly violations: HardeningViolation[]) {
    super(`hardening failed: ${violations.map((v) => `${v.rule} (${v.detail})`).join('; ')}`);
    this.name = 'HardeningError';
  }
}

/** Parse a CF session_duration string ("24h", "30m", "168h", "1h30m") to hours. */
export function sessionHours(duration: string): number {
  const m = duration.match(/(\d+)h/);
  const h = m ? Number(m[1]) : 0;
  const mm = duration.match(/(\d+)m/);
  const min = mm ? Number(mm[1]) : 0;
  return h + min / 60;
}

/**
 * Assert a config + its resulting policies are hardened. Throws HardeningError
 * with the full violation list (never throws on the first one — report them all).
 *
 * @param cfg - the validated config
 * @param policies - the app's current policies (to assert deny-by-default etc.)
 */
export function assertHardened(cfg: SpaAccessConfig, policies: AccessPolicy[]): void {
  const v: HardeningViolation[] = [];

  if (sessionHours(cfg.session_duration) > MAX_SESSION_HOURS) {
    v.push({
      rule: 'session_duration',
      detail: `> ${MAX_SESSION_HOURS}h: ${cfg.session_duration}`,
    });
  }
  if (!cfg.cookie.http_only) {
    v.push({ rule: 'cookie.http_only', detail: 'must be true' });
  }
  if (!cfg.cookie.same_site) {
    v.push({ rule: 'cookie.same_site', detail: 'must be set (strict|lax)' });
  }

  // No email_domain wildcards anywhere in the allow policies.
  for (const p of policies) {
    if (p.decision !== 'allow') continue;
    for (const rule of p.include) {
      if ('email_domain' in rule) {
        v.push({
          rule: 'email_domain_wildcard',
          detail: `policy "${p.name}" includes an email_domain rule`,
        });
      }
      if ('everyone' in rule) {
        v.push({ rule: 'everyone', detail: `policy "${p.name}" allows EVERYONE` });
      }
    }
  }

  // Deny-by-default: at least one allow policy must exist (otherwise no humans
  // can reach the app — that is a misconfig we surface rather than silently ship).
  if (policies.length > 0 && !policies.some((p) => p.decision === 'allow')) {
    v.push({ rule: 'deny_by_default', detail: 'no allow policy present' });
  }

  // Service-token policies must be non_identity (never allow).
  for (const p of policies) {
    const isSvc = p.include.some((r) => 'service_token' in r);
    if (isSvc && p.decision !== 'non_identity') {
      v.push({ rule: 'service_token_decision', detail: `policy "${p.name}" must be non_identity` });
    }
  }

  if (v.length > 0) throw new HardeningError(v);
}

/** GitHub App client ids start with this prefix; CF Access does NOT support them. */
export const GITHUB_APP_PREFIX = 'Iv23li';
/** GitHub OAuth App client ids start with this prefix; required by CF Access. */
export const GITHUB_OAUTH_PREFIX = 'Ov23';

/**
 * Assert the account's identity providers are correctly configured for the IdPs
 * the config wants. Throws HardeningError on any problem.
 *
 * @param cfg - the validated config
 * @param idps - the account identity providers
 * @param authDomain - the team auth domain (e.g. "team.cloudflareaccess.com")
 */
export function assertIdps(cfg: SpaAccessConfig, idps: AccessIdp[], authDomain: string): void {
  const v: HardeningViolation[] = [];
  const expectedCallback = `https://${authDomain}/cdn-cgi/access/callback`;
  const typeFor: Record<string, string> = { github: 'github', google: 'google', otp: 'onetimepin' };

  for (const kind of cfg.allowed_idps) {
    const type = typeFor[kind];
    const idp = idps.find((i) => i.type === type);
    if (!idp) {
      v.push({ rule: 'idp_missing', detail: `no ${kind} identity provider on the account` });
      continue;
    }
    if (kind === 'otp') continue; // onetimepin has no OAuth client/callback

    const cb = idp.config?.redirect_url;
    if (cb && cb !== expectedCallback) {
      v.push({ rule: 'idp_callback', detail: `${kind} redirect_url ${cb} != ${expectedCallback}` });
    }
    if (kind === 'github') {
      const cid = idp.config?.client_id ?? '';
      if (cid.startsWith(GITHUB_APP_PREFIX)) {
        v.push({
          rule: 'github_app_not_oauth_app',
          detail: `GitHub client_id ${cid} is a GitHub App (${GITHUB_APP_PREFIX}); CF Access needs an OAuth App (${GITHUB_OAUTH_PREFIX})`,
        });
      } else if (!cid.startsWith(GITHUB_OAUTH_PREFIX)) {
        v.push({
          rule: 'github_client_id',
          detail: `GitHub client_id ${cid} is not an OAuth App (${GITHUB_OAUTH_PREFIX})`,
        });
      }
    }
  }

  if (v.length > 0) throw new HardeningError(v);
}
