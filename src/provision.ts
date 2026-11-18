/**
 * @file provision.ts
 * @description Idempotent provisioning of Access groups, apps, and policies from
 * a validated SpaAccessConfig. Create-or-update by name/domain so re-running the
 * same config is a no-op. The allow policy references the shared group (single
 * source of truth) plus any per-app override emails.
 */

import type { AccessApp, AccessPolicy, AccessRule, CfAccessClient } from './cf-access';
import type { IdpKind, SpaAccessConfig } from './schemas';

/** Result of a provisioning run, returned in the API report. */
export interface ProvisionResult {
  app: { id: string; domain: string; aud: string; created: boolean };
  group: { id: string; name: string; created: boolean; emails: string[] };
  policy: { id: string; created: boolean };
  revoked: boolean;
}

/**
 * Ensure an Access group exists, WITHOUT ever rewriting the membership of one
 * that already exists.
 *
 * THIS USED TO REPLACE-ON-DRIFT, AND THAT WAS A LOCKOUT WAITING TO HAPPEN.
 * The caller passed `[]` for the email list whenever a config supplied
 * `override_emails`, so a single provisioning run would set the SHARED group's
 * include list to empty — revoking access to every app that references it, in
 * one API call, with no warning. That risk stops being theoretical the moment a
 * shared group gates live apps.
 *
 * The deeper reason not to write here: the Cloudflare dashboard is the single
 * source of truth for who is in a group. Provisioning code that "reconciles"
 * membership is a second source of truth, and the two silently fight — which is
 * the exact class of drift this service exists to remove. Adding a person must
 * mean editing the group, and nothing else.
 *
 * So: create it if absent, otherwise leave it strictly alone and report the
 * membership actually found. Drift against the caller's expectation is LOGGED,
 * never silently reconciled.
 *
 * @param client - Access API client
 * @param name - group name (e.g. "admins")
 * @param seedEmails - members used ONLY when creating the group for the first
 *   time. Ignored entirely when the group already exists.
 * @returns the group id, name, whether it was created, and its LIVE membership
 * @throws when the group is absent and no seed was supplied — a shared
 *   allowlist must be created deliberately, not conjured empty by a deploy.
 */
export async function ensureGroup(
  client: CfAccessClient,
  name: string,
  seedEmails: string[],
): Promise<{ id: string; name: string; created: boolean; emails: string[] }> {
  const existing = await client.getGroupByName(name);
  if (existing) {
    const liveEmails = (existing.include ?? [])
      .map((r) => (r as { email?: { email?: string } }).email?.email)
      .filter((e): e is string => Boolean(e));
    const unexpected = seedEmails.filter((e) => !liveEmails.includes(e));
    if (unexpected.length > 0) {
      // Loud, but NOT corrective: the dashboard wins.
      console.warn(
        JSON.stringify({
          level: 'warn',
          worker: 'cf-access-provisioner',
          event: 'access_group_membership_drift',
          group: name,
          expected_not_present: unexpected,
          live_count: liveEmails.length,
          message:
            'caller expected members that are not in the live group; NOT rewriting — the Cloudflare dashboard is the source of truth',
        }),
      );
    }
    return { id: existing.id, name, created: false, emails: liveEmails };
  }
  if (seedEmails.length === 0) {
    throw new Error(
      `provisioner: Access group "${name}" does not exist and no seed members were supplied. ` +
        `Refusing to create an EMPTY allowlist group — that would authorise no one while looking provisioned. ` +
        `Create the group in the Cloudflare Zero Trust dashboard first.`,
    );
  }
  const include: AccessRule[] = seedEmails.map((email) => ({ email: { email } }));
  const created = await client.createGroup({ name, include, exclude: [], require: [] });
  return { id: created.id, name, created: true, emails: seedEmails };
}

/** Map our IdP kind names to the account's identity_provider ids. */
function resolveAllowedIdpIds(kinds: IdpKind[], idps: { id: string; type: string }[]): string[] {
  if (kinds.length === 0) return []; // [] = all account IdPs (CF default)
  const typeFor: Record<IdpKind, string> = {
    otp: 'onetimepin',
    github: 'github',
    google: 'google',
  };
  const ids: string[] = [];
  for (const k of kinds) {
    const match = idps.find((i) => i.type === typeFor[k]);
    if (match) ids.push(match.id);
  }
  return ids;
}

/** Build the desired app payload from config (hardening attributes included). */
function appPayload(cfg: SpaAccessConfig, allowedIdpIds: string[]): Partial<AccessApp> {
  return {
    name: cfg.app_name,
    domain: cfg.domain,
    // self_hosted is the type for an HTTP SPA behind Access.
    ...({ type: 'self_hosted' } as Record<string, unknown>),
    session_duration: cfg.session_duration,
    allowed_idps: allowedIdpIds,
    auto_redirect_to_identity: cfg.auto_redirect,
    http_only_cookie_attribute: cfg.cookie.http_only,
    same_site_cookie_attribute: cfg.cookie.same_site,
  };
}

/** Build the allow policy include rules: the group + any override emails. */
function allowInclude(groupId: string, overrideEmails: string[]): AccessRule[] {
  const include: AccessRule[] = [{ group: { id: groupId } }];
  for (const email of overrideEmails) include.push({ email: { email } });
  return include;
}

/**
 * Idempotently provision the Access app + allow policy (+ optional service-token
 * non_identity policy) for a validated config. Group must already exist.
 */
export async function provisionApp(
  client: CfAccessClient,
  cfg: SpaAccessConfig,
  group: { id: string; name: string; created: boolean; emails: string[] },
): Promise<ProvisionResult> {
  const idps = await client.listIdps();
  const allowedIdpIds = resolveAllowedIdpIds(cfg.allowed_idps, idps);
  const payload = appPayload(cfg, allowedIdpIds);

  const existingApp = await client.findAppByDomain(cfg.domain);
  const app = existingApp
    ? await client.updateApp(existingApp.id, payload)
    : await client.createApp(payload);
  const appCreated = !existingApp;

  // Allow policy → group (+ overrides). Upsert by name.
  const allowName = `Allow ${group.name}`;
  const policies = await client.listPolicies(app.id);
  const existingAllow = policies.find((p) => p.decision === 'allow');
  const desiredAllow: AccessPolicy = {
    name: allowName,
    decision: 'allow',
    include: allowInclude(group.id, cfg.override_emails),
    exclude: [],
    require: [],
    precedence: 1,
  };
  const allow = existingAllow?.id
    ? await client.updatePolicy(app.id, existingAllow.id, desiredAllow)
    : await client.createPolicy(app.id, desiredAllow);
  const policyCreated = !existingAllow;

  // Optional service-token (non_identity) policy for machine/relay access.
  if (cfg.service_tokens.length > 0) {
    const hasSvc = policies.some((p) => p.decision === 'non_identity');
    if (!hasSvc) {
      await client.createPolicy(app.id, {
        name: 'Service token access',
        decision: 'non_identity',
        include: cfg.service_tokens.map((token_id) => ({ service_token: { token_id } })),
        exclude: [],
        require: [],
        precedence: 2,
      });
    }
  }

  let revoked = false;
  if (cfg.revoke_on_change && (appCreated || policyCreated)) {
    await client.revokeTokens(app.id);
    revoked = true;
  }

  return {
    app: { id: app.id, domain: app.domain, aud: app.aud, created: appCreated },
    group,
    policy: { id: allow.id ?? existingAllow?.id ?? '', created: policyCreated },
    revoked,
  };
}
