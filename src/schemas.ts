/**
 * @file schemas.ts
 * @description Zod schema for an SPA's Access provisioning config — the single
 * input contract any SPA repo posts to this service. Hardening defaults live here so
 * callers cannot accidentally ship an insecure app; email_domain wildcards are
 * rejected at parse time (the 80-app footgun this service exists to kill).
 */

import { z } from 'zod';

/** Identity providers this service knows how to enable on an Access app. */
export const IDP_KINDS = ['otp', 'github', 'google'] as const;

/** A login method offered on the Access app. */
export type IdpKind = (typeof IDP_KINDS)[number];

/**
 * SPA access config. Required: a hostname, a name and the allowlist group. Everything
 * else has a hardened default so the simplest valid config is already safe.
 */
export const SpaAccessConfigSchema = z
  .object({
    /** Hostname the Access app guards, e.g. "app.example.com". */
    domain: z
      .string()
      .min(3)
      .regex(/^[a-z0-9.*-]+(\.[a-z0-9.*-]+)+$/, 'domain must be a bare hostname'),
    /** Human-readable app name shown in the Access dashboard + launcher. */
    app_name: z.string().min(1).max(120),
    /** Login methods to allow. Empty array = all account IdPs (CF default). */
    allowed_idps: z.array(z.enum(IDP_KINDS)).default([]),
    /** Session lifetime. Capped by the hardening enforcer. */
    session_duration: z.string().default('24h'),
    /**
     * Name of the shared Access GROUP that holds the email allowlist (single
     * source of truth). When set, the app's allow policy references the group. Required: it must already exist.
     */
    allowlist_group: z.string().min(1),
    /** Per-app extra emails added to the allow policy (in addition to the group). */
    override_emails: z.array(z.string()).default([]),
    /** Service-token ids granted non_identity (machine/relay) access. */
    service_tokens: z.array(z.string().min(1)).default([]),
    /** Cookie hardening. */
    cookie: z
      .object({
        http_only: z.boolean().default(true),
        same_site: z.enum(['strict', 'lax']).default('lax'),
      })
      .default({ http_only: true, same_site: 'lax' }),
    /** Single-IdP auto-redirect (skip the chooser). Default false = chooser. */
    auto_redirect: z.boolean().default(false),
    /** Revoke existing sessions after a policy change so removals take effect now. */
    revoke_on_change: z.boolean().default(true),
  })
  .strict()
  .superRefine((cfg, ctx) => {
    // Hard ban: email_domain wildcards are expressed as bare "@domain" or "*"
    // entries in override_emails. Checked before the email-format check so the
    // caller gets the wildcard message, not a generic "invalid email".
    for (const e of cfg.override_emails) {
      if (e.startsWith('@') || e.includes('*')) {
        ctx.addIssue({
          code: 'custom',
          path: ['override_emails'],
          message: `email_domain wildcards are banned: "${e}". Use explicit emails or the allowlist_group.`,
        });
      } else if (!z.email().safeParse(e).success) {
        ctx.addIssue({
          code: 'custom',
          path: ['override_emails'],
          message: `not an email address: "${e}"`,
        });
      }
    }
  });

/** Validated SPA access config. */
export type SpaAccessConfig = z.infer<typeof SpaAccessConfigSchema>;

/**
 * Parse + validate raw input into a hardened SpaAccessConfig.
 *
 * @param raw - untrusted request body
 * @returns the parsed config
 * @throws ZodError on any violation (caller maps to HTTP 400)
 */
export function parseAccessConfig(raw: unknown): SpaAccessConfig {
  return SpaAccessConfigSchema.parse(raw);
}
