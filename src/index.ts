/**
 * @file index.ts
 * @description Worker HTTP surface. Routes:
 *   GET  /health                 — liveness
 *   POST /v1/access/provision    — validate config -> provision -> harden -> validate -> report
 *   POST /v1/access/validate     — live login round-trip for a hostname
 *   GET  /v1/access/audit        — account-wide authorization audit
 *   GET  /v1/access/membership   — live Access-group verdicts by email OR sub (no auth domain read)
 * All /v1 routes require bearer ADMIN_TOKEN. Every error path emits a
 * structured JSON line (loud-by-default).
 */

import { timingSafeTokenMatch } from './auth';
import { summarize, classifyApp, type AuditRow } from './audit';
import { CfAccessClient } from './cf-access';
import { resolveCfContext, type ProvisionerEnv } from './env';
import { assertHardened, assertIdps, HardeningError } from './harden';
import { CONSUMER_TTL_SECONDS, MembershipResolver } from './membership';
import { ensureGroup, provisionApp } from './provision';
import { parseAccessConfig, type SpaAccessConfig } from './schemas';
import { validateLive } from './validate-live';

/** JSON response helper. */
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Structured error log + JSON response (loud-by-default). */
function fail(route: string, status: number, message: string, extra?: unknown): Response {
  console.error(JSON.stringify({ level: 'error', worker: 'cf-access-provisioner', route, status, message, extra }));
  return json({ ok: false, error: message, detail: extra }, status);
}

/** Verify the inbound bearer matches ADMIN_TOKEN. */
function authorized(req: Request, env: ProvisionerEnv): boolean {
  const got = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ?? '';
  return timingSafeTokenMatch(got, env.ADMIN_TOKEN ?? '');
}

export default {
  async fetch(req: Request, env: ProvisionerEnv): Promise<Response> {
    const url = new URL(req.url);
    const { pathname } = url;

    if (pathname === '/health') {
      return json({ ok: true, worker: 'cf-access-provisioner' });
    }

    if (!pathname.startsWith('/v1/access/')) {
      return fail(pathname, 404, 'not found');
    }
    if (!authorized(req, env)) {
      return fail(pathname, 401, 'unauthorized: bearer ADMIN_TOKEN required');
    }

    let cf: CfAccessClient;
    try {
      const ctx = resolveCfContext(env);
      cf = new CfAccessClient(ctx.token, ctx.accountId);
    } catch (e) {
      return fail(pathname, 502, 'cloudflare context unavailable', String(e));
    }

    // The Zero Trust auth domain costs a serial CF API read (GET
    // /access/organizations), so only the routes that use it pay for it —
    // provision and validate. Membership and audit never read it. A failure
    // keeps the original contract: 502 "cloudflare context unavailable".
    const withAuthDomain = async (
      handle: (authDomain: string) => Promise<Response>,
    ): Promise<Response> => {
      let authDomain: string;
      try {
        authDomain = await cf.getAuthDomain();
      } catch (e) {
        return fail(pathname, 502, 'cloudflare context unavailable', String(e));
      }
      return handle(authDomain);
    };

    // POST /v1/access/provision
    if (pathname === '/v1/access/provision' && req.method === 'POST') {
      return withAuthDomain(async (authDomain) => {
        let cfg: SpaAccessConfig;
        try {
          cfg = parseAccessConfig(await req.json());
        } catch (e) {
          return fail(pathname, 400, 'invalid access config', (e as Error).message);
        }
        try {
          // No seed members: the shared allowlist group must already exist, with
          // its membership owned by the Cloudflare dashboard. Passing an email
          // list here previously meant a deploy could REWRITE that membership —
          // and with `override_emails` set it passed [], emptying the group and
          // locking every app that references it out at once.
          assertHardened(cfg, []);
          const group = await ensureGroup(cf, cfg.allowlist_group, []);
          const result = await provisionApp(cf, cfg, group);
          const policies = await cf.listPolicies(result.app.id);
          assertHardened(cfg, policies);
          assertIdps(cfg, await cf.listIdps(), authDomain);
          const live = await validateLive(cfg.domain, authDomain);
          return json({ ok: true, result, live });
        } catch (e) {
          if (e instanceof HardeningError) {
            return fail(pathname, 422, 'hardening failed', e.violations);
          }
          return fail(pathname, 500, 'provision failed', String(e));
        }
      });
    }

    // GET /v1/access/membership?email=a@b.test&groups=admins,staff
    // GET /v1/access/membership?sub=<access-user-id>&groups=admins
    //
    // `sub` is for identities whose JWT carries no email claim (for example a
    // name-only account). Exactly one of email|sub. The sub is resolved to the email on
    // the live Access user record (GET /access/users/:id) and that email is
    // evaluated against the live group like any other — never an allowlist,
    // never a name. A malformed sub is 400. A sub that is unknown, mismatched,
    // or whose record has no email, and any CF failure, is a fail-closed 502
    // (no `memberships`; the unknown/no-email cases also log a structured
    // `membership_sub_unresolved` line) — never a quiet false.
    //
    // The single authorization read for every consuming app. Callers pass the
    // identity from their Access JWT plus the group names they care about, and
    // get back a verdict per group. `groups` is caller-supplied rather than a
    // fixed enum so new Access groups created in the Cloudflare dashboard work
    // immediately, with no deploy here and no list to keep in sync.
    //
    // FAIL-CLOSED: any group that cannot be resolved (CF unreachable, group
    // absent, unmodelled rule kind) is reported in `errors` and forces HTTP 502.
    // A caller must treat 502 as "revoke the session and re-authenticate" —
    // never as "not a member". `memberships` is omitted entirely on 502 so a
    // careless caller cannot read a partial result as a clean deny.
    if (pathname === '/v1/access/membership' && req.method === 'GET') {
      const email = url.searchParams.get('email')?.trim() ?? '';
      const groups = (url.searchParams.get('groups') ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const sub = url.searchParams.get('sub')?.trim() ?? '';
      if (email && url.searchParams.has('sub')) {
        return fail(pathname, 400, 'pass email or sub, not both');
      }
      if (!email && !url.searchParams.has('sub')) {
        return fail(pathname, 400, 'email query param required');
      }
      if (!email && !sub) return fail(pathname, 400, 'sub query param must not be empty');
      if (groups.length === 0) return fail(pathname, 400, 'groups query param required');

      // Built per request on purpose: the resolver memoises for its own
      // lifetime with no TTL, so hoisting it would serve a stale snapshot
      // forever and make ttl_seconds false (pinned by index.test.ts).
      const resolver = new MembershipResolver(cf);

      let lookupEmail = email;
      if (!email) {
        let resolved: Awaited<ReturnType<MembershipResolver['emailForSub']>>;
        try {
          resolved = await resolver.emailForSub(sub);
        } catch (e) {
          return fail(pathname, 502, 'membership unresolvable — caller must revoke session', {
            sub: String(e),
          });
        }
        if ('unresolved' in resolved) {
          // "We could not tell" is never "not a member": a quiet false would
          // demote a real admin. Malformed input is the caller's bug (400);
          // everything else is a fail-closed 502 with no `memberships`.
          if (resolved.unresolved === 'sub_malformed') {
            return fail(pathname, 400, 'sub query param is malformed');
          }
          console.error(
            JSON.stringify({
              level: 'error',
              worker: 'cf-access-provisioner',
              event: 'membership_sub_unresolved',
              reason: resolved.unresolved,
              sub: sub.slice(0, 64),
              groups,
              verdict: 'unresolvable',
            }),
          );
          return fail(pathname, 502, 'membership unresolvable — caller must revoke session', {
            sub: `${resolved.unresolved}: sub could not be resolved to an Access identity`,
          });
        }
        lookupEmail = resolved.email;
      }
      const { memberships, errors } = await resolver.resolveAll(groups, lookupEmail);
      if (Object.keys(errors).length > 0) {
        return fail(pathname, 502, 'membership unresolvable — caller must revoke session', errors);
      }
      if (!email) {
        // Sub answer: never echo the email behind it, only that it resolved.
        return json({
          ok: true,
          sub,
          resolved: true,
          memberships,
          ttl_seconds: CONSUMER_TTL_SECONDS,
        });
      }
      return json({
        ok: true,
        email,
        memberships,
        // The consumer's memo window. The snapshot behind this verdict was
        // read from CF on this very request, so its age here is ~0 s.
        ttl_seconds: CONSUMER_TTL_SECONDS,
      });
    }

    // POST /v1/access/validate { hostname }
    if (pathname === '/v1/access/validate' && req.method === 'POST') {
      return withAuthDomain(async (authDomain) => {
        try {
          const reqRaw = (await req.json()) as unknown;
          const { hostname } = reqRaw as { hostname?: string };
          if (!hostname) return fail(pathname, 400, 'hostname required');
          return json({ ok: true, validation: await validateLive(hostname, authDomain) });
        } catch (e) {
          return fail(pathname, 500, 'validate failed', String(e));
        }
      });
    }

    // GET /v1/access/audit?expected=a@b,c@d  (`expected` is required: no
    // address lives in source, and an empty expectation would flag everything)
    if (pathname === '/v1/access/audit' && req.method === 'GET') {
      const expected = new Set(
        (url.searchParams.get('expected') ?? '')
          .split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean),
      );
      if (expected.size === 0) return fail(pathname, 400, 'expected query param required');
      try {
        const apps = await cf.listApps();
        const rows: AuditRow[] = [];
        for (const app of apps) {
          const policies = await cf.listPolicies(app.id);
          rows.push(classifyApp(app.domain, app.id, policies, expected));
        }
        return json({ ok: true, audit: summarize(rows) });
      } catch (e) {
        return fail(pathname, 500, 'audit failed', String(e));
      }
    }

    return fail(pathname, 405, 'method not allowed');
  },
};
