import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../index';
import type { ProvisionerEnv } from '../env';

/**
 * Minimal env with only the inbound bearer set.
 * @param token - the ADMIN_TOKEN value
 * @returns an env that has no Cloudflare credentials
 */
function env(token = 'secret-admin'): ProvisionerEnv {
  return { ADMIN_TOKEN: token, CF_API_TOKEN: '', CF_ACCOUNT_ID: '' };
}

/**
 * Read a JSON body in two steps (unknown, then the expected shape), per the
 * TS agent contract's no-direct-json-cast rule.
 * @param res - the response to read
 * @returns the parsed body, typed as the caller expects
 */
async function readJson<T>(res: Response): Promise<T> {
  const raw = (await res.json()) as unknown;
  return raw as T;
}

const call = (path: string, init?: RequestInit, e = env()) =>
  worker.fetch(new Request(`https://provisioner.example.com${path}`, init), e);

describe('worker routes', () => {
  it('GET /health answers without auth', async () => {
    const res = await call('/health');
    expect(res.status).toBe(200);
    const bodyRaw = await readJson<unknown>(res);
    const body = bodyRaw as { ok: boolean; worker: string };
    expect(body.ok).toBe(true);
    expect(body.worker).toBe('cf-access-provisioner');
  });

  it('404 for unknown path', async () => {
    expect((await call('/nope')).status).toBe(404);
  });

  it('401 on /v1/access/* without bearer', async () => {
    expect((await call('/v1/access/audit')).status).toBe(401);
  });

  it('401 on wrong bearer', async () => {
    const res = await call('/v1/access/audit', { headers: { Authorization: 'Bearer wrong' } });
    expect(res.status).toBe(401);
  });
});

/** Env that also carries Cloudflare credentials, so /v1/access/* reaches the stubbed API. */
function cfEnv(): ProvisionerEnv {
  return { ADMIN_TOKEN: 'secret-admin', CF_API_TOKEN: 'cf-token', CF_ACCOUNT_ID: 'acct-1' };
}

/**
 * Stub global fetch as the Cloudflare API: /access/groups serves a mutable
 * group table, /access/organizations serves an auth domain. Returns the list
 * of CF API paths requested, in order.
 */
function stubCf(
  groups: Array<{ id: string; name: string; include: unknown[] }>,
  extra: Record<string, unknown> = {},
): string[] {
  const seen: string[] = [];
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    const path = new URL(String(input)).pathname.replace(/^\/client\/v4\/accounts\/[^/]+/, '');
    seen.push(path);
    const ok = (result: unknown) =>
      new Response(JSON.stringify({ success: true, result }), { status: 200 });
    if (path === '/access/groups') return ok(structuredClone(groups));
    if (path === '/access/organizations') return ok({ auth_domain: 'team.cloudflareaccess.com' });
    if (path in extra) return ok(extra[path]);
    return new Response(JSON.stringify({ success: false, errors: [path] }), { status: 404 });
  });
  return seen;
}

const membership = (e: ProvisionerEnv) =>
  call(
    '/v1/access/membership?email=alice@example.com&groups=admins',
    { headers: { Authorization: 'Bearer secret-admin' } },
    e,
  );

describe('GET /v1/access/membership — fresh per request', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('reads Cloudflare groups on EVERY request — no cross-request cache', async () => {
    const groups = [
      { id: 'grp-admin', name: 'admins', include: [{ email: { email: 'alice@example.com' } }] },
    ];
    const seen = stubCf(groups);
    const e = cfEnv();

    const first = await readJson<{
      memberships: Record<string, boolean>;
    }>(await membership(e));
    expect(first.memberships['admins']).toBe(true);
    expect(seen.filter((p) => p === '/access/groups')).toHaveLength(1);

    // Someone removes the admin in the dashboard between two requests. The
    // very next request must see it — a hoisted resolver or module-level
    // snapshot would still answer true here.
    groups[0].include = [];
    const second = await readJson<{
      memberships: Record<string, boolean>;
    }>(await membership(e));
    expect(seen.filter((p) => p === '/access/groups')).toHaveLength(2);
    expect(second.memberships['admins']).toBe(false);
  });

  it('does not read /access/organizations (the auth domain is not its concern)', async () => {
    const seen = stubCf([
      { id: 'grp-admin', name: 'admins', include: [{ email: { email: 'alice@example.com' } }] },
    ]);
    const res = await membership(cfEnv());
    expect(res.status).toBe(200);
    expect(seen).not.toContain('/access/organizations');
    expect(seen).toEqual(['/access/groups']);
  });

  it('advertises ttl_seconds 60 — the consumer memo window, inside every contract band', async () => {
    stubCf([
      { id: 'grp-admin', name: 'admins', include: [{ email: { email: 'alice@example.com' } }] },
    ]);
    const body = await readJson<{ ok: boolean; ttl_seconds: number }>(await membership(cfEnv()));
    expect(body.ok).toBe(true);
    expect(body.ttl_seconds).toBe(60);
  });

  it('still fails closed with 502 when a group cannot be resolved', async () => {
    stubCf([]);
    const res = await membership(cfEnv());
    expect(res.status).toBe(502);
    const body = await readJson<{ ok: boolean; memberships?: unknown }>(res);
    expect(body.ok).toBe(false);
    expect(body).not.toHaveProperty('memberships');
  });

  it('validate still resolves the auth domain, and 502s when it cannot', async () => {
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(JSON.stringify({ success: false, errors: ['down'] }), { status: 503 }),
    );
    const res = await call(
      '/v1/access/validate',
      {
        method: 'POST',
        headers: { Authorization: 'Bearer secret-admin' },
        body: JSON.stringify({ hostname: 'x.example.com' }),
      },
      cfEnv(),
    );
    expect(res.status).toBe(502);
    expect((await readJson<{ error: string }>(res)).error).toBe('cloudflare context unavailable');
  });
});

const ADMIN_GROUP = {
  id: 'grp-admin',
  name: 'admins',
  include: [{ email: { email: 'alice@example.com' } }],
};
const AUTH = { Authorization: 'Bearer secret-admin' };

describe('worker — response contract and route guards', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('every response is JSON, and every failure logs one structured error line', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await call('/nope');
    expect(res.headers.get('Content-Type')).toBe('application/json');
    expect(await res.json()).toEqual({ ok: false, error: 'not found' });
    expect(log).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String(log.mock.calls[0][0]))).toEqual({
      level: 'error',
      worker: 'cf-access-provisioner',
      route: '/nope',
      status: 404,
      message: 'not found',
    });
  });

  it('401 names the required bearer', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await call('/v1/access/audit');
    expect((await readJson<{ error: string }>(res)).error).toBe(
      'unauthorized: bearer ADMIN_TOKEN required',
    );
  });

  it('accepts the bearer scheme case-insensitively with any whitespace, and only as a prefix', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubCf([ADMIN_GROUP], { '/access/apps': [] });
    const audit = (h: string) =>
      call('/v1/access/audit?expected=alice@example.com', { headers: { Authorization: h } }, cfEnv());
    expect((await audit('bearer secret-admin')).status).toBe(200);
    expect((await audit('Bearer   secret-admin')).status).toBe(200);
    expect((await audit('xBearer secret-admin')).status).toBe(401);
  });

  it('502 when the CF API context cannot be resolved', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await call('/v1/access/membership?email=a@b.c&groups=g', { headers: AUTH });
    expect(res.status).toBe(502);
    expect((await readJson<{ error: string }>(res)).error).toBe('cloudflare context unavailable');
  });

  it('405 on a known path with the wrong method, for every route', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const seen = stubCf([ADMIN_GROUP]);
    for (const [path, method] of [
      ['/v1/access/provision', 'GET'],
      ['/v1/access/membership?email=a@b.c&groups=admins', 'POST'],
      ['/v1/access/validate', 'GET'],
      ['/v1/access/audit', 'POST'],
    ] as const) {
      const res = await call(path, { method, headers: AUTH }, cfEnv());
      expect(res.status, `${method} ${path}`).toBe(405);
    }
    expect(seen).toEqual([]);
  });
});

describe('GET /v1/access/membership — input handling', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  const get = (q: string) => call(`/v1/access/membership${q}`, { headers: AUTH }, cfEnv());

  it('400 without an email, and without any group', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubCf([ADMIN_GROUP]);
    for (const [q, msg] of [
      ['?groups=admins', 'email query param required'],
      ['?email=%20%20&groups=admins', 'email query param required'],
      ['?email=alice@example.com', 'groups query param required'],
      ['?email=alice@example.com&groups=%20,%20,', 'groups query param required'],
    ]) {
      const res = await get(q);
      expect(res.status, q).toBe(400);
      expect((await readJson<{ error: string }>(res)).error, q).toBe(msg);
    }
  });

  it('trims the email and each group name, and drops empty group entries', async () => {
    stubCf([ADMIN_GROUP]);
    const res = await get('?email=%20alice@example.com%20&groups=%20admins%20,,');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      ok: true,
      email: 'alice@example.com',
      memberships: { 'admins': true },
      ttl_seconds: 60,
    });
  });

  it('502 names the revoke contract and details the unresolved group', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubCf([]);
    const body = await readJson<{
      error: string;
      detail: Record<string, string>;
    }>(await get('?email=alice@example.com&groups=admins'));
    expect(body.error).toBe('membership unresolvable — caller must revoke session');
    expect(body.detail['admins']).toMatch(/^group_missing: /);
  });
});

describe('provision / validate / audit routes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('provision: reads the auth domain, then 400s on an invalid config', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const seen = stubCf([]);
    const res = await call(
      '/v1/access/provision',
      { method: 'POST', headers: AUTH, body: JSON.stringify({ nope: true }) },
      cfEnv(),
    );
    expect(res.status).toBe(400);
    expect((await readJson<{ error: string }>(res)).error).toBe('invalid access config');
    expect(seen).toEqual(['/access/organizations']);
  });

  it('validate: 400 without a hostname, 500 on a non-JSON body', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubCf([]);
    const post = (body: string) =>
      call('/v1/access/validate', { method: 'POST', headers: AUTH, body }, cfEnv());
    const missing = await post('{}');
    expect(missing.status).toBe(400);
    expect((await readJson<{ error: string }>(missing)).error).toBe('hostname required');
    const broken = await post('not json');
    expect(broken.status).toBe(500);
    expect((await readJson<{ error: string }>(broken)).error).toBe('validate failed');
  });

  it('audit: classifies each app against the expected allowlist, without reading the auth domain', async () => {
    const seen = stubCf([], {
      '/access/apps': [{ id: 'app-1', domain: 'a.example.com' }],
      '/access/apps/app-1/policies': [
        { decision: 'allow', include: [{ email: { email: 'Extra@Example.com' } }] },
      ],
    });
    const audit = async (q: string) =>
      (
        await readJson<{
          ok: boolean;
          audit: { total: number; rows: Array<{ verdict: string; extraEmails: string[] }> };
        }>(await call(`/v1/access/audit${q}`, { headers: AUTH }, cfEnv()))
      ).audit;
    const byDefault = await audit('?expected=alice@example.com');
    expect(byDefault.total).toBe(1);
    expect(byDefault.rows[0]).toMatchObject({
      verdict: 'broad',
      extraEmails: ['extra@example.com'],
    });
    const allowlisted = await audit('?expected=%20EXTRA@example.com%20,');
    expect(allowlisted.rows[0]).toMatchObject({ verdict: 'only-allowlisted', extraEmails: [] });
    expect(seen).not.toContain('/access/organizations');
  });

  it('audit: 400 without expected, and no CF read happens', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const seen = stubCf([]);
    const res = await call('/v1/access/audit', { headers: AUTH }, cfEnv());
    expect(res.status).toBe(400);
    expect((await readJson<{ error: string }>(res)).error).toBe('expected query param required');
    expect(seen).not.toContain('/access/apps');
  });

  it('provision: a 48h session is refused before anything is written', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const writes: string[] = [];
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input)).pathname.replace(/^\/client\/v4\/accounts\/[^/]+/, '');
      if (init?.method && init.method !== 'GET') writes.push(`${init.method} ${path}`);
      const result = path === '/access/organizations' ? { auth_domain: 'team.cloudflareaccess.com' } : [];
      return new Response(JSON.stringify({ success: true, result }), { status: 200 });
    });
    const res = await call(
      '/v1/access/provision',
      {
        method: 'POST',
        headers: AUTH,
        body: JSON.stringify({
          domain: 'app.example.com',
          app_name: 'App',
          allowlist_group: 'allowed-users',
          session_duration: '48h',
        }),
      },
      cfEnv(),
    );
    expect(res.status).toBe(422);
    expect(writes).toEqual([]);
  });

  it('audit: 500 when the CF API fails mid-audit', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubCf([], { '/access/apps': [{ id: 'app-9', domain: 'z.example.com' }] });
    const res = await call('/v1/access/audit?expected=alice@example.com', { headers: AUTH }, cfEnv());
    expect(res.status).toBe(500);
    expect((await readJson<{ error: string }>(res)).error).toBe('audit failed');
  });
});

describe('GET /v1/access/membership — by Access sub', () => {
  const MEMBER_SUB = '11111111-aaaa-4aaa-8aaa-111111111111';
  const OTHER_SUB = '22222222-bbbb-4bbb-8bbb-222222222222';
  const GHOST_SUB = 'ffffffff-0000-5000-8000-000000000000';
  const users = {
    [`/access/users/${MEMBER_SUB}`]: {
      id: MEMBER_SUB,
      uid: MEMBER_SUB,
      email: 'Alice@EXAMPLE.com',
      name: 'ignored',
    },
    [`/access/users/${OTHER_SUB}`]: {
      id: OTHER_SUB,
      uid: OTHER_SUB,
      email: 'rando@example.com',
      name: 'alice@example.com',
    },
  };
  const bySub = (sub: string) =>
    call(`/v1/access/membership?sub=${sub}&groups=admins`, { headers: AUTH }, cfEnv());

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('a sub that resolves to a member returns true', async () => {
    stubCf([ADMIN_GROUP], users);
    const res = await bySub(MEMBER_SUB);
    expect(res.status).toBe(200);
    const body = await readJson<{
      resolved: boolean;
      memberships: Record<string, boolean>;
      email?: string;
    }>(res);
    expect(body.resolved).toBe(true);
    expect(body.memberships['admins']).toBe(true);
    expect(body).not.toHaveProperty('email');
  });

  it('a sub that resolves to a non-member returns false, even when the NAME looks like an admin email', async () => {
    stubCf([ADMIN_GROUP], users);
    const body = await readJson<{ resolved: boolean; memberships: Record<string, boolean> }>(
      await bySub(OTHER_SUB),
    );
    expect(body.resolved).toBe(true);
    expect(body.memberships['admins']).toBe(false);
  });

  it('an unknown sub is a 502 fail-closed error with no memberships, never a quiet false', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const seen = stubCf([ADMIN_GROUP], users);
    const res = await bySub(GHOST_SUB);
    expect(res.status).toBe(502);
    const body = await readJson<{ ok: boolean; error: string; detail: Record<string, string> }>(
      res,
    );
    expect(body.ok).toBe(false);
    expect(body.error).toBe('membership unresolvable — caller must revoke session');
    expect(body.detail.sub).toMatch(/sub_unknown/);
    expect(body).not.toHaveProperty('memberships');
    expect(seen).not.toContain('/access/groups');
    const lines = log.mock.calls.map((c) => String(c[0]));
    expect(
      lines.some(
        (l) => l.includes('"event":"membership_sub_unresolved"') && l.includes('sub_unknown'),
      ),
    ).toBe(true);
  });

  it('a record without an email is 502, and a malformed sub is 400; neither reaches groups', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const seen = stubCf([ADMIN_GROUP], {
      '/access/users/aaaaaaaa-1111-5111-8111-aaaaaaaaaaaa': {
        id: 'aaaaaaaa-1111-5111-8111-aaaaaaaaaaaa',
      },
    });
    const bad = await bySub('../groups');
    expect(bad.status).toBe(400);
    expect(await readJson<{ memberships?: unknown }>(bad)).not.toHaveProperty('memberships');
    const noEmail = await bySub('aaaaaaaa-1111-5111-8111-aaaaaaaaaaaa');
    expect(noEmail.status).toBe(502);
    const nb = await readJson<{ detail: Record<string, string> }>(noEmail);
    expect(nb.detail.sub).toMatch(/sub_no_email/);
    expect(nb).not.toHaveProperty('memberships');
    expect(seen).not.toContain('/access/groups');
    expect(log).toHaveBeenCalled();
  });

  it('a record whose id does not match the asked sub is 502 (sub_mismatch)', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubCf([ADMIN_GROUP], {
      [`/access/users/${MEMBER_SUB}`]: { id: OTHER_SUB, uid: OTHER_SUB, email: 'alice@example.com' },
    });
    const res = await bySub(MEMBER_SUB);
    expect(res.status).toBe(502);
    expect(await readJson<{ memberships?: unknown }>(res)).not.toHaveProperty('memberships');
  });

  it('a CF failure while reading the user is 502, never a quiet false', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response(JSON.stringify({ success: false, errors: ['down'] }), { status: 503 }),
    );
    const res = await bySub(MEMBER_SUB);
    expect(res.status).toBe(502);
    expect(await readJson<{ memberships?: unknown }>(res)).not.toHaveProperty('memberships');
  });

  it('email and sub together, or an empty sub, are 400', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubCf([ADMIN_GROUP], users);
    const both = await call(
      `/v1/access/membership?email=a@b.c&sub=${MEMBER_SUB}&groups=g`,
      { headers: AUTH },
      cfEnv(),
    );
    expect(both.status).toBe(400);
    const empty = await call('/v1/access/membership?sub=&groups=g', { headers: AUTH }, cfEnv());
    expect(empty.status).toBe(400);
  });

  it('the email path is unchanged: same body, no user read', async () => {
    const seen = stubCf([ADMIN_GROUP], users);
    const res = await membership(cfEnv());
    expect(await res.json()).toEqual({
      ok: true,
      email: 'alice@example.com',
      memberships: { 'admins': true },
      ttl_seconds: 60,
    });
    expect(seen).toEqual(['/access/groups']);
  });
});
