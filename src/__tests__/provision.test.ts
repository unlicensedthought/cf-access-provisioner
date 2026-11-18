import { describe, expect, it, vi } from 'vitest';
import type { AccessApp, AccessGroup, AccessIdp, AccessPolicy, CfAccessClient } from '../cf-access';
import { ensureGroup, provisionApp } from '../provision';
import { parseAccessConfig } from '../schemas';

/** Build a stateful fake CfAccessClient covering the methods provision uses. */
function fakeClient(seed: { groups?: AccessGroup[]; apps?: AccessApp[]; idps?: AccessIdp[] } = {}) {
  const groups: AccessGroup[] = seed.groups ?? [];
  const apps: AccessApp[] = seed.apps ?? [];
  const idps: AccessIdp[] = seed.idps ?? [
    { id: 'gh', name: 'GitHub', type: 'github' },
    { id: 'gg', name: 'Google', type: 'google' },
    { id: 'otp', name: '', type: 'onetimepin' },
  ];
  const policies: Record<string, AccessPolicy[]> = {};
  let n = 0;
  const api = {
    getGroupByName: vi.fn(async (name: string) => groups.find((g) => g.name === name) ?? null),
    createGroup: vi.fn(async (g: Omit<AccessGroup, 'id'>) => {
      const created = { ...g, id: `grp-${++n}` };
      groups.push(created);
      return created;
    }),
    updateGroup: vi.fn(async (id: string, g: Omit<AccessGroup, 'id'>) => {
      const idx = groups.findIndex((x) => x.id === id);
      groups[idx] = { ...g, id };
      return groups[idx];
    }),
    listIdps: vi.fn(async () => idps),
    findAppByDomain: vi.fn(async (d: string) => apps.find((a) => a.domain === d) ?? null),
    createApp: vi.fn(async (a: Partial<AccessApp>) => {
      const created = { id: `app-${++n}`, aud: `aud-${n}`, ...a } as AccessApp;
      apps.push(created);
      policies[created.id] = [];
      return created;
    }),
    updateApp: vi.fn(async (id: string, a: Partial<AccessApp>) => {
      const idx = apps.findIndex((x) => x.id === id);
      apps[idx] = { ...apps[idx], ...a };
      return apps[idx];
    }),
    listPolicies: vi.fn(async (appId: string) => policies[appId] ?? []),
    createPolicy: vi.fn(async (appId: string, p: AccessPolicy) => {
      const created = { ...p, id: `pol-${++n}` };
      if (!policies[appId]) policies[appId] = [];
      policies[appId].push(created);
      return created;
    }),
    updatePolicy: vi.fn(async (appId: string, pid: string, p: AccessPolicy) => {
      const arr = policies[appId] ?? [];
      const idx = arr.findIndex((x) => x.id === pid);
      arr[idx] = { ...p, id: pid };
      return arr[idx];
    }),
    revokeTokens: vi.fn(async () => ({})),
    _state: { groups, apps, policies },
  };
  return api as unknown as CfAccessClient & { _state: typeof api._state } & typeof api;
}

const cfg = (over = {}) =>
  parseAccessConfig({ domain: 'app.example.com', app_name: 'App', allowlist_group: 'allowed-users', ...over });

describe('ensureGroup', () => {
  it('creates a group when absent', async () => {
    const c = fakeClient();
    const g = await ensureGroup(c, 'allow', ['a@x.test']);
    expect(g.created).toBe(true);
    expect(c.createGroup).toHaveBeenCalledOnce();
    expect(c._state.groups[0].include).toEqual([{ email: { email: 'a@x.test' } }]);
  });

  it('NEVER rewrites the membership of a group that already exists', async () => {
    // This replaces a test that asserted the OPPOSITE ("replaces include when
    // the group exists"). That behaviour was the bug: the shared allowlist is
    // owned by the Cloudflare dashboard, and a deploy that reconciles it is a
    // second source of truth that silently fights the first.
    const c = fakeClient({
      groups: [{ id: 'grp-x', name: 'allow', include: [{ email: { email: 'old@x.test' } }] }],
    });
    const g = await ensureGroup(c, 'allow', ['new@x.test']);
    expect(g.created).toBe(false);
    expect(c.updateGroup).not.toHaveBeenCalled();
    expect(c._state.groups[0].include).toEqual([{ email: { email: 'old@x.test' } }]);
    // Reports what is LIVE, not what the caller wished for.
    expect(g.emails).toEqual(['old@x.test']);
  });

  it('BLOCKS the lockout: an empty email list cannot empty an existing group', async () => {
    // The exact live path — index.ts passed [] whenever override_emails was
    // set, which under the old code emptied the shared group and revoked every
    // app referencing it in a single API call.
    const c = fakeClient({
      groups: [
        {
          id: 'grp-x',
          name: 'staff',
          include: [{ email: { email: 'a@x.test' } }, { email: { email: 'b@x.test' } }],
        },
      ],
    });
    const g = await ensureGroup(c, 'staff', []);
    expect(c.updateGroup).not.toHaveBeenCalled();
    expect(c._state.groups[0].include).toHaveLength(2);
    expect(g.emails).toEqual(['a@x.test', 'b@x.test']);
  });

  it('REFUSES to create an empty allowlist group from nothing', async () => {
    // Creating an empty group would authorise no one while looking provisioned:
    // a silent outage that reads as success.
    const c = fakeClient();
    await expect(ensureGroup(c, 'admins', [])).rejects.toThrow(
      /Refusing to create an EMPTY/,
    );
    expect(c.createGroup).not.toHaveBeenCalled();
  });

  it('logs drift loudly instead of correcting it', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const c = fakeClient({
      groups: [{ id: 'grp-x', name: 'allow', include: [{ email: { email: 'old@x.test' } }] }],
    });
    await ensureGroup(c, 'allow', ['missing@x.test']);
    expect(warn).toHaveBeenCalled();
    const line = JSON.parse(warn.mock.calls[0][0] as string);
    expect(line.event).toBe('access_group_membership_drift');
    expect(line.expected_not_present).toEqual(['missing@x.test']);
    expect(c.updateGroup).not.toHaveBeenCalled();
    warn.mockRestore();
  });
});

describe('provisionApp', () => {
  it('creates app + allow policy referencing the group, then revokes', async () => {
    const c = fakeClient();
    const group = await ensureGroup(c, 'allowed-users', ['a@x.test']);
    const r = await provisionApp(c, cfg({ allowed_idps: ['github', 'google'] }), group);
    expect(r.app.created).toBe(true);
    expect(r.policy.created).toBe(true);
    expect(r.revoked).toBe(true);
    expect(c.createApp).toHaveBeenCalledOnce();
    const created = c.createApp.mock.calls[0][0];
    expect(created.allowed_idps).toEqual(['gh', 'gg']);
    expect(created.http_only_cookie_attribute).toBe(true);
    const pol = c._state.policies[r.app.id][0];
    expect(pol.include).toContainEqual({ group: { id: group.id } });
  });

  it('updates an existing app (idempotent, no second create)', async () => {
    const c = fakeClient({
      apps: [{ id: 'app-existing', name: 'App', domain: 'app.example.com', aud: 'aud-e' }],
    });
    const group = await ensureGroup(c, 'allowed-users', ['a@x.test']);
    const r = await provisionApp(c, cfg(), group);
    expect(r.app.created).toBe(false);
    expect(c.createApp).not.toHaveBeenCalled();
    expect(c.updateApp).toHaveBeenCalledOnce();
  });
});
