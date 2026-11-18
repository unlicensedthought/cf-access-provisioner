/**
 * @file membership.test.ts
 * @description Negative-proof suite for the Access-group membership gate.
 *
 * A gate that cannot be SHOWN to block is not a gate. Every allow case below is
 * paired with a deny case, and every unresolvable case asserts that the answer
 * is an ERROR rather than a quiet `false` — because `false` would silently
 * demote a real admin and look exactly like a legitimate denial.
 */

import { describe, expect, it, vi } from 'vitest';
import type { AccessGroup, CfAccessClient } from '../cf-access';
import { MembershipResolver, MembershipUnresolvable } from '../membership';

/** Build a stub CfAccessClient backed by an in-memory group table. */
function stubClient(groups: AccessGroup[], opts: { throwOn?: 'byName' | 'list' } = {}) {
  const listGroups = vi.fn(async () => {
    if (opts.throwOn === 'list') throw new Error('CF 503');
    return groups;
  });
  const getGroupByName = vi.fn(async (name: string) => {
    if (opts.throwOn === 'byName') throw new Error('CF 503');
    return groups.find((g) => g.name === name) ?? null;
  });
  return { listGroups, getGroupByName } as unknown as CfAccessClient & {
    listGroups: typeof listGroups;
    getGroupByName: typeof getGroupByName;
  };
}

const ADMIN: AccessGroup = {
  id: 'grp-admin',
  name: 'admins',
  include: [
    { email: { email: 'alice@example.com' } },
    { email: { email: 'bob@example.com' } },
  ],
};

const USERS: AccessGroup = {
  id: 'grp-users',
  name: 'staff',
  include: [
    { email: { email: 'carol@example.org' } },
    { email_domain: { domain: 'example.com' } },
  ],
};

describe('MembershipResolver — allow/deny', () => {
  it('ALLOWS a listed email', async () => {
    const r = new MembershipResolver(stubClient([ADMIN]));
    expect(await r.isMember('admins', 'alice@example.com')).toBe(true);
  });

  it('DENIES an email that is not in the group (negative proof)', async () => {
    const r = new MembershipResolver(stubClient([ADMIN]));
    expect(await r.isMember('admins', 'attacker@evil.test')).toBe(false);
  });

  it('DENIES a non-admin who is only in the users group (privilege separation)', async () => {
    const r = new MembershipResolver(stubClient([ADMIN, USERS]));
    expect(await r.isMember('admins', 'carol@example.org')).toBe(false);
    expect(await r.isMember('staff', 'carol@example.org')).toBe(true);
  });

  it('matches case-insensitively, as Cloudflare does', async () => {
    const r = new MembershipResolver(stubClient([ADMIN]));
    expect(await r.isMember('admins', 'ALICE@EXAMPLE.COM')).toBe(true);
  });

  it('ALLOWS via email_domain and DENIES a lookalike domain', async () => {
    const r = new MembershipResolver(stubClient([USERS]));
    expect(await r.isMember('staff', 'anyone@example.com')).toBe(true);
    // Suffix confusion must not pass: evil-example.com is a different domain.
    expect(await r.isMember('staff', 'x@evil-example.com')).toBe(false); // gate:allow-line: test fixture
    // Subdomain is likewise a different domain.
    expect(await r.isMember('staff', 'x@sub.example.com')).toBe(false); // gate:allow-line: test fixture
  });

  it('honors exclude over include', async () => {
    const g: AccessGroup = {
      id: 'g',
      name: 'grp',
      include: [{ email_domain: { domain: 'example.com' } }],
      exclude: [{ email: { email: 'fired@example.com' } }],
    };
    const r = new MembershipResolver(stubClient([g]));
    expect(await r.isMember('grp', 'ok@example.com')).toBe(true);
    expect(await r.isMember('grp', 'fired@example.com')).toBe(false);
  });

  it('resolves nested group rules', async () => {
    const parent: AccessGroup = {
      id: 'parent',
      name: 'parent',
      include: [{ group: { id: 'grp-admin' } }],
    };
    const r = new MembershipResolver(stubClient([parent, ADMIN]));
    expect(await r.isMember('parent', 'alice@example.com')).toBe(true);
    expect(await r.isMember('parent', 'nobody@example.com')).toBe(false);
  });
});

describe('MembershipResolver — fail closed, never a silent false', () => {
  it('THROWS (not false) when Cloudflare is unreachable', async () => {
    const r = new MembershipResolver(stubClient([ADMIN], { throwOn: 'byName' }));
    await expect(r.isMember('admins', 'alice@example.com')).rejects.toBeInstanceOf(
      MembershipUnresolvable,
    );
    await expect(r.isMember('admins', 'alice@example.com')).rejects.toMatchObject({
      reason: 'cf_unreachable',
    });
  });

  it('THROWS (not false) when the group does not exist', async () => {
    const r = new MembershipResolver(stubClient([]));
    await expect(r.isMember('admins', 'alice@example.com')).rejects.toMatchObject({
      reason: 'group_missing',
    });
  });

  it('THROWS on a rule kind it cannot decide, rather than ignoring the rule', async () => {
    // The live-drift scenario: someone adds a device-posture or IdP-group rule
    // in the dashboard. Skipping it would silently WIDEN or NARROW access.
    for (const rule of [
      { ip: { ip: '192.0.2.1/32' } },
      { email_list: { id: 'list-1' } },
      { azureAD: { id: 'x', identity_provider_id: 'y' } },
      { device_posture: { integration_uid: 'z' } },
    ]) {
      const g: AccessGroup = { id: 'g', name: 'grp', include: [rule] };
      const r = new MembershipResolver(stubClient([g]));
      await expect(r.isMember('grp', 'alice@example.com')).rejects.toMatchObject({
        reason: 'unknown_rule',
      });
    }
  });

  it('THROWS on an unknown rule even when an earlier rule already matched', async () => {
    // Guards the short-circuit trap: `include: [matching, unknown]` must NOT
    // return true early and skip the rule it does not understand.
    const g: AccessGroup = {
      id: 'g',
      name: 'grp',
      include: [{ email: { email: 'alice@example.com' } }, { ip: { ip: '192.0.2.1/32' } }],
    };
    const r = new MembershipResolver(stubClient([g]));
    await expect(r.isMember('grp', 'alice@example.com')).rejects.toMatchObject({
      reason: 'unknown_rule',
    });
  });

  it('THROWS on a nested group cycle instead of recursing forever', async () => {
    const a: AccessGroup = { id: 'a', name: 'a', include: [{ group: { id: 'b' } }] };
    const b: AccessGroup = { id: 'b', name: 'b', include: [{ group: { id: 'a' } }] };
    const r = new MembershipResolver(stubClient([a, b]));
    await expect(r.isMember('a', 'x@y.test')).rejects.toMatchObject({ reason: 'cycle' });
  });

  it('resolveAll reports errors separately and never as false', async () => {
    const r = new MembershipResolver(stubClient([ADMIN]));
    const { memberships, errors } = await r.resolveAll(
      ['admins', 'does-not-exist'],
      'alice@example.com',
    );
    expect(memberships['admins']).toBe(true);
    expect(memberships).not.toHaveProperty('does-not-exist');
    expect(errors['does-not-exist']).toMatch(/group_missing/);
  });
});

describe('MembershipResolver — per-request lifetime, no TTL cache', () => {
  it('shares one listGroups read across the nested lookups of a single request', async () => {
    const a: AccessGroup = { id: 'a', name: 'a', include: [{ group: { id: 'grp-admin' } }] };
    const b: AccessGroup = { id: 'b', name: 'b', include: [{ group: { id: 'grp-admin' } }] };
    const client = stubClient([a, b, ADMIN]);
    const r = new MembershipResolver(client);
    const { memberships, errors } = await r.resolveAll(['a', 'b'], 'alice@example.com');
    expect(errors).toEqual({});
    expect(memberships).toEqual({ a: true, b: true });
    // The nested grp-admin lookup is read once and then served from this
    // request's memo for the second group.
    expect(client.listGroups).toHaveBeenCalledTimes(1);
    // ...and group "b" itself came from that same read, not a second fetch.
    expect(client.getGroupByName).toHaveBeenCalledTimes(1);
  });

  it('a group named twice in one request is read once', async () => {
    const client = stubClient([ADMIN]);
    const r = new MembershipResolver(client);
    await r.resolveAll(['admins', 'admins'], 'alice@example.com');
    expect(client.getGroupByName).toHaveBeenCalledTimes(1);
  });

  it('a new resolver (a new request) re-reads Cloudflare: a removal takes effect on the next request', async () => {
    const groups: AccessGroup[] = [{ ...ADMIN, include: [{ email: { email: 'alice@example.com' } }] }];
    const client = stubClient(groups);

    expect(await new MembershipResolver(client).isMember('admins', 'alice@example.com')).toBe(
      true,
    );
    groups[0].include = []; // someone removes them in the dashboard
    expect(await new MembershipResolver(client).isMember('admins', 'alice@example.com')).toBe(
      false,
    );
    expect(client.getGroupByName).toHaveBeenCalledTimes(2);
  });
});

describe('MembershipResolver — rule edge cases', () => {
  const one = (rule: Record<string, unknown>, extra: Partial<AccessGroup> = {}) =>
    new MembershipResolver(stubClient([{ id: 'g', name: 'grp', include: [rule], ...extra }]));

  it('everyone matches any identity', async () => {
    expect(await one({ everyone: {} }).isMember('grp', 'anyone@anywhere.test')).toBe(true);
  });

  it('trims and lower-cases both sides of an email comparison', async () => {
    const r = one({ email: { email: 'Alice@EXAMPLE.com' } });
    expect(await r.isMember('grp', '  alice@example.COM  ')).toBe(true);
  });

  it('email_domain tolerates a leading @ and refuses a string with no usable domain', async () => {
    const r = one({ email_domain: { domain: '@Example.com' } });
    expect(await r.isMember('grp', 'a@example.com')).toBe(true);
    // No "@" at all: the whole string must not be mistaken for the domain.
    expect(await r.isMember('grp', 'example.com')).toBe(false);
    // Trailing "@": there is no domain part.
    const bare = one({ email_domain: { domain: 'example.com@' } });
    expect(await bare.isMember('grp', 'example.com@')).toBe(false);
  });

  it('THROWS unknown_rule on a malformed rule of a supported kind', async () => {
    for (const rule of [{ email: {} }, { email_domain: {} }, { group: {} }]) {
      await expect(one(rule).isMember('grp', 'alice@example.com')).rejects.toMatchObject({
        reason: 'unknown_rule',
        group: 'grp',
      });
    }
  });

  it('THROWS unknown_rule on a rule object carrying two kinds', async () => {
    const r = one({ email: { email: 'alice@example.com' }, everyone: {} });
    await expect(r.isMember('grp', 'alice@example.com')).rejects.toThrow(
      /rule with 2 keys \(email,everyone\)/,
    );
  });

  it('require: every require rule must match', async () => {
    const r = one(
      { email_domain: { domain: 'example.com' } },
      { require: [{ email: { email: 'boss@example.com' } }] },
    );
    expect(await r.isMember('grp', 'boss@example.com')).toBe(true);
    expect(await r.isMember('grp', 'staff@example.com')).toBe(false);
  });

  it('nested lookups fail closed: CF down is cf_unreachable, an unknown id is group_missing', async () => {
    const parent: AccessGroup = { id: 'p', name: 'parent', include: [{ group: { id: 'ghost' } }] };
    const down = new MembershipResolver(stubClient([parent], { throwOn: 'list' }));
    await expect(down.isMember('parent', 'x@y.z')).rejects.toMatchObject({
      reason: 'cf_unreachable',
      group: 'parent',
    });
    const missing = new MembershipResolver(stubClient([parent]));
    await expect(missing.isMember('parent', 'x@y.z')).rejects.toMatchObject({
      reason: 'group_missing',
      message: 'nested group "ghost" (from "parent") does not exist',
    });
  });

  it('resolveAll logs each unresolvable group as one structured line', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { errors } = await new MembershipResolver(stubClient([])).resolveAll(['absent'], 'x@y.z');
    expect(errors.absent).toBe('group_missing: group "absent" does not exist in Cloudflare Access');
    expect(JSON.parse(String(log.mock.calls[0][0]))).toEqual({
      level: 'error',
      worker: 'cf-access-provisioner',
      event: 'membership_unresolvable',
      group: 'absent',
      reason: 'group_missing',
      message: 'group "absent" does not exist in Cloudflare Access',
    });
    log.mockRestore();
  });
});
