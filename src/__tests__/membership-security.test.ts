/**
 * @file membership-security.test.ts
 * @description Mutation-driven behavioural tests for the fail-closed admin
 * resolver. Each test names the attack or bug it catches; none reads source text.
 *
 * `emailForSub` (the JWT `sub` -> email lookup that feeds the admin decision)
 * had ZERO coverage before this file: a Stryker run showed every mutant in it
 * as NoCoverage.
 */

import { describe, expect, it, vi } from 'vitest';
import type { AccessGroup, AccessUser, CfAccessClient } from '../cf-access';
import { MembershipResolver, MembershipUnresolvable } from '../membership';

const SUB = 'a1b2c3d4-0000-4000-8000-123456789abc';

/** Stub client exposing only the calls the resolver makes. */
function client(opts: {
  user?: Partial<AccessUser> | null;
  userThrows?: Error;
  groups?: AccessGroup[];
}) {
  const getUserById = vi.fn(async (_id: string) => {
    if (opts.userThrows) throw opts.userThrows;
    return (opts.user ?? null) as AccessUser | null;
  });
  const groups = opts.groups ?? [];
  return {
    getUserById,
    listGroups: vi.fn(async () => groups),
    getGroupByName: vi.fn(async (n: string) => groups.find((g) => g.name === n) ?? null),
  } as unknown as CfAccessClient & { getUserById: typeof getUserById };
}

describe('emailForSub: the sub is a lookup key, never trusted input', () => {
  it('refuses a path-traversal sub and never calls Cloudflare with it (URL injection)', async () => {
    const c = client({ user: { id: SUB, email: 'a@b.test' } });
    const r = await new MembershipResolver(c).emailForSub('../apps/00000000');
    expect(r).toEqual({ unresolved: 'sub_malformed' });
    expect(c.getUserById).not.toHaveBeenCalled();
  });

  it('refuses a valid-looking sub with a suffix: the pattern is anchored at the end', async () => {
    const c = client({ user: { id: SUB, email: 'a@b.test' } });
    expect(await new MembershipResolver(c).emailForSub(`${SUB}/../x`)).toEqual({
      unresolved: 'sub_malformed',
    });
    expect(c.getUserById).not.toHaveBeenCalled();
  });

  it('refuses a sub with a prefix: the pattern is anchored at the start', async () => {
    const c = client({ user: { id: SUB, email: 'a@b.test' } });
    expect(await new MembershipResolver(c).emailForSub(`/${SUB}`)).toEqual({
      unresolved: 'sub_malformed',
    });
    expect(c.getUserById).not.toHaveBeenCalled();
  });

  it('enforces the 8..64 length window exactly', async () => {
    const lookup = async (sub: string) => {
      const c = client({ user: { id: sub, email: 'a@b.test' } });
      return new MembershipResolver(c).emailForSub(sub);
    };
    expect(await lookup('a'.repeat(7))).toEqual({ unresolved: 'sub_malformed' });
    expect(await lookup('a'.repeat(8))).toEqual({ email: 'a@b.test' });
    expect(await lookup('a'.repeat(64))).toEqual({ email: 'a@b.test' });
    expect(await lookup('a'.repeat(65))).toEqual({ unresolved: 'sub_malformed' });
  });

  it('accepts a real UUID sub and resolves it to the record email', async () => {
    const c = client({ user: { id: SUB, email: 'alice@example.com' } });
    expect(await new MembershipResolver(c).emailForSub(SUB)).toEqual({ email: 'alice@example.com' });
    expect(c.getUserById).toHaveBeenCalledWith(SUB);
  });

  it('an unknown sub (CF 404) is sub_unknown, not a membership', async () => {
    const c = client({ user: null });
    expect(await new MembershipResolver(c).emailForSub(SUB)).toEqual({ unresolved: 'sub_unknown' });
  });

  it('REFUSES a record whose id is another identity: a swapped lookup must not lend its email', async () => {
    const c = client({ user: { id: 'ffffffff-0000-4000-8000-ffffffffffff', email: 'admin@x.test' } });
    expect(await new MembershipResolver(c).emailForSub(SUB)).toEqual({
      unresolved: 'sub_mismatch',
    });
  });

  it('REFUSES a record whose uid disagrees even when its id matches', async () => {
    const c = client({
      user: { id: SUB, uid: 'ffffffff-0000-4000-8000-ffffffffffff', email: 'admin@x.test' },
    });
    expect(await new MembershipResolver(c).emailForSub(SUB)).toEqual({
      unresolved: 'sub_mismatch',
    });
  });

  it('accepts a record whose uid equals the sub, and one with no uid at all', async () => {
    const withUid = client({ user: { id: SUB, uid: SUB, email: 'a@b.test' } });
    expect(await new MembershipResolver(withUid).emailForSub(SUB)).toEqual({ email: 'a@b.test' });
    const noUid = client({ user: { id: SUB, email: 'a@b.test' } });
    expect(await new MembershipResolver(noUid).emailForSub(SUB)).toEqual({ email: 'a@b.test' });
  });

  it('a record with no id field cannot vouch for itself', async () => {
    const c = client({ user: { email: 'a@b.test' } });
    expect(await new MembershipResolver(c).emailForSub(SUB)).toEqual({
      unresolved: 'sub_mismatch',
    });
  });

  it.each([
    ['missing', undefined],
    ['non-string', 42],
    ['empty', ''],
    ['whitespace only', '   '],
    ['no at-sign', 'not-an-address'],
    ['empty domain', 'user@'],
  ])('a record whose email is %s is sub_no_email (never an empty-string member)', async (_n, email) => {
    const c = client({ user: { id: SUB, email } as Partial<AccessUser> });
    expect(await new MembershipResolver(c).emailForSub(SUB)).toEqual({
      unresolved: 'sub_no_email',
    });
  });

  it('returns the email trimmed and lower-cased so the group evaluator compares like with like', async () => {
    const c = client({ user: { id: SUB, email: '  ALICE@EXAMPLE.COM ' } });
    expect(await new MembershipResolver(c).emailForSub(SUB)).toEqual({ email: 'alice@example.com' });
  });

  it('a Cloudflare outage THROWS: an unreachable lookup is not "not a member"', async () => {
    const c = client({ userThrows: new Error('CF 503') });
    await expect(new MembershipResolver(c).emailForSub(SUB)).rejects.toThrow('CF 503');
  });
});

describe('malformed rules are MembershipUnresolvable, never a TypeError or a silent skip', () => {
  const unresolved = async (group: AccessGroup, who = 'u@x.test') => {
    const r = new MembershipResolver(client({ groups: [group] }));
    return r.isMember(group.name, who).then(
      () => null,
      (e: unknown) => e,
    );
  };
  const g = (rule: Record<string, unknown>): AccessGroup =>
    ({ id: 'g1', name: 'admins', include: [rule] }) as unknown as AccessGroup;

  it.each([
    ['email', { email: null }],
    ['email_domain', { email_domain: null }],
    ['group', { group: null }],
  ])('a null %s rule body is a typed fail-closed error', async (_k, rule) => {
    const e = await unresolved(g(rule));
    expect(e).toBeInstanceOf(MembershipUnresolvable);
    expect((e as MembershipUnresolvable).reason).toBe('unknown_rule');
    expect((e as MembershipUnresolvable).group).toBe('admins');
  });

  it('names the group and the offending rule kind so a human can find it', async () => {
    const e = (await unresolved(g({ ip: { ip: '1.2.3.4' } }))) as MembershipUnresolvable;
    expect(e).toBeInstanceOf(MembershipUnresolvable);
    expect(e.name).toBe('MembershipUnresolvable');
    expect(e.reason).toBe('unknown_rule');
    expect(e.message).toContain('"admins"');
    expect(e.message).toContain('"ip"');
  });

  it('a two-key rule is unknown_rule and names its keys', async () => {
    const e = (await unresolved(g({ email: { email: 'a@b.test' }, everyone: {} }))) as Error;
    expect(e).toBeInstanceOf(MembershipUnresolvable);
    expect((e as MembershipUnresolvable).reason).toBe('unknown_rule');
    expect(e.message).toContain('email,everyone');
  });

  it.each([
    ['email', { email: {} }, 'email rule with no address'],
    ['email_domain', { email_domain: {} }, 'email_domain rule with no domain'],
    ['group', { group: {} }, 'nested group rule with no id'],
  ])('an empty %s body explains itself', async (_k, rule, text) => {
    const e = (await unresolved(g(rule))) as MembershipUnresolvable;
    expect(e).toBeInstanceOf(MembershipUnresolvable);
    expect(e.reason).toBe('unknown_rule');
    expect(e.message).toContain(text);
  });

  it('a CF read failure names the group it was reading', async () => {
    const c = client({});
    (c.getGroupByName as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('boom'));
    const e = (await new MembershipResolver(c)
      .isMember('admins', 'u@x.test')
      .catch((x) => x)) as MembershipUnresolvable;
    expect(e.reason).toBe('cf_unreachable');
    expect(e.message).toContain('"admins"');
    expect(e.message).toContain('boom');
  });

  it('a nested-group read failure names the nested id and the referencing group', async () => {
    const parent: AccessGroup = {
      id: 'p',
      name: 'parent',
      include: [{ group: { id: 'child-id' } }],
    } as AccessGroup;
    const c = client({ groups: [parent] });
    (c.listGroups as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('down'));
    const e = (await new MembershipResolver(c)
      .isMember('parent', 'u@x.test')
      .catch((x) => x)) as MembershipUnresolvable;
    expect(e.reason).toBe('cf_unreachable');
    expect(e.message).toContain('"child-id"');
    expect(e.message).toContain('"parent"');
    expect(e.message).toContain('down');
  });

  it('a nested cycle names the group that closes it', async () => {
    const a: AccessGroup = {
      id: 'a',
      name: 'ga',
      include: [{ group: { id: 'b' } }],
    } as AccessGroup;
    const b: AccessGroup = {
      id: 'b',
      name: 'gb',
      include: [{ group: { id: 'a' } }],
    } as AccessGroup;
    const e = (await new MembershipResolver(client({ groups: [a, b] }))
      .isMember('ga', 'u@x.test')
      .catch((x) => x)) as MembershipUnresolvable;
    expect(e.reason).toBe('cycle');
    expect(e.message).toContain('cycle');
    expect(e.message).toContain('"ga"');
  });
});

describe('rule matching edge cases that decide who is an admin', () => {
  const only = (rule: Record<string, unknown>): AccessGroup =>
    ({ id: 'g', name: 'admins', include: [rule] }) as unknown as AccessGroup;

  it('an email_domain rule cannot be satisfied by gluing a rule containing "@" onto a different domain', async () => {
    // Bug caught: replace(/^@/) widened to replace(/@/) turns the configured
    // value "a@evil.test" into "aevil.test", which then admits anyone at aevil.test.
    const r = new MembershipResolver(
      client({ groups: [only({ email_domain: { domain: 'a@evil.test' } })] }),
    );
    expect(await r.isMember('admins', 'u@aevil.test')).toBe(false);
  });

  it('an address ending in "@" has no domain and matches no domain rule', async () => {
    const r = new MembershipResolver(client({ groups: [only({ email_domain: { domain: '' } })] }));
    await expect(r.isMember('admins', 'user@')).rejects.toBeInstanceOf(
      MembershipUnresolvable,
    );
    const r2 = new MembershipResolver(
      client({ groups: [only({ email_domain: { domain: 'x.co' } })] }),
    );
    expect(await r2.isMember('admins', 'user@')).toBe(false);
  });

  it('resolveAll turns an unexpected non-typed failure into an error entry, not a false', async () => {
    const r = new MembershipResolver(client({ groups: [only({ everyone: {} })] }));
    const out = await r.resolveAll(['admins'], undefined as unknown as string);
    expect(out.memberships).toEqual({});
    expect(out.errors['admins']).toMatch(/^cf_unreachable: /);
  });
});
