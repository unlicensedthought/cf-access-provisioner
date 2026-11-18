import { describe, expect, it } from 'vitest';
import type { AccessPolicy } from '../cf-access';
import { classifyApp, summarize } from '../audit';

const EXPECTED = new Set(['alice@example.com', 'bob@example.com']);

describe('classifyApp', () => {
  it('only-allowlisted when policy includes exactly the expected emails', () => {
    const p: AccessPolicy[] = [
      {
        name: 'Allow',
        decision: 'allow',
        include: [
          { email: { email: 'alice@example.com' } },
          { email: { email: 'bob@example.com' } },
        ],
      },
    ];
    expect(classifyApp('a.com', 'id', p, EXPECTED).verdict).toBe('only-allowlisted');
  });

  it('only-allowlisted when group-only', () => {
    const p: AccessPolicy[] = [
      { name: 'Allow', decision: 'allow', include: [{ group: { id: 'grp-0001' } }] },
    ];
    expect(classifyApp('a.com', 'id', p, EXPECTED).verdict).toBe('only-allowlisted');
  });

  it('broad when an email_domain wildcard is present', () => {
    const p: AccessPolicy[] = [
      {
        name: 'Allow',
        decision: 'allow',
        include: [{ email_domain: { domain: 'example.com' } }],
      },
    ];
    const row = classifyApp('a.com', 'id', p, EXPECTED);
    expect(row.verdict).toBe('broad');
    expect(row.flags).toContain('domain:example.com');
  });

  it('broad when an extra email is present', () => {
    const p: AccessPolicy[] = [
      { name: 'Allow', decision: 'allow', include: [{ email: { email: 'someone@else.test' } }] },
    ];
    const row = classifyApp('a.com', 'id', p, EXPECTED);
    expect(row.verdict).toBe('broad');
    expect(row.extraEmails).toContain('someone@else.test');
  });

  it('no-allow-policy when only a service-token policy exists', () => {
    const p: AccessPolicy[] = [
      { name: 'Svc', decision: 'non_identity', include: [{ service_token: { token_id: 't' } }] },
    ];
    expect(classifyApp('a.com', 'id', p, EXPECTED).verdict).toBe('no-allow-policy');
  });

  it('everyone when a public policy exists', () => {
    const p: AccessPolicy[] = [{ name: 'Pub', decision: 'allow', include: [{ everyone: {} }] }];
    expect(classifyApp('a.com', 'id', p, EXPECTED).verdict).toBe('everyone');
  });
});

describe('summarize', () => {
  it('counts verdicts', () => {
    const rows = [
      classifyApp(
        'a',
        '1',
        [{ name: 'A', decision: 'allow', include: [{ group: { id: 'gxxxxxxx' } }] }],
        EXPECTED,
      ),
      classifyApp(
        'b',
        '2',
        [{ name: 'B', decision: 'allow', include: [{ everyone: {} }] }],
        EXPECTED,
      ),
    ];
    const s = summarize(rows);
    expect(s.total).toBe(2);
    expect(s.byVerdict['only-allowlisted']).toBe(1);
    expect(s.byVerdict.everyone).toBe(1);
  });
});
