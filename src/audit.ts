/**
 * @file audit.ts
 * @description Account-wide Access authorization audit. Classifies every app's
 * allow policies against an expected allowlist so broad/footgun apps surface.
 * This is the programmatic form of the manual sweep that found ~80 apps sharing
 * a domain-wildcard + extra-emails policy.
 */

import type { AccessPolicy } from './cf-access';

/** Verdict for a single app. */
export type AuditVerdict = 'only-allowlisted' | 'broad' | 'no-allow-policy' | 'everyone';

/** Audit row for one app. */
export interface AuditRow {
  domain: string;
  appId: string;
  verdict: AuditVerdict;
  /** Emails allowed beyond the expected allowlist. */
  extraEmails: string[];
  /** Non-email broadening rules (email_domain, everyone, ip, etc.). */
  flags: string[];
}

/**
 * Classify one app's policies against the expected allowlist email set.
 *
 * @param domain - app hostname
 * @param appId - app id
 * @param policies - the app's policies
 * @param expected - the only emails that should be allowed (lower-cased)
 */
export function classifyApp(
  domain: string,
  appId: string,
  policies: AccessPolicy[],
  expected: Set<string>,
): AuditRow {
  const allows = policies.filter((p) => p.decision === 'allow');
  const flags: string[] = [];
  const emails = new Set<string>();

  for (const p of allows) {
    for (const rule of p.include) {
      if ('email' in rule) {
        const e = (rule.email as { email: string }).email.toLowerCase();
        emails.add(e);
      } else if ('email_domain' in rule) {
        flags.push(`domain:${(rule.email_domain as { domain: string }).domain}`);
      } else if ('everyone' in rule) {
        flags.push('everyone');
      } else if ('group' in rule) {
        flags.push(`group:${(rule.group as { id: string }).id.slice(0, 8)}`);
      } else if ('ip' in rule) {
        flags.push('ip-range');
      } else {
        flags.push(Object.keys(rule)[0] ?? 'unknown');
      }
    }
  }

  const extraEmails = [...emails].filter((e) => !expected.has(e));

  let verdict: AuditVerdict;
  if (flags.includes('everyone')) verdict = 'everyone';
  else if (allows.length === 0) verdict = 'no-allow-policy';
  else if (extraEmails.length === 0 && flags.every((f) => f.startsWith('group:'))) {
    // Pure group-based or pure expected-emails only — treat as locked.
    verdict = 'only-allowlisted';
  } else if (extraEmails.length === 0 && flags.length === 0) verdict = 'only-allowlisted';
  else verdict = 'broad';

  return { domain, appId, verdict, extraEmails, flags };
}

/** Summary counts across an audit run. */
export interface AuditSummary {
  total: number;
  byVerdict: Record<AuditVerdict, number>;
  rows: AuditRow[];
}

/** Aggregate audit rows into a summary. */
export function summarize(rows: AuditRow[]): AuditSummary {
  const byVerdict: Record<AuditVerdict, number> = {
    'only-allowlisted': 0,
    broad: 0,
    'no-allow-policy': 0,
    everyone: 0,
  };
  for (const r of rows) byVerdict[r.verdict]++;
  return { total: rows.length, byVerdict, rows };
}
