/**
 * @file membership.ts
 * @description Runtime resolution of "is this email in Access GROUP <name>?" so
 * consuming apps derive authorization from the live CF
 * Access group instead of a hardcoded list they must remember to update.
 *
 * WHY THIS FILE EXISTS AT ALL — three Cloudflare facts, each verified against
 * the docs, that together rule out every cheaper design:
 *
 *   1. Access GROUP membership is NOT in the Access JWT and NOT in
 *      /cdn-cgi/access/get-identity. Only the IdP's own groups can ride in the
 *      token, and ours are Access groups. So an app behind Access cannot learn
 *      group membership from the request alone.
 *   2. There is NO CF API endpoint answering "is user X in group Y". The Access
 *      Groups API is list/get/create/update only. A client must read the group's
 *      `include` rules and evaluate them itself — which is what this file is.
 *   3. There is NO push event when a group's membership CHANGES. Notifications
 *      have no Access/Zero-Trust config-change alert type, and Zero Trust
 *      Logpush ships access_requests + auth audit logs, not config changes.
 *      "Event-driven invalidation" would mean polling the Audit Logs API — a
 *      second poll, with delivery lag, that fails OPEN when an event is missed.
 *      So: read the group live on every membership request, and let consumers
 *      memoise the verdict for a bounded window (CONSUMER_TTL_SECONDS).
 *
 * COST, STATED TRUTHFULLY: this service holds NO cross-request cache. Every
 * /v1/access/membership request reads the Access groups from the CF API
 * (one GET /access/groups per requested group name, plus at most one more for
 * nested `group` rules, shared within that request). Observed load is a few to
 * ~15 requests per DAY against a 1200-per-5-minute account limit, so a
 * cross-request cache would buy nothing measurable and would make the
 * advertised `ttl_seconds` a lie (the consumer's memo window would stack on top
 * of an unknown snapshot age). The earlier per-isolate TTL cache never served a
 * second request — a resolver was built per request — and was deleted as dead
 * code. A test pins "fresh per request" so a hoisted resolver or
 * module-level cache goes red.
 *
 * FAIL-CLOSED CONTRACT: if membership cannot be resolved —
 * CF unreachable, token rejected, or the group contains a rule type this
 * evaluator does not understand — the answer is NEVER `false`. `false` is
 * indistinguishable from a legitimate deny and would silently downgrade a user.
 * Unresolvable groups surface as ERRORS so the caller revokes the session and
 * forces re-authentication, loudly.
 */

import type { AccessGroup, AccessRule, CfAccessClient } from './cf-access';

/**
 * The `ttl_seconds` this service advertises on a membership verdict: how long a
 * CONSUMER may memoise that verdict before asking again. It is not a cache age
 * inside this service — the group snapshot behind every verdict is read from CF on the
 * request that produced it, so a verdict is at most this old when a consumer
 * honours it. Consumers should treat it as a bound of 5..60 seconds;
 * changing it changes what every consumer may assume.
 */
export const CONSUMER_TTL_SECONDS = 60;

/**
 * Rule kinds this evaluator can decide from an email alone.
 *
 * Deliberately NOT supported, and therefore fail-closed (see `evaluateRule`):
 *   - `email_list`  — needs a second API read of the list's contents.
 *   - `ip`/`geo`/`country`/`device_posture`/`auth_method`/`common_name` — depend
 *     on request context this resolver is not given, so it cannot honestly
 *     answer; deciding them from an email would be a lie.
 *   - `azureAD`/`okta`/`github`/`google`/`saml`/`gsuite` (IdP groups) — require
 *     the caller's IdP claims, which are not in scope here.
 * Any of these makes the whole group unresolvable rather than partially applied.
 */
const SUPPORTED_RULE_KINDS = ['email', 'email_domain', 'everyone', 'group'] as const;

/** A rule kind this evaluator can decide. */
export type SupportedRuleKind = (typeof SUPPORTED_RULE_KINDS)[number];

/** Raised when a group cannot be honestly evaluated. Caller MUST fail closed. */
export class MembershipUnresolvable extends Error {
  /**
   * Build a fail-closed membership error.
   * @param message - human-readable cause, surfaced in the 502 detail
   * @param group - the group name the failure is attributed to
   * @param reason - machine-readable failure class
   */
  constructor(
    message: string,
    readonly group: string,
    readonly reason: 'unknown_rule' | 'cf_unreachable' | 'group_missing' | 'cycle',
  ) {
    super(message);
    this.name = 'MembershipUnresolvable';
  }
}

/** Shape of an Access user id: UUID-like. Anything else never reaches the CF API. */
const SUB_PATTERN = /^[A-Za-z0-9-]{8,64}$/;

/**
 * Normalize an email for comparison: CF matches case-insensitively.
 * @param email - the raw email as received from the JWT or a CF rule
 * @returns the trimmed, lower-cased email
 */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Extract the domain part of an email.
 * @param email - an email address, already normalized
 * @returns the part after the last `@`, or null when it is not an address
 */
function domainOf(email: string): string | null {
  const at = email.lastIndexOf('@');
  return at === -1 || at === email.length - 1 ? null : email.slice(at + 1);
}

/**
 * Decide a single include rule for an email.
 *
 * @param rule - one CF Access include rule
 * @param email - the already-normalized identity under test
 * @param groupName - name of the group being evaluated (for error context)
 * @param resolveNested - resolver for a nested `group` rule, by group id
 * @returns true when the rule matches this email, false when it definitively does not
 * @throws MembershipUnresolvable when the rule kind cannot be honestly decided
 */
async function evaluateRule(
  rule: AccessRule,
  email: string,
  groupName: string,
  resolveNested: (groupId: string) => Promise<boolean>,
): Promise<boolean> {
  const kinds = Object.keys(rule);
  // A rule object carries exactly one kind. More than one means CF returned a
  // shape we do not model — refuse rather than guess which key wins.
  if (kinds.length !== 1) {
    throw new MembershipUnresolvable(
      `group "${groupName}": rule with ${kinds.length} keys (${kinds.join(',')}) is not a shape this service models`,
      groupName,
      'unknown_rule',
    );
  }
  const kind = kinds[0];

  if (!SUPPORTED_RULE_KINDS.includes(kind as SupportedRuleKind)) {
    throw new MembershipUnresolvable(
      `group "${groupName}": rule kind "${kind}" cannot be decided from an email alone — failing closed rather than silently ignoring it`,
      groupName,
      'unknown_rule',
    );
  }

  switch (kind as SupportedRuleKind) {
    case 'everyone':
      return true;

    case 'email': {
      const want = (rule.email as { email?: string } | undefined)?.email;
      if (!want) {
        throw new MembershipUnresolvable(
          `group "${groupName}": email rule with no address`,
          groupName,
          'unknown_rule',
        );
      }
      return normalizeEmail(want) === email;
    }

    case 'email_domain': {
      const want = (rule.email_domain as { domain?: string } | undefined)?.domain;
      if (!want) {
        throw new MembershipUnresolvable(
          `group "${groupName}": email_domain rule with no domain`,
          groupName,
          'unknown_rule',
        );
      }
      return domainOf(email) === normalizeEmail(want).replace(/^@/, '');
    }

    case 'group': {
      const id = (rule.group as { id?: string } | undefined)?.id;
      if (!id) {
        throw new MembershipUnresolvable(
          `group "${groupName}": nested group rule with no id`,
          groupName,
          'unknown_rule',
        );
      }
      return resolveNested(id);
    }
  }
}

/**
 * Reads Access groups and evaluates membership.
 *
 * ONE INSTANCE PER REQUEST. The instance memoises group reads for its own
 * lifetime only, so the nested lookups of a single request share one
 * `listGroups` read instead of re-fetching per rule. It carries no TTL and
 * never expires an entry, so an instance MUST NOT outlive the request that
 * built it: hoisting it to module scope would silently serve a stale snapshot
 * for the isolate's lifetime and make the advertised `ttl_seconds` false.
 */
export class MembershipResolver {
  private readonly byName = new Map<string, AccessGroup>();
  private readonly byId = new Map<string, AccessGroup>();

  /**
   * Bind a resolver to one request's CF Access client.
   * @param client - the CF Access API client for THIS request
   */
  constructor(private readonly client: CfAccessClient) {}

  /**
   * Record a group under both its name and id so nested lookups share the read.
   * @param group - the group just read from Cloudflare
   * @returns the same group, for chaining
   */
  private remember(group: AccessGroup): AccessGroup {
    this.byName.set(group.name, group);
    this.byId.set(group.id, group);
    return group;
  }

  /**
   * Fetch a group by name, reusing a read made earlier in this request.
   * @param name - the Access group name
   * @returns the resolved group
   * @throws MembershipUnresolvable when CF is unreachable or the group is absent
   */
  private async groupByName(name: string): Promise<AccessGroup> {
    const known = this.byName.get(name);
    if (known) return known;
    let found: AccessGroup | null;
    try {
      found = await this.client.getGroupByName(name);
    } catch (e) {
      throw new MembershipUnresolvable(
        `group "${name}": Cloudflare API read failed: ${String(e)}`,
        name,
        'cf_unreachable',
      );
    }
    if (!found) {
      throw new MembershipUnresolvable(
        `group "${name}" does not exist in Cloudflare Access`,
        name,
        'group_missing',
      );
    }
    return this.remember(found);
  }

  /**
   * Fetch a group by id, reusing a read made earlier in this request.
   * @param id - the Access group id referenced by a nested rule
   * @param context - name of the group whose rule referenced `id`, for error reporting
   * @returns the resolved group
   * @throws MembershipUnresolvable when CF is unreachable or the group is absent
   */
  private async groupById(id: string, context: string): Promise<AccessGroup> {
    const known = this.byId.get(id);
    if (known) return known;
    let all: AccessGroup[];
    try {
      all = await this.client.listGroups();
    } catch (e) {
      throw new MembershipUnresolvable(
        `nested group "${id}" (from "${context}"): Cloudflare API read failed: ${String(e)}`,
        context,
        'cf_unreachable',
      );
    }
    for (const g of all) this.remember(g);
    const found = all.find((g) => g.id === id);
    if (!found) {
      throw new MembershipUnresolvable(
        `nested group "${id}" (from "${context}") does not exist`,
        context,
        'group_missing',
      );
    }
    return found;
  }

  /**
   * Is `email` a member of the Access group named `name`?
   *
   * A group matches when ANY include rule matches and NO exclude rule matches,
   * and every `require` rule matches — mirroring Cloudflare's own evaluation.
   *
   * @param name - the Access group name, e.g. "admins"
   * @param rawEmail - the authenticated identity from the Access JWT
   * @returns true iff the identity is a member
   * @throws MembershipUnresolvable — caller MUST revoke the session, never treat as false
   */
  async isMember(name: string, rawEmail: string): Promise<boolean> {
    const email = normalizeEmail(rawEmail);
    return this.evaluateGroup(await this.groupByName(name), email, new Set());
  }

  /**
   * Evaluate a resolved group against an email, guarding against rule cycles.
   * @param group - the resolved group to evaluate
   * @param email - the normalized identity email
   * @param seen - ids of groups already on the current evaluation path
   * @returns true iff the group's include/exclude/require rules admit the email
   * @throws MembershipUnresolvable on a nested cycle or an unreadable nested group
   */
  private async evaluateGroup(
    group: AccessGroup,
    email: string,
    seen: Set<string>,
  ): Promise<boolean> {
    if (seen.has(group.id)) {
      throw new MembershipUnresolvable(
        `group "${group.name}": nested group cycle detected`,
        group.name,
        'cycle',
      );
    }
    seen.add(group.id);

    const nested = async (id: string): Promise<boolean> =>
      this.evaluateGroup(await this.groupById(id, group.name), email, seen);

    const any = async (rules: AccessRule[] | undefined): Promise<boolean> => {
      let matched = false;
      for (const r of rules ?? []) {
        // Not short-circuited: an unknown rule kind ANYWHERE in the group must
        // throw rather than be skipped because an earlier rule already matched.
        if (await evaluateRule(r, email, group.name, nested)) matched = true;
      }
      return matched;
    };
    const all = async (rules: AccessRule[] | undefined): Promise<boolean> => {
      let satisfied = true;
      for (const r of rules ?? []) {
        if (!(await evaluateRule(r, email, group.name, nested))) satisfied = false;
      }
      return satisfied;
    };

    // Order matters: exclude wins over include, and require gates everything.
    const included = await any(group.include);
    const excluded = await any(group.exclude);
    const required = await all(group.require);
    return included && !excluded && required;
  }

  /**
   * Resolve a Cloudflare Access `sub` (user id) to the email on the live Access
   * user record, so the one existing email evaluator decides membership. The
   * verdict therefore still comes only from the live Access group; the sub is a
   * lookup key, never an allowlist, and no name/display name is read.
   *
   * @param sub - the Access JWT `sub` claim
   * @returns the user's email, or null when the sub is malformed, unknown, or
   *   its record carries no email (all of which mean "not a member")
   * @throws when CF is unreachable (non-404) — caller fails closed with 502
   */
  async emailForSub(sub: string): Promise<{ email: string } | { unresolved: string }> {
    if (!SUB_PATTERN.test(sub)) return { unresolved: 'sub_malformed' };
    const user = await this.client.getUserById(sub);
    if (!user) return { unresolved: 'sub_unknown' };
    // Trust the record only if it is the very identity asked for.
    if (user.id !== sub || (user.uid !== undefined && user.uid !== sub)) {
      return { unresolved: 'sub_mismatch' };
    }
    const email = typeof user.email === 'string' ? normalizeEmail(user.email) : '';
    if (!email || domainOf(email) === null) return { unresolved: 'sub_no_email' };
    return { email };
  }

  /**
   * Resolve membership for several groups at once.
   *
   * Never collapses an error into `false`: unresolvable groups land in `errors`
   * and the caller is expected to fail closed on a non-empty `errors` map.
   *
   * @param names - group names to test, e.g. ["admins", "staff"]
   * @param email - the authenticated identity
   * @returns per-group verdicts in `memberships` and per-group failure reasons in `errors`
   */
  async resolveAll(
    names: string[],
    email: string,
  ): Promise<{ memberships: Record<string, boolean>; errors: Record<string, string> }> {
    const memberships: Record<string, boolean> = {};
    const errors: Record<string, string> = {};
    for (const name of names) {
      try {
        memberships[name] = await this.isMember(name, email);
      } catch (e) {
        const reason = e instanceof MembershipUnresolvable ? e.reason : 'cf_unreachable';
        errors[name] = `${reason}: ${e instanceof Error ? e.message : String(e)}`;
        console.error(
          JSON.stringify({
            level: 'error',
            worker: 'cf-access-provisioner',
            event: 'membership_unresolvable',
            group: name,
            reason,
            message: e instanceof Error ? e.message : String(e),
          }),
        );
      }
    }
    return { memberships, errors };
  }
}
