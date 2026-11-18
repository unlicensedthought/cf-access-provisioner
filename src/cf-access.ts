/**
 * @file cf-access.ts
 * @description Thin typed client over the Cloudflare Access (Zero Trust) API.
 * One job: HTTP + the CF success/error envelope. No provisioning policy lives
 * here — that is provision.ts. Idempotency lookups (findAppByDomain, etc.)
 * belong here because they are pure reads.
 */

const CF_API = 'https://api.cloudflare.com/client/v4';

/** Minimal shape of an Access identity provider. */
export interface AccessIdp {
  id: string;
  name: string;
  type: string;
  config?: { client_id?: string; redirect_url?: string };
}

/** Minimal shape of an Access application. */
export interface AccessApp {
  id: string;
  name: string;
  domain: string;
  aud: string;
  allowed_idps?: string[];
  auto_redirect_to_identity?: boolean;
  session_duration?: string;
  http_only_cookie_attribute?: boolean;
  same_site_cookie_attribute?: string;
}

/** A single include/exclude/require rule inside an Access policy. */
export type AccessRule = Record<string, unknown>;

/** Minimal shape of an Access policy. */
export interface AccessPolicy {
  id?: string;
  name: string;
  decision: 'allow' | 'deny' | 'non_identity' | 'bypass';
  include: AccessRule[];
  exclude?: AccessRule[];
  require?: AccessRule[];
  precedence?: number;
}

/** Minimal shape of an Access group. */
export interface AccessGroup {
  id: string;
  name: string;
  include: AccessRule[];
  exclude?: AccessRule[];
  require?: AccessRule[];
}

/**
 * Minimal shape of an Access user (an identity that has signed in). `uid` equals
 * `id` and is the `sub` claim of that user's Access JWT. Only `email` ever feeds
 * a membership verdict; `name` is deliberately not modelled so it cannot.
 */
export interface AccessUser {
  id: string;
  uid?: string;
  email?: string;
}

/** Error thrown when the CF API returns a non-success envelope. */
export class CfApiError extends Error {
  /**
   * Build an error describing a failed CF API call.
   * @param message - human-readable summary of the failure
   * @param status - HTTP status the CF API answered with
   * @param errors - the raw `errors` array from the CF envelope, kept for diagnostics
   */
  constructor(
    message: string,
    readonly status: number,
    readonly errors: unknown,
  ) {
    super(message);
    this.name = 'CfApiError';
  }
}

/**
 * Typed client for the account-scoped Cloudflare Access API. Construct once per
 * request with the resolved token + account id.
 */
export class CfAccessClient {
  /**
   * Bind a client to one account and credential.
   * @param token - CF API bearer token with Access read scope
   * @param accountId - the Cloudflare account id the Access API is scoped to
   * @param fetchImpl - fetch implementation; defaults to the global fetch, tests inject a stub
   */
  constructor(
    private readonly token: string,
    private readonly accountId: string,
    // Arrow wrapper calls the global fetch with no detached receiver — avoids
    // the Workers "Illegal invocation" error. Tests inject their own stub.
    private readonly fetchImpl: typeof fetch = (input, init) => fetch(input, init),
  ) {}

  /** Account-scoped path prefix. */
  private base(path: string): string {
    return `${CF_API}/accounts/${this.accountId}${path}`;
  }

  /**
   * Issue a CF API call and unwrap the success envelope.
   * @throws CfApiError when the envelope reports failure or HTTP is non-2xx.
   */
  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetchImpl(this.base(path), {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const rawData = (await res.json()) as unknown;
    const data = rawData as { success?: boolean; result?: T; errors?: unknown };
    if (!res.ok || !data.success) {
      throw new CfApiError(`CF API ${method} ${path} failed`, res.status, data.errors);
    }
    return data.result as T;
  }

  // ── Organizations ──────────────────────────────────────────────────────
  /** Resolve the Zero Trust org auth_domain (e.g. "team.cloudflareaccess.com"). */
  async getAuthDomain(): Promise<string> {
    const org = await this.call<{ auth_domain: string }>('GET', '/access/organizations');
    return org.auth_domain;
  }

  // ── Identity providers ─────────────────────────────────────────────────
  /** List account identity providers. */
  listIdps(): Promise<AccessIdp[]> {
    return this.call<AccessIdp[]>('GET', '/access/identity_providers');
  }

  // ── Users ──────────────────────────────────────────────────────────────
  /**
   * Read one Access user by id (the JWT `sub`). Returns null only on a
   * definitive CF 404; every other failure throws so callers fail closed.
   */
  async getUserById(id: string): Promise<AccessUser | null> {
    try {
      return await this.call<AccessUser>('GET', `/access/users/${encodeURIComponent(id)}`);
    } catch (e) {
      if (e instanceof CfApiError && e.status === 404) return null;
      throw e;
    }
  }

  // ── Apps ───────────────────────────────────────────────────────────────
  /** List Access apps. */
  listApps(): Promise<AccessApp[]> {
    return this.call<AccessApp[]>('GET', '/access/apps');
  }

  /** Find an app by exact domain match, or null. */
  async findAppByDomain(domain: string): Promise<AccessApp | null> {
    const apps = await this.listApps();
    return apps.find((a) => a.domain === domain) ?? null;
  }

  /** Create an Access app. */
  createApp(app: Partial<AccessApp>): Promise<AccessApp> {
    return this.call<AccessApp>('POST', '/access/apps', app);
  }

  /** Update an Access app. */
  updateApp(id: string, app: Partial<AccessApp>): Promise<AccessApp> {
    return this.call<AccessApp>('PUT', `/access/apps/${id}`, app);
  }

  /** Revoke all sessions for an app (evicts users after a policy change). */
  revokeTokens(id: string): Promise<unknown> {
    return this.call('POST', `/access/apps/${id}/revoke_tokens`);
  }

  // ── Policies ───────────────────────────────────────────────────────────
  /** List policies on an app. */
  listPolicies(appId: string): Promise<AccessPolicy[]> {
    return this.call<AccessPolicy[]>('GET', `/access/apps/${appId}/policies`);
  }

  /** Create a policy on an app. */
  createPolicy(appId: string, policy: AccessPolicy): Promise<AccessPolicy> {
    return this.call<AccessPolicy>('POST', `/access/apps/${appId}/policies`, policy);
  }

  /** Update a policy on an app. */
  updatePolicy(appId: string, policyId: string, policy: AccessPolicy): Promise<AccessPolicy> {
    return this.call<AccessPolicy>('PUT', `/access/apps/${appId}/policies/${policyId}`, policy);
  }

  // ── Groups ─────────────────────────────────────────────────────────────
  /** List Access groups. */
  listGroups(): Promise<AccessGroup[]> {
    return this.call<AccessGroup[]>('GET', '/access/groups');
  }

  /** Find a group by exact name, or null. */
  async getGroupByName(name: string): Promise<AccessGroup | null> {
    const groups = await this.listGroups();
    return groups.find((g) => g.name === name) ?? null;
  }

  /** Create an Access group. */
  createGroup(group: Omit<AccessGroup, 'id'>): Promise<AccessGroup> {
    return this.call<AccessGroup>('POST', '/access/groups', group);
  }

  /** Update an Access group. */
  updateGroup(id: string, group: Omit<AccessGroup, 'id'>): Promise<AccessGroup> {
    return this.call<AccessGroup>('PUT', `/access/groups/${id}`, group);
  }
}
