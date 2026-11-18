/**
 * @file env.ts
 * @description Runtime bindings for the worker. All three are Worker secrets
 * (`wrangler secret put`), never `[vars]`:
 *   CF_API_TOKEN   - Cloudflare API token scoped to Access apps/policies/groups/IdPs edit
 *   CF_ACCOUNT_ID  - target account id
 *   ADMIN_TOKEN    - inbound bearer for this worker's own /v1/access/* endpoints
 */

/** Runtime environment bindings for the worker. */
export interface ProvisionerEnv {
  /** Inbound bearer token callers must present on /v1/access/*. */
  ADMIN_TOKEN: string;
  /** Cloudflare API token used for Access calls. */
  CF_API_TOKEN: string;
  /** Cloudflare account id the Access API is scoped to. */
  CF_ACCOUNT_ID: string;
}

/** Resolved configuration needed to talk to the Cloudflare API. */
export interface CfContext {
  token: string;
  accountId: string;
}

/**
 * Read the Cloudflare context from the env. Fails loud: throws if either value
 * is missing rather than half-configuring.
 *
 * @param env - the worker env
 * @returns the resolved CF context
 * @throws Error when CF_API_TOKEN or CF_ACCOUNT_ID is absent
 */
export function resolveCfContext(env: ProvisionerEnv): CfContext {
  if (!env.CF_API_TOKEN) throw new Error('provisioner: CF_API_TOKEN missing');
  if (!env.CF_ACCOUNT_ID) throw new Error('provisioner: CF_ACCOUNT_ID missing');
  return { token: env.CF_API_TOKEN, accountId: env.CF_ACCOUNT_ID };
}
