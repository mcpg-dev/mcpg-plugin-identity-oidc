# OIDC/OAuth Identity Resolver — `dev.mcpg.identity.oidc`

> class `identity_provider` · `native` · package `mcpg-plugin-identity-oidc` · artifact `libmcpg_plugin_identity_oidc.so`

Resolves caller identity from OIDC/OAuth bearer tokens against one or more
configured issuers. Validates signatures (JWKS), enforces audiences, maps claims
to roles/groups/scopes/attributes, and populates the gateway identity context.
Reach for it for human SSO / federated workforce auth.

## What it does
- Extracts the bearer token from `Authorization: Bearer` (default) or a custom
  header. Validates against the matching provider's issuer.
- Verification modes per provider: `oidc_jwks` (discovery + JWKS signature
  verification), `oauth_introspection` (RFC 7662 opaque-token introspection), or
  `hybrid` (JWKS first, then introspection).
- Enforces `aud` against the provider's `audiences`, clock skew, and an
  allowed-algorithm list (HMAC requires explicit `allow_hmac` opt-in).
- Claim mapping pulls subject/groups/roles/scopes/attributes from configurable
  JSON claim paths.
- SSRF guard on discovery/JWKS/introspection fetches (private ranges blocked
  unless `allow_private_issuer`); requires capability `network_outbound`.
- Also available as a built-in gateway bridge (`auth:` / `oidc_oauth:` blocks);
  this crate packages the same logic as a loadable plugin.

## Configuration
Part of the identity chain, loaded via the top-level `plugins:` list:

```yaml
plugins:
  - id: dev.mcpg.identity.oidc
    class: identity_provider
    source: { path: ./plugins/libmcpg_plugin_identity_oidc.so }
    config:
      token_source:
        kind: authorization_bearer       # or "custom_header" { header_name, header_prefix }
      providers:
        - issuer: "https://idp.example.com"
          discovery_uri: null            # default: <issuer>/.well-known/openid-configuration
          audiences: ["mcpg"]
          clock_skew_secs: 60
          allowed_issuer_hosts: []
          allow_private_issuer: false
          verification:
            kind: oidc_jwks               # "oidc_jwks" | "oauth_introspection" | "hybrid"
            allowed_algs: ["RS256"]
            refresh_interval_secs: 300
            timeout_ms: 2000
            max_staleness_secs: 3600
            allow_hmac: false
          claim_mappings:
            subject_claim: sub
            group_claim_paths: ["groups"]
            role_claim_paths: ["realm_access/roles"]
            scope_claim_paths: ["scope", "scp"]
            attribute_claim_mappings: { tenant: "tenant_id" }
```

Top-level:

| Field | Type | Default | Description |
|---|---|---|---|
| `token_source.kind` | enum | `authorization_bearer` | `authorization_bearer` or `custom_header` (with `header_name` / `header_prefix`). |
| `providers` | provider[] | — | One or more issuers; non-empty, distinct `issuer`s. |

Per provider (`providers[]`):

| Field | Type | Default | Description |
|---|---|---|---|
| `issuer` | string | — | Issuer URL (`https://`/`http://`). |
| `discovery_uri` | string? | `null` | Override OIDC discovery URL. |
| `audiences` | string[] | `[]` | Accepted `aud` values. |
| `clock_skew_secs` | u64 | `60` | Allowed clock skew. |
| `allowed_issuer_hosts` | string[] | `[]` | Hostname allowlist for discovery/JWKS fetches. |
| `allow_private_issuer` | bool | `false` | Permit private/loopback issuer URLs (dev only). |
| `verification` | object | — | Tagged by `kind` (see below). |
| `claim_mappings` | object | defaults | Subject/group/role/scope/attribute claim paths. |

`verification.kind`: `oidc_jwks { allowed_algs=[RS256], refresh_interval_secs=300, timeout_ms=2000, max_staleness_secs=3600, allow_hmac=false }`;
`oauth_introspection { introspection_url, client_id, client_secret_ref, timeout_ms=2000 }`;
`hybrid { …jwks fields…, introspection_url, client_id, client_secret_ref, introspection_timeout_ms=2000, allow_hmac=false }`.

## Build
```bash
cargo build -p mcpg-plugin-identity-oidc --features cdylib-export --release   # → target/release/libmcpg_plugin_identity_oidc.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
- Built-in bridge equivalent: `apps/gateway/src/runtime/identity_plugin.rs`
