//! OIDC/OAuth identity plugin for MCPG.
//!
//! Standalone crate encapsulating the full OIDC/OAuth verification
//! pipeline:
//! - OIDC discovery document caching
//! - JWKS key rotation and caching
//! - JWT access token verification
//! - RFC 7662 token introspection (opaque tokens)
//! - Hybrid mode (JWT with introspection fallback)
//! - Claim extraction: roles, groups, scopes, attributes
//!
//! Ships as `native-cdylib-v1`. The async resolver (with
//! `tokio::sync::RwLock`-guarded JWKS / discovery caches + reqwest)
//! is kept intact; the cdylib bundles its own private
//! `tokio::runtime::Runtime` and `block_on`s on each
//! `resolve_identity` call. The plugin crosses the sync FFI boundary
//! via a bundled runtime rather than a reqwest::blocking /
//! std::thread rewrite — the OIDC resolver's RwLock-shared caches
//! genuinely want a runtime.

// The verification pipeline and its config types live in the sibling
// `-core` library, which the GATEWAY links directly (its config schema and
// the SSRF guard in config validation are built on them). This crate is the
// plugin-ABI wrapper around that library and nothing else; the re-exports
// keep `mcpg_plugin_identity_oidc::{config, resolver, …}` working for
// existing consumers.
pub use mcpg_plugin_identity_oidc_core::{config, resolver};

pub use mcpg_plugin_identity_oidc_core::{
    ClaimMappingConfig, OidcIdentity, OidcOAuthConfig, OidcOAuthResolver, OidcProviderConfig,
    OidcVerificationResult, TokenSourceConfig, VerificationConfig, parse_algorithm,
};

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tracing::{debug, info_span, warn};

/// The plugin id this crate registers under — also the id an operator
/// names in `plugins[]` to load the signed cdylib instead.
pub const PLUGIN_ID: &str = "dev.mcpg.identity.oidc";

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!(
        "mcpg_identity_oidc_resolutions_total",
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!("mcpg_identity_oidc_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            elapsed_ms = %elapsed.as_millis(),
            "oidc identity resolved"
        ),
        IdentityResolution::None => debug!(
            elapsed_ms = %elapsed.as_millis(),
            "oidc identity: no token — fall through"
        ),
        IdentityResolution::Invalid { reason, .. } => warn!(
            reason = %reason,
            elapsed_ms = %elapsed.as_millis(),
            "oidc identity: token verification failed"
        ),
    }
}

/// OIDC/OAuth identity resolution as a gateway plugin.
///
/// Wraps an `OidcOAuthResolver` and adapts it to the sync
/// `SyncIdentityResolver` trait by block-on'ing onto a private
/// `tokio::runtime::Runtime`. The runtime is dedicated to this
/// plugin instance and lives until the plugin is dropped.
pub struct OidcIdentityPlugin {
    resolver: Arc<OidcOAuthResolver>,
    manifest: PluginManifest,
    runtime: Runtime,
}

impl OidcIdentityPlugin {
    /// Create from a shared resolver.
    pub fn from_resolver(resolver: Arc<OidcOAuthResolver>) -> Self {
        Self {
            resolver,
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "OIDC/OAuth Identity Resolver".into(),
                plugin_class: PluginClass::IdentityProvider,
                protocol_version: "1.0".into(),
                // Discovery + JWKS refresh + (optionally) introspection
                // all require outbound HTTP to the identity provider.
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("mcpg-oidc-runtime")
                .build()
                .expect("build oidc plugin tokio runtime"),
        }
    }

    /// Create from config, constructing the resolver internally.
    pub fn from_config(config: &OidcOAuthConfig) -> anyhow::Result<Self> {
        let resolver = OidcOAuthResolver::from_config(config)?;
        Ok(Self::from_resolver(Arc::new(resolver)))
    }

    /// SDK macro factory: parse operator config JSON. On parse
    /// failure, the plugin refuses to load — an identity resolver
    /// that silently misconfigures is a security hole, not a
    /// harmless default.
    pub fn from_config_json(config_json: &str) -> Self {
        let config: OidcOAuthConfig = serde_json::from_str(config_json).unwrap_or_else(|err| {
            panic!(
                "oidc-identity: config JSON failed to parse: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load rather than \
                 falling back to defaults. Fix operator config and retry."
            );
        });
        Self::from_config(&config).unwrap_or_else(|err| {
            panic!(
                "oidc-identity: resolver construction failed: {err}. Check provider \
                 URIs, audiences, and verification mode in config."
            );
        })
    }
}

/// Shared header conversion + verification result → IdentityResolution
/// mapping used by both the async `IdentityProviderPlugin` trait impl (gateway
/// static-link path) and the sync `SyncIdentityResolver` trait impl
/// (cdylib FFI path).
async fn resolve_from_headers(
    resolver: &OidcOAuthResolver,
    headers: &[(String, String)],
) -> IdentityResolution {
    let mut header_map = http::HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            header_map.insert(name, value);
        }
    }
    match resolver.verify_from_headers(&header_map).await {
        OidcVerificationResult::Verified(oidc_id) => IdentityResolution::Resolved {
            identity: PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some(oidc_id.subject_id),
                auth_provider: Some(format!("oidc_oauth:{}", oidc_id.provider_label)),
                issuer: Some(oidc_id.issuer),
                roles: oidc_id.roles,
                groups: oidc_id.groups,
                scopes: oidc_id.scopes,
                attributes: oidc_id.attributes,
            },
        },
        OidcVerificationResult::None => IdentityResolution::None,
        OidcVerificationResult::Invalid(reason) => IdentityResolution::Invalid {
            reason,
            response_headers: Vec::new(),
        },
    }
}

/// Async trait impl — used by the gateway when this crate is linked
/// directly. The plugin remains a path-dep for OIDC-specific gateway
/// plumbing (`crate::config::OidcOAuthConfig` / `crate::runtime::oidc`
/// re-exports, identity_plugin wiring). The cdylib surface is added
/// on top — it doesn't remove this path.
#[async_trait]
impl IdentityProviderPlugin for OidcIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &serde_json::Value,
    ) -> IdentityResolution {
        // Plugin-scoped span so traces from oidc identity attribute
        // back to dev.mcpg.identity.oidc.
        use tracing::Instrument;
        let span = info_span!("identity_oidc_resolve", plugin_id = PLUGIN_ID);
        let started = std::time::Instant::now();
        let result = resolve_from_headers(&self.resolver, headers)
            .instrument(span)
            .await;
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

/// Sync trait impl — used by the cdylib's FFI surface generated by
/// `declare_plugin!`'s `identity` arm. Wraps the async verifier in
/// a `block_on` on the plugin's private runtime.
impl SyncIdentityResolver for OidcIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &serde_json::Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_oidc_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let resolver = self.resolver.clone();
        let headers = headers.to_vec();
        let result = self
            .runtime
            .block_on(async move { resolve_from_headers(&resolver, &headers).await });
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {

    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: OidcIdentityPlugin,
            // OIDC verifier holds a per-process JWKS cache; could later
            // benefit from cluster-coordinated cache invalidation when an
            // issuer rotates keys, but the current implementation refreshes
            // on cache miss + TTL, which is correct without cluster help.
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> OidcIdentityPlugin {
                OidcIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> OidcOAuthConfig {
        OidcOAuthConfig {
            token_source: TokenSourceConfig::default(),
            providers: vec![OidcProviderConfig {
                issuer: "https://login.example.com/".into(),
                discovery_uri: None,
                audiences: vec![],
                verification: VerificationConfig::OidcJwks {
                    allowed_algs: vec!["RS256".into()],
                    refresh_interval_secs: 300,
                    timeout_ms: 2000,
                    max_staleness_secs: 3600,
                    allow_hmac: false,
                },
                claim_mappings: ClaimMappingConfig::default(),
                clock_skew_secs: 60,
                allowed_issuer_hosts: Vec::new(),
                allow_private_issuer: true,
                allow_any_audience: false,
            }],
        }
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = OidcIdentityPlugin::from_config(&sample_config()).unwrap();
        let m = SyncIdentityResolver::manifest(&plugin);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::IdentityProvider);
        assert!(m.required_capabilities.is_empty());
    }

    #[test]
    fn sync_no_headers_returns_no_token() {
        let plugin = OidcIdentityPlugin::from_config(&sample_config()).unwrap();
        let metadata = mcpg_plugin_protocol::types::RequestMetadata::default();
        let result =
            SyncIdentityResolver::resolve_identity(&plugin, &[], &metadata, &serde_json::json!({}));
        assert!(matches!(result, IdentityResolution::None));
    }

    #[test]
    fn sync_bad_token_returns_invalid() {
        let plugin = OidcIdentityPlugin::from_config(&sample_config()).unwrap();
        let headers = vec![("authorization".into(), "Bearer bad.token.here".into())];
        let metadata = mcpg_plugin_protocol::types::RequestMetadata::default();
        let result = SyncIdentityResolver::resolve_identity(
            &plugin,
            &headers,
            &metadata,
            &serde_json::json!({}),
        );
        assert!(matches!(result, IdentityResolution::Invalid { .. }));
    }

    // Note: no `#[tokio::test]`-flavoured coverage of the async
    // `IdentityProviderPlugin::resolve_identity` path. The plugin owns a
    // private `tokio::runtime::Runtime` (for the cdylib `block_on`
    // path); that runtime panics on drop when it's dropped from
    // inside another tokio context — which is exactly what happens
    // under `#[tokio::test]`. In production the plugin is loaded on
    // a blocking libloading thread so no enclosing context exists
    // and the drop is safe. The async path is still exercised by
    // the sync tests above (they go through `block_on`).
}
