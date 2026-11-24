//! Aivory Warden providers: API clients that create, rotate, verify and revoke tokens.
//!
//! Use [`build`] to get a [`Provider`] for a [`ProviderRef`]. See `PROVIDERS.md` for the
//! confirmed capability matrix and the documentation URLs.

mod aws;
mod cloudflare;
mod command;
mod gitlab;
mod http;
mod manual;
mod openai;

pub use aws::AwsIam;
pub use cloudflare::Cloudflare;
pub use command::CommandProvider;
pub use gitlab::GitLab;
pub use manual::Manual;
pub use openai::OpenAi;
pub use warden_core::{Provider, ProviderKind, ProviderRef, Result};

/// Build the provider for a provider reference. The config comes from `ProviderRef.config`.
///
/// Common config key: `base_url` (API root override for self-hosted servers and tests).
pub fn build(r: &ProviderRef) -> Result<Box<dyn Provider>> {
    let c = &r.config;
    Ok(match r.kind {
        ProviderKind::GitLab => Box::new(GitLab::from_config(c)?),
        ProviderKind::AwsIam => Box::new(AwsIam::from_config(c)?),
        ProviderKind::Cloudflare => Box::new(Cloudflare::from_config(c)?),
        ProviderKind::OpenAi => Box::new(OpenAi::from_config(c)?),
        ProviderKind::Command => Box::new(CommandProvider::from_config(c)?),
        ProviderKind::Manual => Box::new(Manual::from_config(c)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn factory_builds_all_kinds() {
        for kind in [
            ProviderKind::GitLab,
            ProviderKind::AwsIam,
            ProviderKind::Cloudflare,
            ProviderKind::OpenAi,
            ProviderKind::Command,
            ProviderKind::Manual,
        ] {
            let p = build(&ProviderRef {
                kind,
                config: json!({}),
            })
            .unwrap();
            let _ = p.capabilities();
        }
    }
}
