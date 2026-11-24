//! AWS IAM provider: access keys, signed with a hand-rolled SigV4.
//!
//! Secret value format: JSON `{"access_key_id","secret_access_key"}` (optional
//! `session_token`).

use crate::http::{Http, cfg_loopback, cfg_str, check_name, text_capped};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use warden_core::{
    CreateRequest, IssuedToken, Provider, ProviderCaps, Result, RotateRequest, RotationClass,
    SecretValue, TokenInfo, WardenError,
};

const GLOBAL_REGION: &str = "us-east-1";
const MAX_KEYS: usize = 2;
const IAM_VERSION: &str = "2010-05-08";
const STS_VERSION: &str = "2011-06-15";

/// AWS IAM provider.
///
/// Config: `region` (default `us-east-1`), `iam_endpoint` (default
/// `https://iam.amazonaws.com`), `sts_endpoint` (default `https://sts.amazonaws.com`),
/// `base_url` (one override for both endpoints, for tests), `user_name` (target user for
/// `create_derived`; `revoke` uses it when set). The global default endpoints always sign
/// with `us-east-1`; `region` applies only to a custom endpoint.
#[derive(Debug)]
pub struct AwsIam {
    iam: Http,
    sts: Http,
    iam_region: String,
    sts_region: String,
    user_name: Option<String>,
    /// Hint from the engine: start of the open rotation intent.
    intent_at: Option<DateTime<Utc>>,
    /// Hint from the engine: id of the key that is in use now.
    current_id: Option<String>,
}

/// Parsed credential.
#[derive(Serialize, Deserialize)]
struct Creds {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
}

fn parse_creds(c: &SecretValue) -> Result<Creds> {
    serde_json::from_str(c.expose()).map_err(|_| {
        WardenError::Config("aws credential must be JSON {access_key_id, secret_access_key}".into())
    })
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn sha_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Compute the SigV4 `Authorization` header value.
///
/// `headers` holds lowercase names and trimmed values. `amz_date` is `yyyymmddThhmmssZ`.
#[allow(clippy::too_many_arguments)]
fn sigv4(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    creds: &Creds,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    let mut h: Vec<_> = headers.to_vec();
    h.sort();
    let canon_headers: String = h
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed = h.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
    let canon = format!(
        "{method}\n{path}\n{query}\n{canon_headers}\n{signed}\n{}",
        sha_hex(body)
    );
    let day = &amz_date[..8];
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha_hex(canon.as_bytes())
    );
    let k = hmac(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        day.as_bytes(),
    );
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, service.as_bytes());
    let k = hmac(&k, b"aws4_request");
    let sig = hex::encode(hmac(&k, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
        creds.access_key_id
    )
}

fn urlenc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Text of the first `<tag>` element.
fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].trim().to_string())
}

fn host_of(url: &str) -> Result<String> {
    let u = reqwest::Url::parse(url).map_err(|e| WardenError::Config(format!("bad url: {e}")))?;
    let h = u
        .host_str()
        .ok_or_else(|| WardenError::Config("url has no host".into()))?;
    Ok(match u.port() {
        Some(p) => format!("{h}:{p}"),
        None => h.to_string(),
    })
}

impl AwsIam {
    /// Build from provider config.
    pub fn from_config(c: &serde_json::Value) -> Result<Self> {
        let base = cfg_str(c, "base_url");
        let iam_cfg = cfg_str(c, "iam_endpoint").or_else(|| base.clone());
        let sts_cfg = cfg_str(c, "sts_endpoint").or(base);
        let region = cfg_str(c, "region").unwrap_or_else(|| GLOBAL_REGION.into());
        // The global IAM and STS endpoints sign with us-east-1. A custom endpoint uses `region`.
        let iam_region = if iam_cfg.is_some() {
            region.clone()
        } else {
            GLOBAL_REGION.into()
        };
        let sts_region = if sts_cfg.is_some() {
            region
        } else {
            GLOBAL_REGION.into()
        };
        let lb = cfg_loopback(c);
        Ok(Self {
            iam: Http::new(
                iam_cfg.unwrap_or_else(|| "https://iam.amazonaws.com".into()),
                lb,
            )?,
            sts: Http::new(
                sts_cfg.unwrap_or_else(|| "https://sts.amazonaws.com".into()),
                lb,
            )?,
            iam_region,
            sts_region,
            user_name: cfg_str(c, "user_name"),
            intent_at: cfg_str(c, "_warden_intent_at")
                .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
                .map(|t| t.with_timezone(&Utc)),
            current_id: cfg_str(c, "_warden_current_id"),
        })
    }

    /// Send one signed Query API call. Returns the XML body.
    async fn call(
        &self,
        service: &str,
        creds: &Creds,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<String> {
        let (http, region) = if service == "sts" {
            (&self.sts, &self.sts_region)
        } else {
            (&self.iam, &self.iam_region)
        };
        let version = if service == "sts" {
            STS_VERSION
        } else {
            IAM_VERSION
        };
        let mut body = format!("Action={action}&Version={version}");
        for (k, v) in params {
            body.push_str(&format!("&{}={}", urlenc(k), urlenc(v)));
        }
        let ctype = "application/x-www-form-urlencoded; charset=utf-8";
        let host = host_of(&http.base)?;
        let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut hs = vec![
            ("content-type", ctype),
            ("host", host.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        if let Some(t) = &creds.session_token {
            hs.push(("x-amz-security-token", t.as_str()));
        }
        let auth = sigv4(
            "POST",
            "/",
            "",
            &hs,
            body.as_bytes(),
            creds,
            region,
            service,
            &amz_date,
        );
        let mut rb = http
            .client
            .post(http.url("/"))
            .header("content-type", ctype)
            .header("x-amz-date", &amz_date)
            .header("authorization", auth)
            .body(body);
        if let Some(t) = &creds.session_token {
            rb = rb.header("x-amz-security-token", t);
        }
        let resp = http.send_with(rb, true).await?;
        text_capped(resp).await
    }

    /// Own user name from `sts:GetCallerIdentity`.
    async fn caller_user(&self, creds: &Creds) -> Result<String> {
        let xml = self.call("sts", creds, "GetCallerIdentity", &[]).await?;
        let arn = tag(&xml, "Arn")
            .ok_or_else(|| WardenError::Provider("no Arn in GetCallerIdentity".into()))?;
        match arn.split_once(":user/") {
            Some((_, p)) => Ok(p.rsplit('/').next().unwrap_or(p).to_string()),
            None => Err(WardenError::Config(format!(
                "caller is not an IAM user: {arn}"
            ))),
        }
    }

    /// Keys of `user` with their creation time.
    async fn list_keys_meta(
        &self,
        creds: &Creds,
        user: &str,
    ) -> Result<Vec<(String, Option<DateTime<Utc>>)>> {
        let xml = self
            .call("iam", creds, "ListAccessKeys", &[("UserName", user)])
            .await?;
        Ok(xml
            .split("<member>")
            .skip(1)
            .filter_map(|m| {
                let id = tag(m, "AccessKeyId")?;
                let at = tag(m, "CreateDate")
                    .and_then(|d| DateTime::parse_from_rfc3339(&d).ok())
                    .map(|d| d.with_timezone(&Utc));
                Some((id, at))
            })
            .collect())
    }

    async fn list_keys(&self, creds: &Creds, user: &str) -> Result<Vec<String>> {
        Ok(self
            .list_keys_meta(creds, user)
            .await?
            .into_iter()
            .map(|(id, _)| id)
            .collect())
    }

    /// At the key limit, delete the orphan of a lost `CreateAccessKey` reply.
    /// An orphan is not the current key, is not the signing key, and is not older than the
    /// intent. Logs the key id only.
    async fn clear_orphan(
        &self,
        creds: &Creds,
        user: &str,
        keys: &[(String, Option<DateTime<Utc>>)],
    ) -> Result<()> {
        let manual = || {
            WardenError::Provider(format!(
                "user already has {} access keys (limit {MAX_KEYS}) and none is a Warden                  orphan; delete one key in the AWS console or with `aws iam delete-access-key`",
                keys.len()
            ))
        };
        let (Some(intent_at), Some(current)) = (self.intent_at, &self.current_id) else {
            return Err(manual());
        };
        let orphans: Vec<&str> = keys
            .iter()
            .filter(|(id, at)| {
                id != current && *id != creds.access_key_id && at.is_some_and(|t| t >= intent_at)
            })
            .map(|(id, _)| id.as_str())
            .collect();
        let [orphan] = orphans.as_slice() else {
            return Err(manual());
        };
        tracing::warn!(key_id = %orphan, "deleting orphan access key of a lost rotation");
        self.call(
            "iam",
            creds,
            "DeleteAccessKey",
            &[("UserName", user), ("AccessKeyId", orphan)],
        )
        .await?;
        Ok(())
    }

    /// Create a key for `user`, tag the user with the key id, return the issued token.
    async fn create_key(&self, creds: &Creds, user: &str, name: &str) -> Result<IssuedToken> {
        check_name(name)?;
        let existing = self.list_keys_meta(creds, user).await?;
        if existing.len() >= MAX_KEYS {
            self.clear_orphan(creds, user, &existing).await?;
        }
        let xml = self
            .call("iam", creds, "CreateAccessKey", &[("UserName", user)])
            .await?;
        let (Some(id), Some(secret)) = (tag(&xml, "AccessKeyId"), tag(&xml, "SecretAccessKey"))
        else {
            return Err(WardenError::Provider("bad CreateAccessKey response".into()));
        };
        let value = serde_json::to_string(&Creds {
            access_key_id: id.clone(),
            secret_access_key: secret,
            session_token: None,
        })?;
        // A failed tag must not lose the new key. Warn and continue.
        let tagged = self
            .call(
                "iam",
                creds,
                "TagUser",
                &[
                    ("UserName", user),
                    ("Tags.member.1.Key", &id),
                    ("Tags.member.1.Value", name),
                ],
            )
            .await;
        if let Err(e) = tagged {
            tracing::warn!(error = %e, "TagUser failed after CreateAccessKey");
        }
        Ok(IssuedToken {
            value: SecretValue::new(value),
            provider_token_id: id,
            expires_at: None,
        })
    }
}

#[async_trait]
impl Provider for AwsIam {
    fn class(&self) -> RotationClass {
        RotationClass::Overlap
    }

    fn capabilities(&self) -> ProviderCaps {
        ProviderCaps {
            self_rotate: true,
            create_derived: true,
            revoke: true,
            naming: true,
        }
    }

    async fn verify(&self, cred: &SecretValue) -> Result<TokenInfo> {
        let c = parse_creds(cred)?;
        let user = self.caller_user(&c).await?;
        self.list_keys(&c, &user).await?;
        Ok(TokenInfo {
            provider_token_id: c.access_key_id,
            expires_at: None,
            scopes: vec![],
        })
    }

    async fn rotate_self(&self, cred: &SecretValue, req: &RotateRequest) -> Result<IssuedToken> {
        let c = parse_creds(cred)?;
        let user = self.caller_user(&c).await?;
        self.create_key(&c, &user, &req.token_name).await
    }

    async fn create_derived(
        &self,
        admin: &SecretValue,
        req: &CreateRequest,
    ) -> Result<IssuedToken> {
        let c = parse_creds(admin)?;
        let user = self
            .user_name
            .clone()
            .ok_or_else(|| WardenError::Config("missing config key `user_name`".into()))?;
        self.create_key(&c, &user, &req.token_name).await
    }

    async fn revoke(&self, admin: &SecretValue, provider_token_id: &str) -> Result<()> {
        let c = parse_creds(admin)?;
        let mut p = vec![("AccessKeyId", provider_token_id)];
        if let Some(u) = &self.user_name {
            p.push(("UserName", u.as_str()));
        }
        self.call("iam", &c, "DeleteAccessKey", &p).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testutil::{create_req, rotate_req};
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn global_endpoints_sign_with_us_east_1() {
        let a = AwsIam::from_config(&json!({"region": "eu-west-1"})).unwrap();
        assert_eq!(
            (a.iam_region.as_str(), a.sts_region.as_str()),
            ("us-east-1", "us-east-1")
        );
        let b = AwsIam::from_config(&json!({
            "region": "eu-west-1",
            "sts_endpoint": "https://sts.eu-west-1.amazonaws.com"
        }))
        .unwrap();
        assert_eq!(
            (b.iam_region.as_str(), b.sts_region.as_str()),
            ("us-east-1", "eu-west-1")
        );
    }

    #[test]
    fn sigv4_matches_aws_test_vector() {
        // AWS SigV4 test suite: get-vanilla.
        let c = Creds {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let a = sigv4(
            "GET",
            "/",
            "",
            &[
                ("host", "example.amazonaws.com"),
                ("x-amz-date", "20150830T123600Z"),
            ],
            b"",
            &c,
            "us-east-1",
            "service",
            "20150830T123600Z",
        );
        assert_eq!(
            a,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    fn cred(id: &str) -> SecretValue {
        SecretValue::new(
            json!({"access_key_id": id, "secret_access_key": "secret-fixture"}).to_string(),
        )
    }
    fn aws(s: &MockServer) -> AwsIam {
        AwsIam::from_config(&json!({"base_url": s.uri(), "user_name": "bob"})).unwrap()
    }
    fn keys_at(items: &[(&str, &str)]) -> ResponseTemplate {
        let m: String = items
            .iter()
            .map(|(i, d)| {
                format!(
                    "<member><AccessKeyId>{i}</AccessKeyId><CreateDate>{d}</CreateDate>                     </member>"
                )
            })
            .collect();
        ResponseTemplate::new(200).set_body_string(format!(
            "<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>{m}             </AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>"
        ))
    }
    fn hinted(s: &MockServer) -> AwsIam {
        AwsIam::from_config(&json!({
            "base_url": s.uri(),
            "user_name": "bob",
            "_warden_intent_at": "2026-11-24T10:00:00Z",
            "_warden_current_id": "AKIAOLD"
        }))
        .unwrap()
    }
    fn identity() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(
            "<GetCallerIdentityResponse><GetCallerIdentityResult>\
             <Arn>arn:aws:iam::123456789012:user/bob</Arn></GetCallerIdentityResult>\
             </GetCallerIdentityResponse>",
        )
    }
    fn keys(ids: &[&str]) -> ResponseTemplate {
        let m: String = ids
            .iter()
            .map(|i| {
                format!("<member><AccessKeyId>{i}</AccessKeyId><Status>Active</Status></member>")
            })
            .collect();
        ResponseTemplate::new(200).set_body_string(format!(
            "<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>{m}\
             </AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>"
        ))
    }
    async fn mount(s: &MockServer, action: &str, r: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(body_string_contains(format!("Action={action}")))
            .respond_with(r)
            .mount(s)
            .await;
    }

    #[tokio::test]
    async fn verify_ok() {
        let s = MockServer::start().await;
        mount(&s, "GetCallerIdentity", identity()).await;
        mount(&s, "ListAccessKeys", keys(&["AKIAOLD"])).await;
        let i = aws(&s).verify(&cred("AKIAOLD")).await.unwrap();
        assert_eq!(i.provider_token_id, "AKIAOLD");
    }

    #[tokio::test]
    async fn rotate_creates_key_and_tags() {
        let s = MockServer::start().await;
        mount(&s, "GetCallerIdentity", identity()).await;
        mount(&s, "ListAccessKeys", keys(&["AKIAOLD"])).await;
        mount(
            &s,
            "CreateAccessKey",
            ResponseTemplate::new(200).set_body_string(
                "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey>\
                 <AccessKeyId>AKIANEW</AccessKeyId><SecretAccessKey>newsecret</SecretAccessKey>\
                 </AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>",
            ),
        )
        .await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=TagUser"))
            .and(body_string_contains("Tags.member.1.Key=AKIANEW"))
            .and(body_string_contains(
                "Tags.member.1.Value=aivw_demo_20261124",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("<TagUserResponse/>"))
            .expect(1)
            .mount(&s)
            .await;
        let t = aws(&s)
            .rotate_self(&cred("AKIAOLD"), &rotate_req(Some("AKIAOLD")))
            .await
            .unwrap();
        assert_eq!(t.provider_token_id, "AKIANEW");
        let v: serde_json::Value = serde_json::from_str(t.value.expose()).unwrap();
        assert_eq!(v["access_key_id"], "AKIANEW");
        assert_eq!(v["secret_access_key"], "newsecret");
    }

    #[tokio::test]
    async fn rotate_refuses_with_two_keys() {
        let s = MockServer::start().await;
        mount(&s, "GetCallerIdentity", identity()).await;
        mount(&s, "ListAccessKeys", keys(&["A", "B"])).await;
        let e = aws(&s)
            .rotate_self(&cred("A"), &rotate_req(None))
            .await
            .unwrap_err();
        assert!(
            matches!(e, WardenError::Provider(m) if m.contains("limit 2") && m.contains("delete one key"))
        );
    }

    #[tokio::test]
    async fn orphan_key_is_deleted_before_create() {
        let s = MockServer::start().await;
        mount(&s, "GetCallerIdentity", identity()).await;
        mount(
            &s,
            "ListAccessKeys",
            keys_at(&[
                ("AKIAOLD", "2026-01-01T00:00:00Z"),
                ("AKIAORPHAN", "2026-11-24T10:00:05Z"),
            ]),
        )
        .await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=DeleteAccessKey"))
            .and(body_string_contains("AccessKeyId=AKIAORPHAN"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .expect(1)
            .mount(&s)
            .await;
        mount(
            &s,
            "CreateAccessKey",
            ResponseTemplate::new(200).set_body_string(
                "<AccessKey><AccessKeyId>AKIANEW</AccessKeyId>                 <SecretAccessKey>s</SecretAccessKey></AccessKey>",
            ),
        )
        .await;
        mount(
            &s,
            "TagUser",
            ResponseTemplate::new(200).set_body_string("<ok/>"),
        )
        .await;
        let t = hinted(&s)
            .rotate_self(&cred("AKIAOLD"), &rotate_req(Some("AKIAOLD")))
            .await
            .unwrap();
        assert_eq!(t.provider_token_id, "AKIANEW");
    }

    #[tokio::test]
    async fn two_keys_without_orphan_give_manual_step() {
        let s = MockServer::start().await;
        mount(&s, "GetCallerIdentity", identity()).await;
        mount(
            &s,
            "ListAccessKeys",
            keys_at(&[
                ("AKIAOLD", "2026-01-01T00:00:00Z"),
                ("AKIAOTHER", "2026-02-01T00:00:00Z"),
            ]),
        )
        .await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=DeleteAccessKey"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&s)
            .await;
        let e = hinted(&s)
            .rotate_self(&cred("AKIAOLD"), &rotate_req(Some("AKIAOLD")))
            .await
            .unwrap_err();
        assert!(matches!(e, WardenError::Provider(m) if m.contains("delete one key")));
    }

    #[tokio::test]
    async fn create_derived_name_check_and_revoke() {
        let s = MockServer::start().await;
        mount(&s, "ListAccessKeys", keys(&[])).await;
        mount(
            &s,
            "CreateAccessKey",
            ResponseTemplate::new(200).set_body_string(
                "<AccessKey><AccessKeyId>AKIAD</AccessKeyId>\
                 <SecretAccessKey>s</SecretAccessKey></AccessKey>",
            ),
        )
        .await;
        mount(
            &s,
            "TagUser",
            ResponseTemplate::new(200).set_body_string("<ok/>"),
        )
        .await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=DeleteAccessKey"))
            .and(body_string_contains("AccessKeyId=AKIAD"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .expect(1)
            .mount(&s)
            .await;
        let p = aws(&s);
        let t = p
            .create_derived(&cred("AKIAADMIN"), &create_req("aivw_demo_20261124"))
            .await
            .unwrap();
        assert_eq!(t.provider_token_id, "AKIAD");
        assert!(matches!(
            p.create_derived(&cred("AKIAADMIN"), &create_req("demo"))
                .await,
            Err(WardenError::Config(_))
        ));
        p.revoke(&cred("AKIAADMIN"), "AKIAD").await.unwrap();
    }

    async fn status(r: ResponseTemplate) -> WardenError {
        let s = MockServer::start().await;
        Mock::given(method("POST")).respond_with(r).mount(&s).await;
        aws(&s).verify(&cred("A")).await.unwrap_err()
    }

    #[tokio::test]
    async fn error_mapping() {
        assert!(matches!(
            status(ResponseTemplate::new(403).set_body_string("<Code>InvalidClientTokenId</Code>"))
                .await,
            WardenError::ProviderAuth(_)
        ));
        assert!(matches!(
            status(ResponseTemplate::new(401)).await,
            WardenError::ProviderAuth(_)
        ));
        assert!(matches!(
            status(ResponseTemplate::new(429).insert_header("Retry-After", "3")).await,
            WardenError::ProviderRateLimited { retry_after: Some(d) } if d.as_secs() == 3
        ));
        assert!(matches!(
            status(ResponseTemplate::new(400).set_body_string("<Code>Throttling</Code>")).await,
            WardenError::ProviderRateLimited { .. }
        ));
        assert!(matches!(
            status(ResponseTemplate::new(503)).await,
            WardenError::Provider(_)
        ));
    }

    #[test]
    fn bad_credential_is_config_error() {
        assert!(matches!(
            parse_creds(&SecretValue::new("not json")),
            Err(WardenError::Config(_))
        ));
    }
}
