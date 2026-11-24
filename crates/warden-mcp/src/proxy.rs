//! HTTP proxy that uses a secret without revealing it.
//!
//! The daemon calls [`execute`]. The function checks the request against the [`McpPolicy`],
//! sends it with the secret in one header, and redacts the secret from the answer.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use warden_core::{McpPolicy, Result, SecretValue, WardenError};

/// Maximum request body in bytes.
pub const MAX_REQUEST_BODY: usize = 1024 * 1024;
/// Maximum response body in bytes. The proxy truncates a longer body.
pub const MAX_RESPONSE_BODY: usize = 2 * 1024 * 1024;
/// Time limit for the whole request.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Text that replaces a secret in a response.
pub const REDACTED: &str = "[REDACTED:aivw]";
/// Placeholder text that a caller must not put into the URL or the body.
pub const PLACEHOLDER: &str = "{{secret}}";

/// A request from an agent.
#[derive(Debug, Clone, Default)]
pub struct HttpCall {
    /// HTTP method.
    pub method: String,
    /// URL. HTTPS only.
    pub url: String,
    /// Extra headers.
    pub headers: BTreeMap<String, String>,
    /// Request body.
    pub body: Option<String>,
}

/// The redacted answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResult {
    /// HTTP status code. A 3xx code is returned as is.
    pub status: u16,
    /// Response headers (redacted).
    pub headers: BTreeMap<String, String>,
    /// Response body (redacted, lossy UTF-8).
    pub body: String,
    /// The body was longer than [`MAX_RESPONSE_BODY`] and was cut.
    pub truncated: bool,
}

/// DNS lookup. Tests replace it.
#[async_trait]
pub trait Resolve: Send + Sync {
    /// Return the IP addresses of `host`.
    async fn lookup(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The system resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

#[async_trait]
impl Resolve for SystemResolver {
    async fn lookup(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let addrs = tokio::net::lookup_host((host, 443)).await?;
        Ok(addrs.map(|a| a.ip()).collect())
    }
}

/// A request that passed all checks.
#[derive(Debug)]
pub(crate) struct Prepared {
    pub(crate) method: reqwest::Method,
    pub(crate) url: url::Url,
    pub(crate) host: String,
    pub(crate) addrs: Vec<SocketAddr>,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<String>,
}

fn refuse<T>(msg: impl Into<String>) -> Result<T> {
    Err(WardenError::Config(format!(
        "request refused: {}",
        msg.into()
    )))
}

/// Return true when `ip` is not a public unicast address.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b)) // CGNAT 100.64.0.0/10
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // TEST-NET-1
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // TEST-NET-2
        || (a == 203 && b == 0 && c == 113) // TEST-NET-3
        || a >= 240 // reserved
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return forbidden_v4(v4);
    }
    let s = ip.segments();
    // fe80::/10 link-local, fec0::/10 site-local, fc00::/7 unique local.
    if (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0 || (s[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    let embedded =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    // IPv4-compatible (::a.b.c.d), NAT64 (64:ff9b::/96), 6to4 (2002::/16): check the embedded v4.
    if s[..6] == [0; 6] {
        return forbidden_v4(embedded(s[6], s[7]));
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return forbidden_v4(embedded(s[6], s[7]));
    }
    if s[0] == 0x2002 {
        return forbidden_v4(embedded(s[1], s[2]));
    }
    // 2001:db8::/32 documentation, 100::/64 discard.
    (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x0100 && s[1..4] == [0; 3])
}

const ALWAYS_FORBIDDEN_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "expect",
];

fn contains_placeholder(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.contains(PLACEHOLDER) || lower.contains("%7b%7bsecret%7d%7d") {
        return true;
    }
    let pct: Vec<u8> = percent_decode(s.as_bytes());
    String::from_utf8_lossy(&pct)
        .to_ascii_lowercase()
        .contains(PLACEHOLDER)
}

fn percent_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&b[i + 1..i + 3]), 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Run all checks. The DNS lookup is the only network access.
pub(crate) async fn preflight(
    policy: &McpPolicy,
    secret: &SecretValue,
    req: &HttpCall,
    resolver: &dyn Resolve,
) -> Result<Prepared> {
    let method = match req.method.to_ascii_uppercase().as_str() {
        m @ ("GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS") => {
            reqwest::Method::from_bytes(m.as_bytes()).expect("valid method")
        }
        other => return refuse(format!("method `{other}` is not allowed")),
    };
    if req
        .body
        .as_ref()
        .is_some_and(|b| b.len() > MAX_REQUEST_BODY)
    {
        return refuse("request body is larger than 1 MiB");
    }
    if contains_placeholder(&req.url) || req.body.as_deref().is_some_and(contains_placeholder) {
        return refuse("the URL and the body must not contain the secret placeholder");
    }
    let url = url::Url::parse(&req.url).or_else(|e| refuse(format!("bad URL: {e}")))?;
    if url.scheme() != "https" {
        return refuse("only https URLs are allowed");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return refuse("a URL with user info is not allowed");
    }
    if url.port().is_some_and(|p| p != 443) {
        return refuse("only port 443 is allowed");
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => return refuse("the URL has no host"),
    };
    if !policy
        .allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&host))
    {
        return refuse(format!(
            "host `{host}` is not in the allowlist of this secret"
        ));
    }

    let own_name = HeaderName::from_bytes(policy.header_name.as_bytes())
        .or_else(|_| refuse("the policy header name is not valid"))?;
    let mut headers = HeaderMap::new();
    for (name, value) in &req.headers {
        let hn = HeaderName::from_bytes(name.as_bytes())
            .or_else(|_| refuse(format!("bad header name `{name}`")))?;
        let lname = hn.as_str();
        if hn == own_name
            || ALWAYS_FORBIDDEN_HEADERS.contains(&lname)
            || lname.starts_with("proxy-")
        {
            return refuse(format!("header `{name}` is not allowed"));
        }
        if contains_placeholder(value) {
            return refuse("a header value must not contain the secret placeholder");
        }
        let hv = HeaderValue::from_str(value)
            .or_else(|_| refuse(format!("bad value for header `{name}`")))?;
        headers.append(hn, hv);
    }
    let mut injected = HeaderValue::from_str(&policy.render_header(secret.expose()))
        .or_else(|_| refuse("the rendered secret header is not valid"))?;
    injected.set_sensitive(true);
    headers.insert(own_name, injected);

    let ips: Vec<IpAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![IpAddr::V4(ip)],
        Some(url::Host::Ipv6(ip)) => vec![IpAddr::V6(ip)],
        _ => resolver
            .lookup(&host)
            .await
            .or_else(|e| refuse(format!("DNS lookup failed: {e}")))?,
    };
    if ips.is_empty() {
        return refuse("DNS returned no address");
    }
    if let Some(bad) = ips.iter().find(|ip| is_forbidden_ip(**ip)) {
        return refuse(format!("host resolves to a non-public address ({bad})"));
    }
    Ok(Prepared {
        method,
        url,
        host,
        addrs: ips.into_iter().map(|ip| SocketAddr::new(ip, 443)).collect(),
        headers,
        body: req.body.clone(),
    })
}

/// All textual forms of the values that the proxy removes from a response, longest first.
pub(crate) fn redaction_forms(values: &[&str]) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    for v in values.iter().filter(|v| !v.is_empty()) {
        let b = v.as_bytes();
        forms.push((*v).to_owned());
        forms.push(STANDARD.encode(b));
        forms.push(STANDARD_NO_PAD.encode(b));
        forms.push(URL_SAFE.encode(b));
        forms.push(URL_SAFE_NO_PAD.encode(b));
        forms.push(hex::encode(b));
        forms.push(hex::encode_upper(b));
        forms.push(url::form_urlencoded::byte_serialize(b).collect());
        forms.push(percent_encode_all(b));
    }
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    forms.dedup();
    forms
}

fn percent_encode_all(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        if x.is_ascii_alphanumeric() || matches!(x, b'-' | b'_' | b'.' | b'~') {
            s.push(*x as char);
        } else {
            s.push_str(&format!("%{x:02X}"));
        }
    }
    s
}

/// Replace every form in `forms` with [`REDACTED`].
pub(crate) fn redact(text: &str, forms: &[String]) -> String {
    let mut out = text.to_owned();
    for f in forms {
        if out.contains(f.as_str()) {
            out = out.replace(f.as_str(), REDACTED);
        }
    }
    out
}

/// Send a checked request and return the redacted answer.
pub(crate) async fn send(p: Prepared, forms: &[String]) -> Result<HttpResult> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .no_proxy()
        .resolve_to_addrs(&p.host, &p.addrs)
        .user_agent(concat!("aivory-warden/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| WardenError::Provider(format!("http client: {e}")))?;
    let mut rb = client.request(p.method, p.url).headers(p.headers);
    if let Some(b) = p.body {
        rb = rb.body(b);
    }
    let mut resp = rb.send().await.map_err(|e| {
        WardenError::Provider(format!(
            "http request failed: {}",
            redact(&e.to_string(), forms)
        ))
    })?;
    let status = resp.status().as_u16();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in resp.headers() {
        let val = redact(&String::from_utf8_lossy(v.as_bytes()), forms);
        headers
            .entry(k.as_str().to_owned())
            .and_modify(|e| {
                e.push_str(", ");
                e.push_str(&val);
            })
            .or_insert(val);
    }
    // Read a little beyond the limit so that a secret at the cut point is still redacted whole.
    let slack = forms.iter().map(String::len).max().unwrap_or(0);
    let read_cap = MAX_RESPONSE_BODY + slack;
    let mut buf: Vec<u8> = Vec::new();
    let mut over = false;
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        WardenError::Provider(format!(
            "http body failed: {}",
            redact(&e.to_string(), forms)
        ))
    })? {
        buf.extend_from_slice(&chunk);
        if buf.len() > read_cap {
            over = true;
            break;
        }
    }
    let mut text = redact(&String::from_utf8_lossy(&buf), forms);
    let mut truncated = over;
    if text.len() > MAX_RESPONSE_BODY {
        let mut cut = MAX_RESPONSE_BODY;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        truncated = true;
    }
    Ok(HttpResult {
        status,
        headers,
        body: text,
        truncated,
    })
}

/// Execute `req` under `policy` with `secret` in the policy header. Uses the system resolver.
///
/// Refuses (with `WardenError::Config`) a request that breaks the policy. The result never
/// contains the secret.
pub async fn execute(
    policy: &McpPolicy,
    secret: &SecretValue,
    req: HttpCall,
) -> Result<HttpResult> {
    execute_with_resolver(policy, secret, req, &SystemResolver).await
}

/// Like [`execute`] with a custom DNS resolver.
pub async fn execute_with_resolver(
    policy: &McpPolicy,
    secret: &SecretValue,
    req: HttpCall,
    resolver: &dyn Resolve,
) -> Result<HttpResult> {
    let prepared = preflight(policy, secret, &req, resolver).await?;
    let rendered = policy.render_header(secret.expose());
    let forms = redaction_forms(&[secret.expose(), &rendered]);
    send(prepared, &forms).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SECRET: &str = "aivw_test_SECRET-value+/42=";

    struct Fixed(Vec<IpAddr>);
    #[async_trait]
    impl Resolve for Fixed {
        async fn lookup(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    fn pub_ip() -> Fixed {
        Fixed(vec!["93.184.216.34".parse().unwrap()])
    }

    fn policy() -> McpPolicy {
        McpPolicy {
            allowed_hosts: vec!["api.example.com".into()],
            ..McpPolicy::default()
        }
    }

    fn call(url: &str) -> HttpCall {
        HttpCall {
            method: "GET".into(),
            url: url.into(),
            ..HttpCall::default()
        }
    }

    async fn pre(req: HttpCall, r: &dyn Resolve) -> Result<Prepared> {
        preflight(&policy(), &SecretValue::new(SECRET), &req, r).await
    }

    #[tokio::test]
    async fn accepts_good_request() {
        let p = pre(call("https://api.example.com/v1/x?a=1"), &pub_ip())
            .await
            .unwrap();
        assert_eq!(p.addrs[0].port(), 443);
        assert_eq!(
            p.headers.get("authorization").unwrap().to_str().unwrap(),
            format!("Bearer {SECRET}")
        );
    }

    #[tokio::test]
    async fn refuses_bad_requests() {
        let bad = [
            call("http://api.example.com/"),
            call("https://evil.example.com/"),
            call("https://sub.api.example.com/"),
            call("https://api.example.com:8443/"),
            call("https://user:pw@api.example.com/"),
            call("https://api.example.com/?k={{secret}}"),
            call("https://api.example.com/?k=%7B%7Bsecret%7D%7D"),
            HttpCall {
                body: Some("x {{secret}} y".into()),
                ..call("https://api.example.com/")
            },
            HttpCall {
                method: "CONNECT".into(),
                ..call("https://api.example.com/")
            },
            HttpCall {
                body: Some("x".repeat(MAX_REQUEST_BODY + 1)),
                method: "POST".into(),
                ..call("https://api.example.com/")
            },
        ];
        for r in bad {
            let url = r.url.clone();
            assert!(pre(r, &pub_ip()).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn refuses_forbidden_headers() {
        for h in [
            "Authorization",
            "cookie",
            "Proxy-Authorization",
            "HOST",
            "x-a",
        ] {
            let mut r = call("https://api.example.com/");
            let v = if h == "x-a" { "{{secret}}" } else { "v" };
            r.headers.insert(h.into(), v.into());
            assert!(pre(r, &pub_ip()).await.is_err(), "{h}");
        }
        let mut pol = policy();
        pol.header_name = "X-Api-Key".into();
        let mut r = call("https://api.example.com/");
        r.headers.insert("x-api-key".into(), "mine".into());
        let e = preflight(&pol, &SecretValue::new(SECRET), &r, &pub_ip()).await;
        assert!(e.is_err());
    }

    #[tokio::test]
    async fn refuses_private_dns_answers() {
        for ip in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "192.168.1.1",
            "172.16.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
        ] {
            let r = Fixed(vec![ip.parse().unwrap()]);
            assert!(
                pre(call("https://api.example.com/"), &r).await.is_err(),
                "{ip}"
            );
        }
        let mixed = Fixed(vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ]);
        assert!(pre(call("https://api.example.com/"), &mixed).await.is_err());
        assert!(!is_forbidden_ip("93.184.216.34".parse().unwrap()));
        assert!(!is_forbidden_ip("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn redacts_all_forms() {
        let forms = redaction_forms(&[SECRET]);
        let b = SECRET.as_bytes();
        let echoes = [
            SECRET.to_owned(),
            STANDARD.encode(b),
            URL_SAFE_NO_PAD.encode(b),
            hex::encode(b),
            hex::encode_upper(b),
            percent_encode_all(b),
            url::form_urlencoded::byte_serialize(b).collect::<String>(),
        ];
        for e in echoes {
            let out = redact(&format!("a {e} b"), &forms);
            assert_eq!(out, format!("a {REDACTED} b"));
        }
    }

    /// Serve one plain-HTTP answer on loopback. Returns the port.
    async fn serve_once(response: Vec<u8>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(&response).await;
            let _ = s.shutdown().await;
        });
        port
    }

    fn prepared_local(port: u16) -> Prepared {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer x"));
        Prepared {
            method: reqwest::Method::GET,
            url: url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
            host: "127.0.0.1".into(),
            addrs: vec![SocketAddr::new("127.0.0.1".parse().unwrap(), port)],
            headers,
            body: None,
        }
    }

    #[tokio::test]
    async fn redirect_is_not_followed_and_echo_is_redacted() {
        let b64 = STANDARD.encode(SECRET);
        let body = format!("plain={SECRET} b64={b64} hex={}", hex::encode(SECRET));
        let resp = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/next\r\nX-Echo: {SECRET}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let port = serve_once(resp.into_bytes()).await;
        let forms = redaction_forms(&[SECRET]);
        let r = send(prepared_local(port), &forms).await.unwrap();
        assert_eq!(r.status, 302);
        assert!(r.headers["location"].contains("/next"));
        let all = format!("{:?} {}", r.headers, r.body);
        assert!(!all.contains(SECRET));
        assert!(!all.contains(&b64));
        assert!(!all.contains(&hex::encode(SECRET)));
        assert!(r.body.contains(REDACTED));
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn large_response_is_truncated() {
        let body = "a".repeat(MAX_RESPONSE_BODY + 1000);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let port = serve_once(resp.into_bytes()).await;
        let r = send(prepared_local(port), &[]).await.unwrap();
        assert!(r.truncated);
        assert_eq!(r.body.len(), MAX_RESPONSE_BODY);
    }
}
