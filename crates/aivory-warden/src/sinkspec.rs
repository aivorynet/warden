//! Parse `--sink` specs such as `dotenv:PATH:KEY`.
//!
//! Forms:
//!
//! - `dotenv:PATH:KEY`
//! - `json:PATH:/pointer`
//! - `toml:PATH:a.b` and `yaml:PATH:a.b`
//! - `ssh:user@host[:port]:/remote/path:dotenv|json|toml|yaml:KEY`
//! - `env:NAME`
//!
//! The key is the text after the last colon, so a Windows drive letter in PATH works.

use std::path::{Path, PathBuf};
use warden_core::{RemoteFormat, Result, SinkSpec, WardenError};

/// Defaults for the SSH identity and known_hosts files.
#[derive(Debug, Clone)]
pub struct SshDefaults {
    /// Private key file.
    pub identity_file: PathBuf,
    /// known_hosts file.
    pub known_hosts: PathBuf,
}

fn bad(msg: &str) -> WardenError {
    WardenError::Config(format!("bad sink spec: {msg}"))
}

fn abs(p: &str) -> Result<PathBuf> {
    std::path::absolute(Path::new(p)).map_err(|e| bad(&format!("cannot resolve path: {e}")))
}

fn key_path(k: &str) -> Vec<String> {
    k.split('.').map(str::to_owned).collect()
}

/// Parse one sink spec. File paths become absolute.
pub fn parse(spec: &str, ssh: &SshDefaults) -> Result<SinkSpec> {
    let (kind, rest) = spec.split_once(':').ok_or_else(|| bad("missing `:`"))?;
    match kind {
        "env" => {
            if rest.is_empty() {
                return Err(bad("env needs a name"));
            }
            Ok(SinkSpec::EnvVar { name: rest.into() })
        }
        "dotenv" | "json" | "toml" | "yaml" => {
            let (path, key) = rest
                .rsplit_once(':')
                .filter(|(p, k)| !p.is_empty() && !k.is_empty())
                .ok_or_else(|| bad("use KIND:PATH:KEY"))?;
            let path = abs(path)?;
            Ok(match kind {
                "dotenv" => SinkSpec::Dotenv {
                    path,
                    key: key.into(),
                },
                "json" => SinkSpec::Json {
                    path,
                    pointer: key.into(),
                },
                "toml" => SinkSpec::Toml {
                    path,
                    key_path: key_path(key),
                },
                _ => SinkSpec::Yaml {
                    path,
                    key_path: key_path(key),
                },
            })
        }
        "ssh" => parse_ssh(rest, ssh),
        other => Err(bad(&format!("unknown kind `{other}`"))),
    }
}

fn parse_ssh(rest: &str, ssh: &SshDefaults) -> Result<SinkSpec> {
    let usage = || bad("use ssh:user@host[:port]:/path:FORMAT:KEY");
    let (userhost, rest) = rest.split_once(':').ok_or_else(usage)?;
    let (user, host) = userhost.split_once('@').ok_or_else(usage)?;
    let (port, rest) = match rest.split_once(':') {
        Some((p, r)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (p.parse::<u16>().map_err(|_| bad("bad port"))?, r)
        }
        _ => (22, rest),
    };
    let (rest, key) = rest.rsplit_once(':').ok_or_else(usage)?;
    let (path, fmt) = rest.rsplit_once(':').ok_or_else(usage)?;
    if user.is_empty() || host.is_empty() || !path.starts_with('/') || key.is_empty() {
        return Err(usage());
    }
    let format = match fmt {
        "dotenv" => RemoteFormat::Dotenv { key: key.into() },
        "json" => RemoteFormat::Json {
            pointer: key.into(),
        },
        "toml" => RemoteFormat::Toml {
            key_path: key_path(key),
        },
        "yaml" => RemoteFormat::Yaml {
            key_path: key_path(key),
        },
        _ => return Err(bad("remote format must be dotenv, json, toml or yaml")),
    };
    Ok(SinkSpec::Ssh {
        host: host.into(),
        port,
        user: user.into(),
        identity_file: ssh.identity_file.clone(),
        known_hosts: ssh.known_hosts.clone(),
        remote_path: path.into(),
        format: Box::new(format),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> SshDefaults {
        SshDefaults {
            identity_file: "id".into(),
            known_hosts: "kh".into(),
        }
    }

    #[test]
    fn file_sinks() {
        let s = parse("toml:/etc/a.toml:a.b", &d()).unwrap();
        assert!(matches!(s, SinkSpec::Toml { key_path, .. } if key_path == ["a", "b"]));
        let s = parse("json:/x/y.json:/a/b", &d()).unwrap();
        assert!(matches!(s, SinkSpec::Json { pointer, .. } if pointer == "/a/b"));
        let s = parse(r"dotenv:C:\work\.env:TOKEN", &d()).unwrap();
        assert!(matches!(s, SinkSpec::Dotenv { key, .. } if key == "TOKEN"));
    }

    #[test]
    fn env_sink() {
        assert_eq!(
            parse("env:MY_TOKEN", &d()).unwrap(),
            SinkSpec::EnvVar {
                name: "MY_TOKEN".into()
            }
        );
    }

    #[test]
    fn ssh_sink_with_and_without_port() {
        let s = parse("ssh:ops@edge:/etc/caddy/env:dotenv:CF", &d()).unwrap();
        match s {
            SinkSpec::Ssh {
                host,
                port,
                user,
                remote_path,
                format,
                ..
            } => {
                assert_eq!((host.as_str(), port, user.as_str()), ("edge", 22, "ops"));
                assert_eq!(remote_path, "/etc/caddy/env");
                assert_eq!(*format, RemoteFormat::Dotenv { key: "CF".into() });
            }
            _ => panic!("not ssh"),
        }
        let s = parse("ssh:u@h:2222:/p/c.toml:toml:a.b", &d()).unwrap();
        assert!(matches!(s, SinkSpec::Ssh { port: 2222, .. }));
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(parse("nope", &d()).is_err());
        assert!(parse("dotenv:onlypath", &d()).is_err());
        assert!(parse("ftp:a:b", &d()).is_err());
        assert!(parse("ssh:host:/p:toml:a", &d()).is_err());
    }
}
