//! Finding and downloading a published MassRelay release, anonymously.
//!
//! Everything comes from the public GitHub repository over HTTPS: the latest stable release
//! from the API, then `SHA256SUMS` and this platform's artifact from that release's download
//! path. No credential of any kind is sent or looked for: no token, GitHub CLI session, netrc
//! or credential store. A repository or release that cannot be read anonymously is an error.
//!
//! What is checked before a byte is kept:
//!
//! - every request and redirect is HTTPS, with a bounded number of redirects;
//! - each response has a size limit and a deadline, and stalls time out;
//! - the release is stable (not a draft or prerelease) and its tag is exactly `vMAJOR.MINOR.PATCH`;
//! - `SHA256SUMS` names this platform's artifact exactly once, and the downloaded bytes hash to
//!   that value.
//!
//! The download source is fixed. Tests inject a local HTTPS fixture.

use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh_relay::tls::{CaTlsConfig, default_provider};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const REPOSITORY: &str = "zorkian/massrelay";
const CHECKSUMS: &str = "SHA256SUMS";
const MAX_REDIRECTS: usize = 5;
const MAX_METADATA: usize = 1 << 20;
const MAX_CHECKSUMS: usize = 64 << 10;
/// Several times the largest released artifact.
const MAX_ARTIFACT: usize = 256 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// The longest wait for more bytes of a response.
const STALL_TIMEOUT: Duration = Duration::from_secs(30);
const METADATA_DEADLINE: Duration = Duration::from_secs(60);
const ARTIFACT_DEADLINE: Duration = Duration::from_secs(15 * 60);

/// A stable release version, compared by its numeric components.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Version {
    /// Exactly `MAJOR.MINOR.PATCH` in decimal digits.
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.').map(|part| {
            let plain = !part.is_empty()
                && part.len() <= 9
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'));
            plain.then(|| part.parse::<u64>().ok()).flatten()
        });
        let version = Self {
            major: parts.next()??,
            minor: parts.next()??,
            patch: parts.next()??,
        };
        parts.next().is_none().then_some(version)
    }

    fn from_tag(tag: &str) -> Option<Self> {
        Self::parse(tag.strip_prefix('v')?)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The release artifact built for this platform, by its packaging name.
pub fn asset() -> Result<&'static str> {
    let name = if cfg!(all(target_os = "linux", target_env = "gnu")) {
        if cfg!(target_arch = "x86_64") {
            Some("massrelay-linux-x86_64")
        } else if cfg!(target_arch = "aarch64") {
            Some("massrelay-linux-aarch64")
        } else {
            None
        }
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "x86_64") {
            Some("massrelay-macos-x86_64")
        } else if cfg!(target_arch = "aarch64") {
            Some("massrelay-macos-aarch64")
        } else {
            None
        }
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Some("massrelay-windows-x86_64.exe")
    } else {
        None
    };
    name.context("MassRelay publishes no release binary for this platform; update from source")
}

/// A published stable release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub version: Version,
}

/// Where releases come from. Only the public GitHub repository outside tests.
pub struct Source {
    api: String,
    downloads: String,
    tls: CaTlsConfig,
    /// Whether the standard proxy environment variables apply.
    proxies: bool,
}

impl Source {
    pub fn github() -> Self {
        Self {
            api: "https://api.github.com".into(),
            downloads: "https://github.com".into(),
            tls: CaTlsConfig::embedded(),
            proxies: true,
        }
    }

    pub fn client(&self) -> Result<Client<'_>> {
        let tls = self
            .tls
            .client_config(default_provider())
            .context("prepare TLS certificate verification")?;
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.url().scheme() != "https" {
                    attempt.error("refusing a redirect that leaves HTTPS")
                } else if attempt.previous().len() > MAX_REDIRECTS {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(STALL_TIMEOUT)
            .user_agent(concat!("massrelay-update/", env!("CARGO_PKG_VERSION")));
        if !self.proxies {
            builder = builder.no_proxy();
        }
        Ok(Client {
            source: self,
            http: builder.build().context("prepare the HTTPS client")?,
        })
    }
}

pub struct Client<'s> {
    source: &'s Source,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct Latest {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

impl Client<'_> {
    /// The latest stable release.
    pub async fn latest(&self) -> Result<Release> {
        let url = format!("{}/repos/{REPOSITORY}/releases/latest", self.source.api);
        let mut body = Vec::new();
        self.fetch(
            &url,
            "the latest release",
            MAX_METADATA,
            METADATA_DEADLINE,
            |chunk| {
                body.extend_from_slice(chunk);
                Ok(())
            },
        )
        .await?;
        let latest: Latest =
            serde_json::from_slice(&body).context("GitHub's release description is not valid")?;
        ensure!(
            !latest.draft && !latest.prerelease,
            "the latest release is not a stable release"
        );
        let version = Version::from_tag(&latest.tag_name).with_context(|| {
            format!(
                "the latest release tag {:?} is not a stable version such as v1.2.3",
                crate::visible(&latest.tag_name)
            )
        })?;
        Ok(Release {
            tag: latest.tag_name,
            version,
        })
    }

    /// The published SHA-256 of `asset` in `release`.
    pub async fn checksum(&self, release: &Release, asset: &str) -> Result<[u8; 32]> {
        let mut body = Vec::new();
        self.fetch(
            &self.download_url(release, CHECKSUMS),
            "the release checksums",
            MAX_CHECKSUMS,
            METADATA_DEADLINE,
            |chunk| {
                body.extend_from_slice(chunk);
                Ok(())
            },
        )
        .await?;
        let text = String::from_utf8(body)
            .ok()
            .context("the release checksums are not text")?;
        published_checksum(&text, asset)
    }

    /// Download `asset` into `sink` and require its SHA-256 to be `expected`. The caller
    /// discards what the sink received when this fails.
    pub async fn download(
        &self,
        release: &Release,
        asset: &str,
        expected: &[u8; 32],
        mut sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut hash = Sha256::new();
        self.fetch(
            &self.download_url(release, asset),
            "the release binary",
            MAX_ARTIFACT,
            ARTIFACT_DEADLINE,
            |chunk| {
                hash.update(chunk);
                sink(chunk)
            },
        )
        .await?;
        ensure!(
            hash.finalize().as_slice() == expected,
            "the downloaded {asset} does not match the checksum published for {}; it was discarded",
            release.tag
        );
        Ok(())
    }

    fn download_url(&self, release: &Release, file: &str) -> String {
        // The tag is a checked version and the file one of this module's own names.
        format!(
            "{}/{REPOSITORY}/releases/download/{}/{file}",
            self.source.downloads, release.tag
        )
    }

    async fn fetch(
        &self,
        url: &str,
        what: &str,
        max: usize,
        deadline: Duration,
        mut sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let unreachable = |error: reqwest::Error| {
            // The cause chain says why (a refused redirect, a certificate, a timeout).
            let mut causes = vec![];
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                causes.push(cause.to_string());
                source = cause.source();
            }
            let cause = causes.last().cloned().unwrap_or_else(|| error.to_string());
            anyhow!("could not download {what} from GitHub: {cause}")
        };
        let transfer = async {
            let mut response = self.http.get(url).send().await.map_err(unreachable)?;
            let status = response.status().as_u16();
            match status {
                200 => {}
                404 => bail!(
                    "{what} of {REPOSITORY} cannot be read without signing in (HTTP 404). \
                     'massrelay update' only uses public GitHub releases"
                ),
                403 | 429 => bail!(
                    "GitHub refused the anonymous request for {what} (HTTP {status}), usually \
                     because of its rate limit. Try again later"
                ),
                _ => bail!("GitHub answered HTTP {status} for {what}"),
            }
            let too_large = || anyhow!("{what} is larger than {max} bytes; refusing it");
            if response
                .content_length()
                .is_some_and(|len| len > max as u64)
            {
                return Err(too_large());
            }
            let mut received = 0usize;
            while let Some(chunk) = response.chunk().await.map_err(unreachable)? {
                received += chunk.len();
                if received > max {
                    return Err(too_large());
                }
                sink(&chunk)?;
            }
            Ok(())
        };
        tokio::time::timeout(deadline, transfer)
            .await
            .map_err(|_| anyhow!("downloading {what} took longer than {deadline:?}"))?
    }
}

/// The digest `sha256sum` published for exactly `asset`, which must be listed once.
fn published_checksum(text: &str, asset: &str) -> Result<[u8; 32]> {
    let mut found = None;
    for line in text.lines() {
        let Some((digest, name)) = line.split_once(' ') else {
            continue;
        };
        // `sha256sum` writes two spaces, or a space and `*` for binary mode.
        let name = name
            .strip_prefix(' ')
            .or_else(|| name.strip_prefix('*'))
            .unwrap_or(name);
        if name.trim_end() != asset {
            continue;
        }
        ensure!(
            found.is_none(),
            "the release lists more than one checksum for {asset}"
        );
        let mut bytes = [0u8; 32];
        let valid = digest.len() == 64
            && digest.is_ascii()
            && bytes.iter_mut().enumerate().all(|(index, byte)| {
                u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
                    .map(|value| *byte = value)
                    .is_ok()
            });
        ensure!(valid, "the release checksum for {asset} is malformed");
        found = Some(bytes);
    }
    found.with_context(|| format!("the release lists no checksum for {asset}"))
}

#[cfg(test)]
pub mod fixture {
    //! A disposable HTTPS server standing in for GitHub.

    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// One canned answer: a status, an optional redirect target and a body.
    #[derive(Clone)]
    pub struct Answer {
        pub status: u16,
        pub location: Option<String>,
        pub body: Vec<u8>,
    }

    impl Answer {
        pub fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: 200,
                location: None,
                body: body.into(),
            }
        }

        pub fn status(status: u16) -> Self {
            Self {
                status,
                location: None,
                body: vec![],
            }
        }

        pub fn redirect(location: impl Into<String>) -> Self {
            Self {
                status: 302,
                location: Some(location.into()),
                body: vec![],
            }
        }
    }

    pub struct Server {
        pub base: String,
        pub routes: Arc<Mutex<BTreeMap<String, Answer>>>,
        certificate: rustls::pki_types::CertificateDer<'static>,
    }

    impl Server {
        pub async fn start() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec![Ipv4Addr::LOCALHOST.to_string()]).unwrap();
            let certificate = cert.der().clone();
            let config = rustls::ServerConfig::builder_with_provider(default_provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.clone()],
                    PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
                )
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let base = format!("https://{}", listener.local_addr().unwrap());
            let routes: Arc<Mutex<BTreeMap<String, Answer>>> = Arc::default();
            let served = routes.clone();
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let (acceptor, served) = (acceptor.clone(), served.clone());
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(socket).await else {
                            return;
                        };
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                                return;
                            }
                            head.push(byte[0]);
                        }
                        let head = String::from_utf8_lossy(&head).into_owned();
                        // A credential on any request fails the test that sent it.
                        let lower = head.to_ascii_lowercase();
                        assert!(!lower.contains("authorization:") && !lower.contains("cookie:"));
                        let path = head.split(' ').nth(1).unwrap_or("/").to_owned();
                        let answer = served
                            .lock()
                            .unwrap()
                            .get(&path)
                            .cloned()
                            .unwrap_or_else(|| Answer::status(404));
                        let location = answer
                            .location
                            .map(|to| format!("Location: {to}\r\n"))
                            .unwrap_or_default();
                        let head = format!(
                            "HTTP/1.1 {} Fixture\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n",
                            answer.status,
                            answer.body.len()
                        );
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.write_all(&answer.body).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                base,
                routes,
                certificate,
            }
        }

        pub fn source(&self) -> Source {
            Source {
                api: self.base.clone(),
                downloads: self.base.clone(),
                tls: CaTlsConfig::custom_roots([self.certificate.clone()]),
                proxies: false,
            }
        }

        pub fn route(&self, path: impl Into<String>, answer: Answer) {
            self.routes.lock().unwrap().insert(path.into(), answer);
        }

        /// Publish `tag` with `artifact` as this platform's binary and a matching checksum.
        pub fn publish(&self, tag: &str, artifact: &[u8]) {
            let asset = asset().unwrap();
            self.route(
                format!("/repos/{REPOSITORY}/releases/latest"),
                Answer::ok(format!(
                    r#"{{"tag_name":"{tag}","draft":false,"prerelease":false}}"#
                )),
            );
            let digest = Sha256::digest(artifact);
            self.route(
                format!("/{REPOSITORY}/releases/download/{tag}/SHA256SUMS"),
                Answer::ok(format!(
                    "{}  massrelay-other-platform\n{digest:x}  {asset}\n",
                    "0".repeat(64)
                )),
            );
            self.route(
                format!("/{REPOSITORY}/releases/download/{tag}/{asset}"),
                Answer::ok(artifact),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{Answer, Server};
    use super::*;

    #[test]
    fn versions_compare_by_numeric_components() {
        let version = |text| Version::parse(text).unwrap();
        assert!(version("0.10.0") > version("0.9.9"));
        assert!(version("1.0.0") > version("0.99.99"));
        assert!(version("0.5.3") == version("0.5.3"));
        assert_eq!(Version::from_tag("v0.5.3"), Some(version("0.5.3")));
        assert_eq!(version("12.0.7").to_string(), "12.0.7");
        // Only stable three-part versions are releases to update to.
        for text in [
            "1.2",
            "1.2.3.4",
            "1.2.3-rc.1",
            "1.2.x",
            "01.2.3",
            "",
            "1..3",
            "+1.2.3",
        ] {
            assert_eq!(Version::parse(text), None, "{text}");
        }
        assert_eq!(Version::from_tag("0.5.3"), None);
        assert_eq!(Version::from_tag("v0.5.3-beta"), None);
    }

    #[test]
    fn the_checksum_must_name_the_exact_artifact_once() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let list = format!("{a}  massrelay-linux-x86_64\n{b} *massrelay-linux-aarch64\n");
        assert_eq!(
            published_checksum(&list, "massrelay-linux-x86_64").unwrap(),
            [0xaa; 32]
        );
        assert_eq!(
            published_checksum(&list, "massrelay-linux-aarch64").unwrap(),
            [0xbb; 32]
        );
        // A longer or shorter name is another artifact.
        assert!(published_checksum(&list, "massrelay-linux-x86").is_err());
        assert!(published_checksum(&list, "massrelay-linux-x86_64.exe").is_err());
        let twice = format!("{list}{b}  massrelay-linux-x86_64\n");
        assert!(published_checksum(&twice, "massrelay-linux-x86_64").is_err());
        let short = format!("{}  massrelay-linux-x86_64\n", "a".repeat(63));
        assert!(published_checksum(&short, "massrelay-linux-x86_64").is_err());
        let odd = format!("{}  massrelay-linux-x86_64\n", "g".repeat(64));
        assert!(published_checksum(&odd, "massrelay-linux-x86_64").is_err());
    }

    async fn download(server: &Server) -> Result<(Release, Vec<u8>)> {
        let source = server.source();
        let client = source.client()?;
        let release = client.latest().await?;
        let asset = asset()?;
        let expected = client.checksum(&release, asset).await?;
        let mut bytes = Vec::new();
        client
            .download(&release, asset, &expected, |chunk| {
                bytes.extend_from_slice(chunk);
                Ok(())
            })
            .await?;
        Ok((release, bytes))
    }

    #[tokio::test]
    #[ignore = "opens a disposable HTTPS server on loopback"]
    async fn a_published_release_downloads_and_verifies_over_https() {
        let server = Server::start().await;
        server.publish("v9.8.7", b"the new program");
        let (release, bytes) = download(&server).await.unwrap();
        assert_eq!(release.version, Version::parse("9.8.7").unwrap());
        assert_eq!(bytes, b"the new program");
    }

    #[tokio::test]
    #[ignore = "opens a disposable HTTPS server on loopback"]
    async fn a_binary_that_does_not_match_its_checksum_is_refused() {
        let server = Server::start().await;
        server.publish("v9.8.7", b"the new program");
        let asset = asset().unwrap();
        let binary = format!("/{REPOSITORY}/releases/download/v9.8.7/{asset}");
        server.route(&binary, Answer::ok("a different program"));
        let error = download(&server).await.unwrap_err();
        assert!(format!("{error:#}").contains("does not match the checksum"));

        // No checksum for this platform, or two of them, is refused before the binary is read.
        let sums = format!("/{REPOSITORY}/releases/download/v9.8.7/SHA256SUMS");
        server.route(
            &sums,
            Answer::ok(format!("{}  another-file\n", "0".repeat(64))),
        );
        server.route(&binary, Answer::status(500));
        let error = download(&server).await.unwrap_err();
        assert!(format!("{error:#}").contains("lists no checksum"));
    }

    #[tokio::test]
    #[ignore = "opens a disposable HTTPS server on loopback"]
    async fn releases_that_are_private_unstable_or_oversized_are_refused() {
        let server = Server::start().await;
        // Nothing is published: what a private repository answers anonymously.
        let error = download(&server).await.unwrap_err();
        assert!(format!("{error:#}").contains("cannot be read without signing in"));

        let latest = format!("/repos/{REPOSITORY}/releases/latest");
        server.route(&latest, Answer::status(403));
        let error = download(&server).await.unwrap_err();
        assert!(format!("{error:#}").contains("rate limit"));

        for body in [
            r#"{"tag_name":"v1.2.3-rc.1"}"#,
            r#"{"tag_name":"v1.2.3","prerelease":true}"#,
            r#"{"tag_name":"../../evil"}"#,
        ] {
            server.route(&latest, Answer::ok(body));
            assert!(download(&server).await.is_err(), "{body}");
        }

        server.publish("v9.8.7", b"the new program");
        let sums = format!("/{REPOSITORY}/releases/download/v9.8.7/SHA256SUMS");
        server.route(&sums, Answer::ok(vec![b'0'; MAX_CHECKSUMS + 1]));
        let error = download(&server).await.unwrap_err();
        assert!(format!("{error:#}").contains("larger than"));
    }

    #[tokio::test]
    #[ignore = "opens a disposable HTTPS server on loopback"]
    async fn only_https_redirects_are_followed() {
        let server = Server::start().await;
        server.publish("v9.8.7", b"the new program");
        let asset = asset().unwrap();
        let binary = format!("/{REPOSITORY}/releases/download/v9.8.7/{asset}");
        // GitHub redirects downloads to its storage host over HTTPS.
        server.route("/storage", Answer::ok("the new program"));
        server.route(
            &binary,
            Answer::redirect(format!("{}/storage", server.base)),
        );
        assert_eq!(download(&server).await.unwrap().1, b"the new program");

        let plain = server.base.replacen("https://", "http://", 1);
        server.route(&binary, Answer::redirect(format!("{plain}/storage")));
        let error = download(&server).await.unwrap_err();
        assert!(format!("{error:#}").contains("could not download"));

        server.route(&binary, Answer::redirect(binary.clone()));
        assert!(download(&server).await.is_err());
    }
}
