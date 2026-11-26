//! Endpoint-key bindings.
//!
//! An MLS credential in a private network is a `BasicCredential` whose
//! identity is a `CredentialBinding`: the device's Iroh endpoint key signs its
//! MLS signature key for one group and protocol version. Every Add recipient
//! and every Welcome joiner verifies the binding, so a leaf can only claim an
//! endpoint whose secret key signed that exact MLS key.
//!
//! A version 2 binding also signs the device's display name. The name lives
//! only in the encrypted request and MLS state, so the relay never sees it,
//! and it is cosmetic: the endpoint key stays the identity, two devices may
//! share a name, and no check ever trusts one.
//!
//! The joiner's detached admission proof (`JoinTranscript`) is a second
//! endpoint-key signature over the exact invite, issuer, relay incarnation and
//! KeyPackage reference.
//!
//! Endpoint signatures use ed25519-dalek `verify_strict`. A rejected
//! signature is reported as `SigReject` and never retried.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use openmls::prelude::{BasicCredential, Credential, CredentialType};

use super::PROTOCOL;
use super::codec::{Dec, DecodeError, Enc, Hash, hash};

pub const BINDING_VERSION: u8 = 1;
/// A binding that also carries the device's display name, signed by the
/// endpoint key. Version 1 bindings carry no name and stay valid as such.
pub const NAMED_BINDING_VERSION: u8 = 2;
/// Longest device display name, in bytes.
pub const MAX_DEVICE_NAME: usize = 63;
const BINDING_PURPOSE: &[u8] = b"massrelay-private credential-binding";
const JOIN_PROOF_PURPOSE: &[u8] = b"massrelay-private join-request-proof";

pub type EndpointKey = [u8; 32];

/// A device's Iroh endpoint secret key (Ed25519), as used for bindings.
pub struct EndpointSecret(SigningKey);

impl EndpointSecret {
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(b))
    }

    pub fn generate() -> Self {
        Self::from_bytes(&super::codec::random::<32>())
    }

    /// Test-only: the secret bytes, to build an Iroh endpoint with the same
    /// key. Product code receives the Iroh secret and calls `from_bytes`.
    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> EndpointKey {
        self.0.verifying_key().to_bytes()
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.sign(msg).to_bytes().to_vec()
    }

    /// Raw Ed25519 signature by the endpoint key. Callers sign a
    /// domain-separated hash only (pairing consent).
    pub(crate) fn sign_raw(&self, msg: &[u8]) -> Vec<u8> {
        self.sign(msg)
    }
}

/// A signature check that failed. Signature rejections are surfaced as an
/// unconfirmed verification fault by callers (see `membership::Halt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigReject(pub String);

pub fn verify_ed25519(key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SigReject> {
    let key: &[u8; 32] = key
        .try_into()
        .map_err(|_| SigReject("public key length".into()))?;
    let sig: &[u8; 64] = sig
        .try_into()
        .map_err(|_| SigReject("signature length".into()))?;
    let vk = VerifyingKey::from_bytes(key).map_err(|e| SigReject(format!("public key: {e}")))?;
    let r = vk
        .verify_strict(msg, &Signature::from_bytes(sig))
        .map_err(|e| SigReject(format!("ed25519: {e}")));
    #[cfg(test)]
    if r.is_err() {
        capture_rejection(key, msg, sig);
    }
    r
}

/// Test-only evidence for the open verification-reliability question: on a
/// rejection, record the exact inputs and two re-evaluations of the same
/// bytes to `MR_FORENSICS_DIR` (if set). The original verdict is always
/// returned; nothing is retried or masked.
#[cfg(test)]
fn capture_rejection(key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) {
    use super::codec::hex;
    let Ok(dir) = std::env::var("MR_FORENSICS_DIR") else {
        return;
    };
    let vk = VerifyingKey::from_bytes(key).expect("parsed before");
    let strict_again = vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok();
    let lenient = ed25519_dalek::Verifier::verify(&vk, msg, &Signature::from_bytes(sig)).is_ok();
    let record = format!(
        "pid={}\nthread={:?}\nstrict_recheck_accepts={strict_again}\nlenient_accepts={lenient}\npk={}\nsig={}\nmsg={}\nbacktrace=\n{}\n",
        std::process::id(),
        std::thread::current().name(),
        hex(key),
        hex(sig),
        hex(msg),
        std::backtrace::Backtrace::force_capture()
    );
    let _ = std::fs::create_dir_all(&dir);
    let name = format!(
        "sig-{}-{}.txt",
        std::process::id(),
        hex(&super::codec::random::<6>())
    );
    let _ = std::fs::write(std::path::Path::new(&dir).join(name), record);
}

#[cfg(test)]
mod replay {
    /// Replay captured rejections (`SIG_REPLAY=<file>[:...]`) many times.
    #[test]
    fn replay_captured_rejections() {
        let Ok(files) = std::env::var("SIG_REPLAY") else {
            return;
        };
        for f in files.split(':') {
            let text = std::fs::read_to_string(f).unwrap();
            let get = |k: &str| {
                let line = text
                    .lines()
                    .find(|l| l.starts_with(&format!("{k}=")))
                    .unwrap();
                let h = &line[k.len() + 1..];
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                    .collect::<Vec<u8>>()
            };
            let (pk, sig, msg) = (get("pk"), get("sig"), get("msg"));
            let n: usize = std::env::var("SIG_REPLAY_N")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000);
            let mut ok = 0;
            for _ in 0..n {
                ok += usize::from(super::verify_ed25519(&pk, &msg, &sig).is_ok());
            }
            println!("REPLAY {f}: {ok}/{n} accepted");
        }
    }
}

/// Check a device display name. Every replica applies the same rule when it
/// decodes a binding, so it never consults local state. Names are ASCII
/// letters, digits, `-` and `_`, at most `MAX_DEVICE_NAME` bytes, and never
/// look like an endpoint key, so a name cannot pose as a key selector.
///
/// A name is a cosmetic, self-asserted label: it is never authority. Two
/// devices may carry the same name.
pub fn check_device_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > MAX_DEVICE_NAME
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "a device name must be 1 to {MAX_DEVICE_NAME} ASCII letters, digits, hyphens or underscores"
        ));
    }
    if name.parse::<iroh::EndpointId>().is_ok() {
        return Err("a device name must not look like an endpoint key".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    Malformed(String),
    WrongCredentialType,
    WrongGroup,
    /// The binding names a different MLS signature key than the leaf uses.
    SignatureKeyMismatch,
    Signature(SigReject),
    /// The display name breaks `check_device_name`.
    Name(String),
}

impl From<DecodeError> for BindingError {
    fn from(e: DecodeError) -> Self {
        BindingError::Malformed(e.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBinding {
    pub endpoint: EndpointKey,
    pub group_tag: Hash,
    pub mls_signature_key: Vec<u8>,
    pub signature: Vec<u8>,
    /// Display name the device chose at enrollment, signed with the rest
    /// (version 2). `None` is a version 1 binding. Only cosmetic: it lives in
    /// the encrypted MLS state, so the relay never sees it.
    pub name: Option<String>,
}

impl CredentialBinding {
    fn signed_message(
        endpoint: &EndpointKey,
        group_tag: &Hash,
        mls_key: &[u8],
        name: Option<&str>,
    ) -> Hash {
        match name {
            None => hash(
                BINDING_PURPOSE,
                &[PROTOCOL, &[BINDING_VERSION], group_tag, endpoint, mls_key],
            ),
            Some(n) => hash(
                BINDING_PURPOSE,
                &[
                    PROTOCOL,
                    &[NAMED_BINDING_VERSION],
                    group_tag,
                    endpoint,
                    mls_key,
                    n.as_bytes(),
                ],
            ),
        }
    }

    pub fn create(secret: &EndpointSecret, group_tag: &Hash, mls_signature_key: &[u8]) -> Self {
        Self::create_named(secret, group_tag, mls_signature_key, None)
            .expect("a nameless binding is always valid")
    }

    /// A binding carrying `name` (checked with `check_device_name`), or a
    /// version 1 binding when `name` is `None`.
    pub fn create_named(
        secret: &EndpointSecret,
        group_tag: &Hash,
        mls_signature_key: &[u8],
        name: Option<&str>,
    ) -> Result<Self, BindingError> {
        if let Some(n) = name {
            check_device_name(n).map_err(BindingError::Name)?;
        }
        let endpoint = secret.public();
        let signature = secret.sign(&Self::signed_message(
            &endpoint,
            group_tag,
            mls_signature_key,
            name,
        ));
        Ok(Self {
            endpoint,
            group_tag: *group_tag,
            mls_signature_key: mls_signature_key.to_vec(),
            signature,
            name: name.map(str::to_owned),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u8(if self.name.is_some() {
            NAMED_BINDING_VERSION
        } else {
            BINDING_VERSION
        })
        .bytes(PROTOCOL)
        .fixed(&self.endpoint)
        .fixed(&self.group_tag)
        .bytes(&self.mls_signature_key);
        if let Some(n) = &self.name {
            e.bytes(n.as_bytes());
        }
        e.bytes(&self.signature).finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, BindingError> {
        let mut d = Dec::new(b);
        let version = d.u8()?;
        if version != BINDING_VERSION && version != NAMED_BINDING_VERSION {
            return Err(BindingError::Malformed("binding version".into()));
        }
        if d.bytes()? != PROTOCOL {
            return Err(BindingError::Malformed("binding protocol".into()));
        }
        let endpoint = d.fixed::<32>()?;
        let group_tag = d.fixed::<32>()?;
        let mls_signature_key = d.bytes()?;
        let name = if version == NAMED_BINDING_VERSION {
            let n = String::from_utf8(d.bytes()?)
                .map_err(|_| BindingError::Name("device name is not UTF-8".into()))?;
            check_device_name(&n).map_err(BindingError::Name)?;
            Some(n)
        } else {
            None
        };
        let signature = d.bytes()?;
        d.end()?;
        Ok(Self {
            endpoint,
            group_tag,
            mls_signature_key,
            signature,
            name,
        })
    }

    pub fn credential(&self) -> Credential {
        BasicCredential::new(self.encode()).into()
    }

    /// Parse and verify the binding carried by `credential` for a leaf whose
    /// MLS signature key is `leaf_signature_key`, in group `group_tag`.
    /// Returns the bound endpoint key.
    pub fn verify_credential(
        credential: &Credential,
        leaf_signature_key: &[u8],
        group_tag: &Hash,
    ) -> Result<EndpointKey, BindingError> {
        Self::verify_credential_named(credential, leaf_signature_key, group_tag).map(|(e, _)| e)
    }

    /// `verify_credential`, also returning the signed display name.
    pub fn verify_credential_named(
        credential: &Credential,
        leaf_signature_key: &[u8],
        group_tag: &Hash,
    ) -> Result<(EndpointKey, Option<String>), BindingError> {
        if credential.credential_type() != CredentialType::Basic {
            return Err(BindingError::WrongCredentialType);
        }
        let basic = BasicCredential::try_from(credential.clone())
            .map_err(|_| BindingError::WrongCredentialType)?;
        let b = Self::decode(basic.identity())?;
        if &b.group_tag != group_tag {
            return Err(BindingError::WrongGroup);
        }
        if b.mls_signature_key != leaf_signature_key {
            return Err(BindingError::SignatureKeyMismatch);
        }
        verify_ed25519(
            &b.endpoint,
            &Self::signed_message(
                &b.endpoint,
                &b.group_tag,
                &b.mls_signature_key,
                b.name.as_deref(),
            ),
            &b.signature,
        )
        .map_err(BindingError::Signature)?;
        Ok((b.endpoint, b.name))
    }

    /// Endpoint key claimed by a credential, without verification. Only for
    /// locating entries in state that was already verified.
    pub fn claimed_endpoint(credential: &Credential) -> Option<EndpointKey> {
        let basic = BasicCredential::try_from(credential.clone()).ok()?;
        Self::decode(basic.identity()).ok().map(|b| b.endpoint)
    }

    /// (endpoint, display name) claimed by a credential, without
    /// verification. Only for already verified state.
    pub fn claimed(credential: &Credential) -> Option<(EndpointKey, Option<String>)> {
        let basic = BasicCredential::try_from(credential.clone()).ok()?;
        Self::decode(basic.identity())
            .ok()
            .map(|b| (b.endpoint, b.name))
    }
}

/// Everything the joiner signs with its endpoint key when it requests
/// admission. The issuer verifies it before reserving, and every recipient of
/// the resulting Add verifies it again from the transition record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTranscript {
    pub group_tag: Hash,
    pub relay_key: [u8; 32],
    pub incarnation: Vec<u8>,
    pub issuer_endpoint: EndpointKey,
    pub issuer_mls_key: Vec<u8>,
    pub invite_id: [u8; 16],
    pub joiner_endpoint: EndpointKey,
    pub key_package_ref: Vec<u8>,
    /// Fresh per request, so two requests by one device are distinct.
    pub request_nonce: [u8; 16],
}

impl JoinTranscript {
    pub fn encode(&self) -> Vec<u8> {
        Enc::new()
            .u8(BINDING_VERSION)
            .bytes(PROTOCOL)
            .fixed(&self.group_tag)
            .fixed(&self.relay_key)
            .bytes(&self.incarnation)
            .fixed(&self.issuer_endpoint)
            .bytes(&self.issuer_mls_key)
            .fixed(&self.invite_id)
            .fixed(&self.joiner_endpoint)
            .bytes(&self.key_package_ref)
            .fixed(&self.request_nonce)
            .finish()
    }

    pub fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        if d.u8()? != BINDING_VERSION {
            return Err(DecodeError("transcript version".into()));
        }
        if d.bytes()? != PROTOCOL {
            return Err(DecodeError("transcript protocol".into()));
        }
        Ok(Self {
            group_tag: d.fixed()?,
            relay_key: d.fixed()?,
            incarnation: d.bytes()?,
            issuer_endpoint: d.fixed()?,
            issuer_mls_key: d.bytes()?,
            invite_id: d.fixed()?,
            joiner_endpoint: d.fixed()?,
            key_package_ref: d.bytes()?,
            request_nonce: d.fixed()?,
        })
    }

    pub fn digest(&self) -> Hash {
        hash(JOIN_PROOF_PURPOSE, &[&self.encode()])
    }

    pub fn sign(&self, secret: &EndpointSecret) -> Vec<u8> {
        assert_eq!(
            secret.public(),
            self.joiner_endpoint,
            "transcript names another endpoint"
        );
        secret.sign(&self.digest())
    }

    pub fn verify(&self, proof: &[u8]) -> Result<(), SigReject> {
        verify_ed25519(&self.joiner_endpoint, &self.digest(), proof)
    }
}
