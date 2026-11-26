//! Canonical length-prefixed encoding and domain-separated hashing for the
//! experimental private membership records.
//!
//! Every record starts with an explicit version byte and is decoded with
//! `Dec::end`, so trailing bytes, truncation and unknown versions fail closed.
//! None of these encodings is a released wire format.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

#[derive(Default)]
pub struct Enc(pub Vec<u8>);

impl Enc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Fixed-length field (length is part of the format, not encoded).
    pub fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    /// Variable-length field with a u32 length prefix. The u32 prefix is the
    /// only framing limit, and the decoder accepts every length the encoder
    /// can write. Records are built locally from bounded inputs, so a field
    /// beyond u32::MAX is a programming error.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        let len = u32::try_from(b.len()).expect("field longer than u32::MAX");
        self.u32(len);
        self.0.extend_from_slice(b);
        self
    }

    pub fn list<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        let len = u32::try_from(items.len()).expect("list longer than u32::MAX");
        self.u32(len);
        for item in items {
            f(self, item);
        }
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decode: {}", self.0)
    }
}

pub struct Dec<'a>(&'a [u8]);

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self(b)
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < n {
            return Err(DecodeError("truncated".into()));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn len(&mut self) -> Result<usize, DecodeError> {
        usize::try_from(self.u32()?).map_err(|_| DecodeError("length not representable".into()))
    }

    /// Variable-length field. A prefix longer than the remaining input fails
    /// as truncated before anything is allocated.
    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.len()?;
        Ok(self.take(n)?.to_vec())
    }

    pub fn list<T>(
        &mut self,
        mut f: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let n = self.len()?;
        // Every element takes at least one byte, so the remaining input
        // bounds the allocation.
        let mut out = Vec::with_capacity(n.min(self.0.len()));
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }

    pub fn expect_label(&mut self, label: &[u8]) -> Result<(), DecodeError> {
        if self.bytes()? != label {
            return Err(DecodeError("wrong record label".into()));
        }
        Ok(())
    }

    pub fn end(&self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError("trailing bytes".into()))
        }
    }
}

/// SHA-256 over a label and length-prefixed parts (domain separation).
pub fn hash(label: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update((label.len() as u64).to_be_bytes());
    h.update(label);
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// Plain SHA-256 of exact bytes (stored ciphertext hashes).
pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Strict lowercase-or-uppercase hex decoding; `None` on any other input.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("operating system randomness");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_accepts_every_length_the_encoder_writes() {
        let big = vec![7u8; (1 << 20) + 17];
        let enc = Enc::new()
            .bytes(&big)
            .list(&[1u8, 2], |e, x| {
                e.u8(*x);
            })
            .finish();
        let mut d = Dec::new(&enc);
        assert_eq!(d.bytes().unwrap(), big);
        assert_eq!(d.list(|d| d.u8()).unwrap(), vec![1, 2]);
        d.end().unwrap();
        // A length prefix beyond the input is truncation, not allocation.
        let mut bad = Enc::new().u32(u32::MAX).finish();
        bad.push(0);
        assert!(Dec::new(&bad).bytes().is_err());
        assert!(Dec::new(&bad).list(|d| d.u8()).is_err());
    }
}
