use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::process::Command;

pub(super) fn openssh(name: &str) -> Result<std::path::PathBuf> {
    #[cfg(unix)]
    let path = Path::new("/usr/bin").join(name);
    #[cfg(windows)]
    let path = {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

        let mut buffer = [0u16; 260];
        // SAFETY: the buffer is writable for the stated length.
        let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        ensure!(
            len > 0 && len < buffer.len(),
            "cannot find the Windows system directory"
        );
        std::path::PathBuf::from(OsString::from_wide(&buffer[..len]))
            .join("OpenSSH")
            .join(format!("{name}.exe"))
    };
    ensure!(
        path.is_file(),
        "OpenSSH executable is missing: {}",
        path.display()
    );
    Ok(path)
}
const ED25519_BLOB: &[u8] = b"\0\0\0\x0bssh-ed25519\0\0\0\x20";

pub(super) fn public_line(key: &[u8; 32]) -> String {
    let encoded = STANDARD.encode([ED25519_BLOB, key.as_slice()].concat());
    format!("ssh-ed25519 {encoded}")
}

pub(super) async fn generate(path: &Path) -> Result<[u8; 32]> {
    let status = Command::new(openssh("ssh-keygen")?)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await
        .context("start OpenSSH key generation")?;
    ensure!(status.success(), "OpenSSH key generation failed");
    public_key(path).await
}

pub(super) async fn public_key(path: &Path) -> Result<[u8; 32]> {
    let result = Command::new(openssh("ssh-keygen")?)
        .args(["-y", "-P", "", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .context("read OpenSSH public key")?;
    ensure!(result.status.success(), "could not read OpenSSH public key");
    let mut fields = std::str::from_utf8(&result.stdout)?.split_ascii_whitespace();
    ensure!(fields.next() == Some("ssh-ed25519"), "expected Ed25519 key");
    let blob = STANDARD.decode(fields.next().context("missing public key blob")?)?;
    Ok(blob
        .strip_prefix(ED25519_BLOB)
        .context("invalid Ed25519 key blob")?
        .try_into()?)
}

pub(super) fn fingerprint(key: &[u8; 32]) -> String {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(ED25519_BLOB);
    digest.update(key);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest.finalize()))
}
