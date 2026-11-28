use std::{
    fs::{self, File, OpenOptions},
    io::BufReader,
    path::Path,
};

use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};

pub fn lock(dir: &Path) -> Result<File> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("lock"))?;
    fs2::FileExt::try_lock_exclusive(&file).context("this state directory is already in use")?;
    Ok(file)
}

pub fn load<T: DeserializeOwned>(dir: &Path, filename: &str) -> Result<T> {
    let path = dir.join(filename);
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    // Unbuffered, the parser would make a system call for every byte.
    serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("read {}", path.display()))
}

pub fn save(dir: &Path, filename: &str, value: &impl Serialize) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    save_temporary(&mut file, value)?;
    publish(dir, filename, file)
}

pub fn save_control_marker(dir: &Path, filename: &str, value: &impl Serialize) -> Result<()> {
    #[cfg(windows)]
    {
        let mut file = crate::windows_service::private_marker(dir)?;
        save_temporary(&mut file, value)?;
        publish(dir, filename, file)
    }
    #[cfg(not(windows))]
    save(dir, filename, value)
}

fn save_temporary(file: &mut tempfile::NamedTempFile, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(file.as_file_mut(), value)?;
    file.as_file().sync_all()?;
    Ok(())
}

fn publish(dir: &Path, filename: &str, file: tempfile::NamedTempFile) -> Result<()> {
    let path = dir.join(filename);
    file.persist(&path)
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        // The rename already committed the new value. Some filesystems reject directory fsync.
        let _ = File::open(dir).and_then(|dir| dir.sync_all());
    }
    Ok(())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
