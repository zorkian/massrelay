//! The Win32 calls behind the Windows system SSH setup.

use std::{
    ffi::OsString,
    fs::{self, File, Metadata},
    io,
    os::windows::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::MetadataExt as _,
    },
    path::{Path, PathBuf},
    ptr::null,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use windows_sys::Win32::{
    Foundation::ERROR_UNABLE_TO_MOVE_REPLACEMENT_2,
    Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, MoveFileExW, ReplaceFileW},
    System::SystemInformation::GetSystemDirectoryW,
    UI::Shell::GetAllUsersProfileDirectoryW,
};

/// The system directory and `ProgramData`, asked of Windows rather than the environment.
pub fn known_directories() -> Result<(PathBuf, PathBuf)> {
    let mut buffer = [0u16; 260];
    // SAFETY: the buffer is writable for the length given.
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    ensure!(
        len > 0 && len < buffer.len(),
        "cannot find the Windows system directory"
    );
    let system = PathBuf::from(OsString::from_wide(&buffer[..len]));
    let mut buffer = [0u16; 260];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer is writable for the length given.
    ensure!(
        unsafe { GetAllUsersProfileDirectoryW(buffer.as_mut_ptr(), &mut len) } != 0,
        "find the ProgramData directory: {}",
        io::Error::last_os_error()
    );
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .context("the ProgramData path is not terminated")?;
    Ok((system, PathBuf::from(OsString::from_wide(&buffer[..end]))))
}

fn wide(path: &Path) -> Result<Vec<u16>> {
    let mut wide: Vec<_> = path.as_os_str().encode_wide().collect();
    ensure!(!wide.contains(&0), "a path contains a NUL character");
    wide.push(0);
    Ok(wide)
}

/// Atomically replace `target` with `replacement`, which keeps the target's access list.
pub fn replace_file(target: &Path, replacement: &Path) -> Result<()> {
    // As unused a name as the staged file's.
    let mut previous = replacement.as_os_str().to_owned();
    previous.push(".previous");
    let previous = PathBuf::from(previous);
    let (to, from, backup) = (wide(target)?, wide(replacement)?, wide(&previous)?);
    // SAFETY: all three paths are NUL-terminated; the reserved arguments are null.
    let replaced = unsafe {
        ReplaceFileW(
            to.as_ptr(),
            from.as_ptr(),
            backup.as_ptr(),
            0,
            null(),
            null(),
        )
    };
    if replaced == 0 {
        let error = io::Error::last_os_error();
        // The one failure that leaves the original under the other name.
        if error.raw_os_error() == Some(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 as i32) {
            // SAFETY: both paths are NUL-terminated.
            ensure!(
                unsafe { MoveFileExW(backup.as_ptr(), to.as_ptr(), 0) } != 0,
                "replacing {} failed; its contents are in {}",
                target.display(),
                previous.display()
            );
        }
        return Err(error).with_context(|| format!("replace {}", target.display()));
    }
    // The new file is in place; a leftover copy of the old one harms nothing.
    let _ = fs::remove_file(previous);
    Ok(())
}

pub fn check_private_directory(path: &Path) -> Result<()> {
    crate::windows_service::ssh_private_dir(path)
}

pub fn check_managed_file(path: &Path) -> Result<()> {
    crate::windows_service::ssh_files::check_managed_file(path)
}

pub fn check_system_path(path: &Path, directory: bool) -> Result<()> {
    crate::windows_service::ssh_files::check_system_path(path, directory)
}

pub fn lock_system(path: &Path, limit: Duration) -> Result<File> {
    crate::windows_service::ssh_files::lock_system(path, limit)
}

pub fn plain(path: &Path) -> Result<PathBuf> {
    Ok(crate::windows_service::plain(path)?.into())
}

pub fn is_reparse(metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}
