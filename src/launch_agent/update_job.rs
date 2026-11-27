//! The one-shot LaunchAgent that runs `massrelay update` for a command that may not outlive
//! the wait: one typed into a shell that the update waits to see end.
//!
//! There is one such job per profile, loaded into the same login domain as the service. Its
//! property list stays in the state directory, outside `LaunchAgents`, so no later login loads
//! it. It has neither `RunAtLoad` nor `KeepAlive`: it runs once, when it is kickstarted. It
//! stays loaded after it ends, which keeps its exit status readable, until the next one
//! replaces it or the login session ends.
//!
//! launchd runs what the property list says, and writes the log, with this account's rights. So
//! before either is written or the job is loaded, they, the lock and every directory above them
//! must be changeable by this account (and root) alone: by owner and mode, and by the extended
//! access control lists of macOS, which can grant what a mode withholds. An entry that only
//! denies, as on home folders, is accepted. One that allows any change is refused, whoever it
//! names, and so is one that cannot be read or understood. No list is ever changed.

use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::{escape_xml, path_text, stage};
use crate::{private::HOST_ENV, update::Finished};

/// How long launchd is given to forget a job that was removed.
const REMOVAL_LIMIT: Duration = Duration::from_secs(5);
const LOCK_LIMIT: Duration = Duration::from_secs(2);

// `acl_tag_t` and `acl_perm_t` of macOS's <sys/acl.h>.
const ALLOW: i32 = 1;
const DENY: i32 = 2;
/// The permissions that change nothing: read data or list, execute or search, read attributes,
/// extended attributes and the access control list, and synchronize.
const HARMLESS: u64 = 1 << 1 | 1 << 3 | 1 << 7 | 1 << 9 | 1 << 11 | 1 << 20;

/// One entry of an extended access control list.
#[derive(Clone, Copy)]
struct Ace {
    tag: i32,
    permissions: u64,
}

/// Reads the extended access control list of exactly the object at a path.
type ReadAcl<'a> = &'a dyn Fn(&Path) -> Result<Vec<Ace>>;

pub(super) struct OneShot<'a> {
    /// The login domain of the installed service.
    pub domain: &'a str,
    pub label: String,
    /// The installed program, by its canonical path.
    pub program: &'a Path,
    /// The profile's canonical state directory.
    pub dir: &'a Path,
    /// Where the job's output goes. It holds the latest run only.
    pub log: &'a Path,
}

impl OneShot<'_> {
    /// Load and start the job, unless it may still be running. `launchctl` runs one
    /// `launchctl` command to its end. Returns what to tell the person who asked.
    pub(super) fn queue(&self, launchctl: &dyn Fn(&[&str]) -> Result<Finished>) -> Result<String> {
        self.queue_reading(launchctl, &extended_acl)
    }

    fn queue_reading(
        &self,
        launchctl: &dyn Fn(&[&str]) -> Result<Finished>,
        acl: ReadAcl,
    ) -> Result<String> {
        check_directory(self.dir, acl).context("check the update job's state directory")?;
        ensure!(
            self.program
                .canonicalize()
                .is_ok_and(|found| found == self.program),
            "{} is not the canonical path of a program; the update was not queued",
            self.program.display()
        );
        self.program
            .ancestors()
            .try_for_each(|path| check_acl(path, acl))
            .context("check the update program's access control lists")?;
        let logs = self
            .log
            .parent()
            .context("the update log has no directory")?;
        prepare_log_directory(logs, acl).context("prepare the update log's directory")?;
        let log = logs.join(self.log.file_name().context("the update log has no name")?);
        let lock_path = self.dir.join("update-job.lock");
        let plist = self.dir.join("update-job.plist");
        for file in [&lock_path, &plist, &log] {
            match fs::symlink_metadata(file) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => check_file(file, acl)?,
            }
        }
        let target = format!("{}/{}", self.domain, self.label);
        let follow = format!(
            "Follow it with 'tail -f \"{}\"' and see its state with 'launchctl print {target}'.",
            log.display()
        );

        // Two commands must not both find the job finished: the second would remove what the
        // first had just started.
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .context("open the update job's lock")?;
        // A new file can inherit entries from its directory.
        check_file(&lock_path, acl)?;
        lock_queue(&lock, LOCK_LIMIT).context("lock the update job")?;

        let printed = launchctl(&["print", &target]).context("look for an earlier update job")?;
        if printed.success {
            if !idle(&printed.stdout) {
                return Ok(format!(
                    "An update is already queued or running as {target}; no other was started. \
                     {follow} If it is stuck, remove it with 'launchctl bootout {target}' and \
                     run 'massrelay update' again."
                ));
            }
            self.remove(&target, launchctl)?;
        }

        stage(self.dir, self.render(&log)?.as_bytes())?
            .persist(&plist)
            .context("save the update job's property list")?;
        // A new file, private to this account, in place of an earlier run's output.
        stage(logs, b"")?
            .persist(&log)
            .context("create the update log")?;
        check_file(&plist, acl)?;
        check_file(&log, acl)?;

        let loaded = launchctl(&["bootstrap", self.domain, path_text(&plist)?])
            .context("load the update job")?;
        ensure!(
            loaded.success,
            "could not load the update job {target}: {}",
            one_line(&loaded.stderr)
        );
        // Without `-k`, a job that already runs is left running.
        let started = launchctl(&["kickstart", &target]).context("start the update job")?;
        ensure!(
            started.success,
            "could not start the update job {target}: {}. Inspect it with 'launchctl print \
             {target}', or run 'massrelay update' again",
            one_line(&started.stderr)
        );
        Ok(format!(
            "The update now runs in the background as {target}. It waits for every connection \
             and temporary exposure on this device to end, including a MassRelay shell this \
             command runs in. {follow} While it is still waiting, 'launchctl bootout {target}' \
             cancels it."
        ))
    }

    /// Remove a loaded job that is not running, and wait until launchd no longer knows it.
    fn remove(&self, target: &str, launchctl: &dyn Fn(&[&str]) -> Result<Finished>) -> Result<()> {
        let removed = launchctl(&["bootout", target]).context("remove the finished update job")?;
        let deadline = Instant::now() + REMOVAL_LIMIT;
        // What is asked for is that the job is gone, whatever `bootout` itself reported.
        while launchctl(&["print", target])?.success {
            ensure!(
                Instant::now() < deadline,
                "could not remove the finished update job {target}: {}",
                one_line(&removed.stderr)
            );
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    fn render(&self, log: &Path) -> Result<String> {
        let text = |path| path_text(path).map(escape_xml);
        let (program, dir, log) = (text(self.program)?, text(self.dir)?, text(log)?);
        // A property list can add environment variables but not remove them, and the login
        // domain may carry the variable that marks a MassRelay shell. The shell removes it
        // and becomes the program; paths reach it as arguments, never as script text.
        let script = escape_xml(&format!("unset {HOST_ENV}; exec \"$0\" \"$@\""));
        let label = &self.label;
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>{script}</string>
    <string>{program}</string>
    <string>--state-dir</string>
    <string>{dir}</string>
    <string>update</string>
  </array>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#
        ))
    }
}

/// Whether `launchctl print` positively says that a loaded job is not running. Its output is
/// no stable interface, so anything else counts as a job that runs or is about to, which is
/// never removed.
fn idle(printed: &str) -> bool {
    let mut lines = printed.lines().map(str::trim);
    !lines.clone().any(|line| line.starts_with("pid = "))
        // The job's own state comes first; nested sections have states of their own.
        && lines.find_map(|line| line.strip_prefix("state = ")) == Some("not running")
}

/// A directory in which, and above which, only this account and root can change anything.
fn check_directory(dir: &Path, acl: ReadAcl) -> Result<()> {
    crate::update::check_ancestry(dir)?;
    // The update's own check lets a sticky directory be shared. This one holds the job's files.
    ensure!(
        fs::symlink_metadata(dir)?.permissions().mode() & 0o022 == 0,
        "{} is writable by other accounts",
        dir.display()
    );
    dir.ancestors().try_for_each(|path| check_acl(path, acl))
}

fn prepare_log_directory(dir: &Path, acl: ReadAcl) -> Result<()> {
    for ancestor in dir.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => check_directory(ancestor, acl)?,
        }
        if ancestor != dir {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            check_directory(dir, acl)?;
        }
        return Ok(());
    }
    anyhow::bail!("no existing parent for {}", dir.display())
}

fn lock_queue(lock: &fs::File, limit: Duration) -> io::Result<()> {
    let deadline = Instant::now() + limit;
    loop {
        match fs2::FileExt::try_lock_exclusive(lock) {
            Err(error)
                if error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(25));
            }
            result => return result,
        }
    }
}

/// A regular file of this account's that nobody else can change, in a checked directory.
fn check_file(path: &Path, acl: ReadAcl) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("read {}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let own = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_file() && metadata.uid() == own && metadata.mode() & 0o022 == 0,
        "{} is not a file that only this account can change. Remove it and run 'massrelay \
         update' again",
        path.display()
    );
    check_acl(path, acl)
}

fn check_acl(path: &Path, acl: ReadAcl) -> Result<()> {
    let entries =
        acl(path).with_context(|| format!("read the access control list of {}", path.display()))?;
    ensure!(
        entries.iter().all(|entry| match entry.tag {
            DENY => true,
            ALLOW => entry.permissions & !HARMLESS == 0,
            _ => false,
        }),
        "the access control list of {path} may let another account change it. See it with \
         'ls -lde \"{path}\"', remove what allows changes with 'chmod -a', and run 'massrelay \
         update' again",
        path = path.display()
    );
    Ok(())
}

/// The extended access control list of `path` itself (a symbolic link is not followed), read
/// with the calls described in acl(3).
#[cfg(target_os = "macos")]
fn extended_acl(path: &Path) -> Result<Vec<Ace>> {
    use std::{
        ffi::{CString, c_char, c_int, c_void},
        os::unix::ffi::OsStrExt,
        ptr,
    };

    // <sys/acl.h>
    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    unsafe extern "C" {
        fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, which: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }
    struct List(*mut c_void);
    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: the list came from `acl_get_link_np` and is freed only here.
            unsafe { acl_free(self.0) };
        }
    }

    let name = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let list = unsafe { acl_get_link_np(name.as_ptr(), ACL_TYPE_EXTENDED) };
    if list.is_null() {
        let error = io::Error::last_os_error();
        // An object without a list gives ENOENT, which a missing object gives too.
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error.into());
        }
        fs::symlink_metadata(path)?;
        return Ok(Vec::new());
    }
    let list = List(list);
    let mut entries = Vec::new();
    let mut which = ACL_FIRST_ENTRY;
    loop {
        let mut entry = ptr::null_mut();
        // SAFETY: the list is live, and `entry` is writable.
        if unsafe { acl_get_entry(list.0, which, &mut entry) } != 0 {
            // Past the last entry the call fails with EINVAL.
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error.into());
            }
            return Ok(entries);
        }
        which = ACL_NEXT_ENTRY;
        let (mut tag, mut permissions) = (0, 0);
        // SAFETY: `entry` belongs to the live list, and both results are writable.
        let read = unsafe {
            acl_get_tag_type(entry, &mut tag) == 0
                && acl_get_permset_mask_np(entry, &mut permissions) == 0
        };
        ensure!(
            read,
            "an entry cannot be read: {}",
            io::Error::last_os_error()
        );
        entries.push(Ace { tag, permissions });
    }
}

#[cfg(not(target_os = "macos"))]
fn extended_acl(_: &Path) -> Result<Vec<Ace>> {
    anyhow::bail!("these access control lists can be read only on macOS")
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(all(test, unix))]
mod tests {
    use std::{cell::RefCell, os::unix::fs::symlink, path::PathBuf, process::Command, sync::Mutex};

    use super::*;

    const NEVER_RAN: &str = "x = {\n\tstate = not running\n\tlast exit code = (never exited)\n}";
    const RUNNING: &str = "x = {\n\tstate = running\n\tpid = 42\n}";
    const FINISHED: &str = "x = {\n\tstate = not running\n\truns = 1\n\tlast exit code = 1\n\
                            \tcoalition = {\n\t\tstate = active\n\t}\n}";

    /// A login domain holding at most the one job.
    #[derive(Default)]
    struct Launchd {
        /// What `print` says of the job, when it is loaded.
        job: Option<String>,
        /// Every command that changes something.
        changes: Vec<String>,
        refuse: Option<&'static str>,
    }

    impl Launchd {
        fn run(state: &Mutex<Self>, args: &[&str]) -> Result<Finished> {
            let mut launchd = state.lock().unwrap();
            let verb = args[0];
            let success = if verb == "print" {
                launchd.job.is_some()
            } else {
                launchd.changes.push(verb.to_owned());
                if launchd.refuse == Some(verb) {
                    false
                } else {
                    match verb {
                        "bootstrap" if launchd.job.is_none() => {
                            launchd.job = Some(NEVER_RAN.into());
                            true
                        }
                        "kickstart" if launchd.job.is_some() => {
                            launchd.job = Some(RUNNING.into());
                            true
                        }
                        "bootout" => launchd.job.take().is_some(),
                        _ => false,
                    }
                }
            };
            Ok(Finished {
                success,
                stdout: launchd.job.clone().unwrap_or_default(),
                stderr: if success {
                    String::new()
                } else {
                    "Input/output\n error".into()
                },
            })
        }

        fn changes(state: &Mutex<Self>) -> Vec<String> {
            std::mem::take(&mut state.lock().unwrap().changes)
        }
    }

    /// The program arguments of a rendered property list.
    fn arguments(plist: &str) -> Vec<String> {
        let array = plist.split_once("<array>").unwrap().1;
        array
            .split_once("</array>")
            .unwrap()
            .0
            .split("<string>")
            .skip(1)
            .map(|rest| {
                rest.split_once("</string>")
                    .unwrap()
                    .0
                    .replace("&#13;", "\r")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&")
            })
            .collect()
    }

    /// A temporary directory that only this account can change, whatever the umask.
    fn private_directory() -> Result<(tempfile::TempDir, PathBuf)> {
        let temp = tempfile::tempdir()?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        let path = temp.path().canonicalize()?;
        Ok((temp, path))
    }

    /// A program that records the shell marker it sees and its arguments.
    fn program(dir: &Path) -> Result<PathBuf> {
        let path = dir.join("massrelay");
        let script =
            format!("#!/bin/sh\nprintf '%s\\n' \"${{{HOST_ENV}-removed}}\" \"$@\" > \"$0.seen\"\n");
        // Written by another process, so that no test thread holds it open for writing when
        // it is run.
        let written = Command::new("/bin/sh")
            .args(["-c", "printf %s \"$1\" > \"$0\""])
            .arg(&path)
            .arg(script)
            .status()?;
        assert!(written.success());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }

    /// No object has an access control list.
    fn no_lists(_: &Path) -> Result<Vec<Ace>> {
        Ok(Vec::new())
    }

    #[test]
    fn the_job_runs_the_exact_update_outside_a_shell_once_at_a_time() -> Result<()> {
        let (_temp, root) = private_directory()?;
        let dir = root.join("A & <B> \"c\" $HOME 'd'");
        fs::create_dir(&dir)?;
        let program = program(&dir)?;
        let log = dir.join("Logs/MassRelay-update.log");
        let job = OneShot {
            domain: "gui/501",
            label: "com.massrelay.client.update".into(),
            program: &program,
            dir: &dir,
            log: &log,
        };
        let launchd = Mutex::new(Launchd::default());
        let run = |args: &[&str]| Launchd::run(&launchd, args);
        let queue = || job.queue_reading(&run, &no_lists);

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1777))?;
        assert!(queue().is_err());
        assert!(!dir.join("update-job.lock").exists());
        assert!(!dir.join("update-job.plist").exists());
        assert!(Launchd::changes(&launchd).is_empty());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;

        // Commands that arrive together start one job.
        thread::scope(|scope| {
            let queued: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| job.queue_reading(&run, &no_lists)))
                .collect();
            for queued in queued {
                queued.join().unwrap().unwrap();
            }
        });
        assert_eq!(Launchd::changes(&launchd), ["bootstrap", "kickstart"]);

        // What launchd would run: the update of this profile, without the inherited marker.
        let plist = fs::read_to_string(dir.join("update-job.plist"))?;
        #[cfg(target_os = "macos")]
        assert!(
            Command::new("/usr/bin/plutil")
                .arg("-lint")
                .arg(dir.join("update-job.plist"))
                .status()?
                .success()
        );
        let arguments = arguments(&plist);
        assert_eq!(arguments[0], "/bin/sh");
        assert_eq!(
            arguments[3..],
            [
                path_text(&program)?,
                "--state-dir",
                path_text(&dir)?,
                "update"
            ]
        );
        let ran = Command::new(&arguments[0])
            .args(&arguments[1..])
            .env(HOST_ENV, "4242")
            .status()?;
        assert!(ran.success());
        assert_eq!(
            fs::read_to_string(dir.join("massrelay.seen"))?,
            format!("removed\n--state-dir\n{}\nupdate\n", dir.display())
        );

        // A job that runs, or that launchd describes in no way known to be over, is left
        // alone, with its output.
        fs::write(&log, "waiting")?;
        for state in [RUNNING, "x = {\n\tstate = spawn scheduled\n}", "x = {\n}"] {
            launchd.lock().unwrap().job = Some(state.into());
            queue()?;
            assert!(Launchd::changes(&launchd).is_empty(), "{state}");
            assert_eq!(fs::read_to_string(&log)?, "waiting");
        }

        // A finished job, and one that was loaded and never started, are replaced.
        for state in [FINISHED, NEVER_RAN] {
            fs::write(&log, "earlier run")?;
            launchd.lock().unwrap().job = Some(state.into());
            queue()?;
            assert_eq!(
                Launchd::changes(&launchd),
                ["bootout", "bootstrap", "kickstart"]
            );
            assert_eq!(fs::read_to_string(&log)?, "");
            assert_eq!(fs::metadata(&log)?.permissions().mode() & 0o077, 0);
        }

        // A refusal is reported, and the next request starts over.
        for refused in ["bootstrap", "kickstart"] {
            let mut state = launchd.lock().unwrap();
            (state.job, state.refuse) = (None, Some(refused));
            drop(state);
            let error = queue().unwrap_err().to_string();
            assert!(error.contains("Input/output error"), "{error}");
            launchd.lock().unwrap().refuse = None;
            Launchd::changes(&launchd);
            queue()?;
            assert!(
                Launchd::changes(&launchd).ends_with(&["bootstrap".into(), "kickstart".into()])
            );
        }

        // Only the program's own path is run.
        let link = dir.join("link");
        symlink(&program, &link)?;
        launchd.lock().unwrap().job = None;
        let linked = OneShot {
            program: &link,
            ..job
        };
        assert!(linked.queue_reading(&run, &no_lists).is_err());
        assert!(Launchd::changes(&launchd).is_empty());
        Ok(())
    }

    #[test]
    fn nothing_another_account_could_change_is_handed_to_launchd() -> Result<()> {
        let (_temp, root) = private_directory()?;
        let (dir, logs) = (root.join("state"), root.join("Logs"));
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let program = program(&root)?;
        let log = logs.join("MassRelay-update.log");
        let job = OneShot {
            domain: "gui/501",
            label: "com.massrelay.client.update".into(),
            program: &program,
            dir: &dir,
            log: &log,
        };
        let files = [
            dir.join("update-job.lock"),
            dir.join("update-job.plist"),
            log.clone(),
        ];
        let launchd = Mutex::new(Launchd::default());
        let run = |args: &[&str]| Launchd::run(&launchd, args);

        // As macOS protects home folders, with an entry that only reads besides.
        let usual = [
            Ace {
                tag: DENY,
                permissions: 1 << 4,
            },
            Ace {
                tag: ALLOW,
                permissions: HARMLESS,
            },
        ];
        // The one path that has another entry too, if the list can be read at all.
        let odd: RefCell<Option<(PathBuf, Option<Ace>)>> = RefCell::default();
        let acl = |path: &Path| {
            let mut entries = usual.to_vec();
            if let Some((_, entry)) = odd.borrow().as_ref().filter(|(odd, _)| odd == path) {
                entries.push(entry.context("Operation not supported")?);
            }
            Ok(entries)
        };
        let refused = |path: &Path, entry: Option<Ace>| {
            odd.replace(Some((path.to_owned(), entry)));
            let error = format!("{:#}", job.queue_reading(&run, &acl).unwrap_err());
            assert!(error.contains(path_text(path).unwrap()), "{error}");
            assert!(Launchd::changes(&launchd).is_empty(), "{error}");
            odd.take();
        };
        // Write or add a file, delete, append or add a directory, delete a child, write
        // attributes, extended attributes or the list, change the owner, and a permission
        // unknown here; then a kind of entry unknown here, and a list that cannot be read.
        let grants = [2, 4, 5, 6, 8, 10, 12, 13, 21].map(|bit| {
            Some(Ace {
                tag: ALLOW,
                permissions: HARMLESS | 1 << bit,
            })
        });
        let unknown = Some(Ace {
            tag: 0,
            permissions: 0,
        });
        let write = grants[0];

        // A directory on the way to the state or the log: nothing is written.
        for path in program
            .ancestors()
            .chain(dir.ancestors())
            .chain(logs.ancestors())
        {
            for entry in grants.into_iter().chain([unknown, None]) {
                refused(path, entry);
            }
            assert!(files.iter().all(|file| !file.exists()));
        }
        // A new file that inherits such an entry is not loaded.
        for new in &files {
            refused(new, write);
            // So that each is new again when its turn comes.
            for file in &files {
                let _ = fs::remove_file(file);
            }
        }

        job.queue_reading(&run, &acl)?;
        assert_eq!(Launchd::changes(&launchd), ["bootstrap", "kickstart"]);
        launchd.lock().unwrap().job = Some(FINISHED.into());
        // An earlier file that others could change stops the next job before anything is
        // replaced, and so do its mode and a link in its place.
        let elsewhere = root.join("elsewhere");
        fs::write(&elsewhere, "untouched")?;
        for file in &files {
            fs::write(file, "earlier")?;
            refused(file, write);
            fs::set_permissions(file, fs::Permissions::from_mode(0o620))?;
            assert!(job.queue_reading(&run, &acl).is_err());
            fs::remove_file(file)?;
            symlink(&elsewhere, file)?;
            assert!(job.queue_reading(&run, &acl).is_err());
            assert!(Launchd::changes(&launchd).is_empty());
            fs::remove_file(file)?;
        }
        assert_eq!(fs::read_to_string(&elsewhere)?, "untouched");
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o1777))?;
        assert!(job.queue_reading(&run, &acl).is_err());
        assert!(Launchd::changes(&launchd).is_empty());

        let redirect = root.join("redirect");
        symlink(&dir, &redirect)?;
        assert!(prepare_log_directory(&redirect.join("nested"), &acl).is_err());
        assert!(!dir.join("nested").exists());

        let lock = fs::File::create(&files[0])?;
        let reader = fs::File::open(&files[0])?;
        fs2::FileExt::lock_shared(&reader)?;
        assert_eq!(
            lock_queue(&lock, Duration::ZERO)
                .unwrap_err()
                .raw_os_error(),
            fs2::lock_contended_error().raw_os_error()
        );
        Ok(())
    }

    /// The native reading, on real files of the test's own.
    #[cfg(target_os = "macos")]
    #[test]
    fn extended_access_lists_are_read_from_macos() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let file = temp.path().canonicalize()?.join("file");
        fs::write(&file, "")?;
        let chmod = |arguments: &[&str]| -> Result<()> {
            let status = Command::new("/bin/chmod")
                .args(arguments)
                .arg(&file)
                .status()?;
            ensure!(status.success(), "chmod {arguments:?}");
            Ok(())
        };
        assert!(extended_acl(&file)?.is_empty());
        check_acl(&file, &extended_acl)?;
        chmod(&["+a", "everyone deny delete"])?;
        chmod(&["+a", "everyone allow read,readattr,readsecurity"])?;
        assert_eq!(extended_acl(&file)?.len(), 2);
        check_acl(&file, &extended_acl)?;
        chmod(&["+a", "everyone allow write"])?;
        assert!(check_acl(&file, &extended_acl).is_err());
        // The denial would keep the temporary directory from being removed.
        chmod(&["-N"])?;
        assert!(extended_acl(&file.with_file_name("missing")).is_err());
        Ok(())
    }
}
