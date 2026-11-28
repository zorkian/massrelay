use std::{
    env, fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, bail, ensure};
use directories::BaseDirs;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{
    ServiceAction, default_state_dir,
    installer::{self, Verify},
    private::{cli, runtime::Identity},
};

#[path = "launch_agent/update_job.rs"]
mod update_job;

const LABEL: &str = "com.massrelay.client";
/// How long launchd is given to end a job it was told to unload, which includes the runtime's
/// own ordered stop.
const STOP_LIMIT: Duration = Duration::from_secs(90);
const HOSTED: &str = "this command depends on the service it would remove: it runs under that \
    service, such as in a MassRelay shell on this device, and would end partway. Nothing was \
    changed. Run 'massrelay uninstall' from a local terminal on this device";
const CHANGED: &str = "the background service is no longer as it was shown, so it was not \
    touched. Run 'massrelay uninstall' again";
const INSTALL_CHANGED: &str = "the background service, or what an install would write, is no \
    longer as it was shown, so nothing was installed. Run 'massrelay install' again";

/// The audit path used by installed LaunchAgents, including older installs.
pub fn audit_path(dir: &Path) -> Result<PathBuf> {
    Ok(Job::for_profile(dir)?.events)
}

/// Everything `install` settles before it changes anything, and so all that a confirmation of
/// it approves.
#[derive(Debug, PartialEq, Eq)]
struct Prepared {
    dir: PathBuf,
    job: Job,
    domain: String,
    service: String,
    /// Set when launchd has the job loaded, with what identifies it where that can be read.
    loaded: Option<Option<Loaded>>,
    previous: Option<Plist>,
    binary: PathBuf,
    contents: String,
}

impl Prepared {
    /// Look, changing nothing, at what an install of `binary` for the profile in the
    /// canonical `dir` would replace.
    fn read(dir: PathBuf, job: Job, binary: PathBuf, run: Tool) -> Result<Self> {
        let domain = user_domain(run)?;
        check_session(&domain, run)?;
        let service = format!("{domain}/{}", job.label);
        let printed = run("/bin/launchctl", &["print", &service])
            .with_context(|| format!("look for {service}"))?;
        let loaded = printed.success.then(|| Loaded::read(&printed.stdout));
        let previous = plist_file(&job.plist)?;
        ensure!(
            loaded.is_none() || previous.is_some(),
            "the loaded LaunchAgent has no plist at {}",
            job.plist.display()
        );
        let contents = job.render(&binary, &dir)?;
        Ok(Self {
            dir,
            job,
            domain,
            service,
            loaded,
            previous,
            binary,
            contents,
        })
    }
}

fn prepare(dir: &Path) -> Result<Prepared> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let job = Job::for_profile(&dir)?;
    let binary = env::current_exe().context("find the running MassRelay binary")?;
    Prepared::read(dir, job, binary, &tool)
}

/// An install as shown for confirmation, which displays as the changes it would make.
pub struct InstallPlan {
    shown: Prepared,
    /// The runtime the job already runs exactly as this install would set it up, which is
    /// therefore left running.
    kept: Option<Identity>,
}

impl fmt::Display for InstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let Prepared {
            dir,
            job,
            domain,
            loaded,
            previous,
            binary,
            ..
        } = &self.shown;
        if self.keeps() {
            return write!(
                formatter,
                "Keep the LaunchAgent {} running in {domain}, without a restart: its property \
                 list {} is already as this install would write it\n\
                 Enable it, so that it also loads at the next login\n\
                 It runs {} for the profile in {} and records events in {}",
                job.label,
                job.plist.display(),
                binary.display(),
                dir.display(),
                job.events.display()
            );
        }
        let write = if previous.is_some() {
            "Replace"
        } else {
            "Write"
        };
        let load = if loaded.is_some() {
            "Unload the running job, then load"
        } else {
            "Load"
        };
        write!(
            formatter,
            "{write} the LaunchAgent property list {}\n\
             {load} {} into {domain}, which starts it\n\
             It runs {} for the profile in {} and records events in {}",
            job.plist.display(),
            job.label,
            binary.display(),
            dir.display(),
            job.events.display()
        )
    }
}

/// What `install` would write and load. Changes nothing, and so leaves to `apply` the lint of
/// the property list and the checks that open the profile's files for writing.
pub fn plan_install(dir: &Path) -> Result<InstallPlan> {
    prepare(dir).map(InstallPlan::new)
}

impl InstallPlan {
    fn new(shown: Prepared) -> Self {
        Self { shown, kept: None }
    }

    /// For a command in a session that depends on `runtime`, which has to be this profile's
    /// service. One that is exactly what this install would make is then left running.
    pub fn carried_by(&mut self, runtime: &Identity) -> Result<()> {
        self.inspect_carrier(runtime, &tool)
    }

    fn inspect_carrier(&mut self, runtime: &Identity, run: Tool) -> Result<()> {
        let Prepared {
            dir,
            job,
            service,
            loaded,
            previous,
            binary,
            contents,
            ..
        } = &self.shown;
        let printed = run("/bin/launchctl", &["print", service])
            .with_context(|| format!("look for {service}"))?;
        ensure!(
            printed.success && job_pid(&printed.stdout) == Some(runtime.pid),
            installer::NOT_THE_SERVICE
        );
        let running = runtime
            .executable
            .as_deref()
            .map(Path::new)
            .filter(|program| program.is_file())
            .context("cannot find the program that would restore this LaunchAgent")?;
        let arguments = [
            path_text(running)?,
            "--state-dir",
            path_text(dir)?,
            "run",
            "--log-file",
            path_text(&job.events)?,
        ];
        let saved = job.render(running, dir)?;
        ensure!(
            previous
                .as_ref()
                .is_some_and(|plist| plist.contents == saved.as_bytes())
                && matches!(loaded, Some(Some(loaded))
                    if loaded.arguments == arguments
                        && loaded.path.as_deref() == job.plist.to_str())
                && Loaded::read(&printed.stdout).as_ref()
                    == loaded.as_ref().and_then(Option::as_ref),
            "the saved LaunchAgent cannot be verified to restore the service carrying this \
             session. Nothing was changed"
        );
        let exact = saved == *contents && installer::is_this_program(runtime, binary);
        self.kept = exact.then(|| runtime.clone());
        Ok(())
    }

    /// Whether applying this leaves the running job loaded as it is.
    pub fn keeps(&self) -> bool {
        self.kept.is_some()
    }

    /// Everything a confirmation of this approves, to compare across processes.
    pub fn approval(&self) -> String {
        format!("{:?} {:?}", self.shown, self.kept)
    }

    /// Where a queued install says what it did.
    pub fn log(&self) -> String {
        self.shown.job.install_log.display().to_string()
    }

    /// Install and load the service, if what it would replace and write is still as it was
    /// shown. Returns the canonical state directory the service was installed for.
    pub fn apply(self) -> Result<PathBuf> {
        self.perform(None)
    }

    fn perform(self, serves: Verify) -> Result<PathBuf> {
        cli::check_enrolled(&self.shown.dir)?;
        let found = self.confirm(prepare(&self.shown.dir)?)?;
        let Some(runtime) = &self.kept else {
            let run = |command: &mut Command, action: &str| checked(command, action).map(drop);
            return register(found, &run, STOP_LIMIT, serves);
        };
        let mut found = Self::new(found);
        found.carried_by(runtime)?;
        ensure!(found.keeps(), INSTALL_CHANGED);
        let Prepared {
            dir, job, service, ..
        } = found.shown;
        // Nothing is unloaded for this.
        checked(&mut launchctl("enable", &service), "enable the LaunchAgent")?;
        crate::update::say(format!(
            "Kept {} running\nEvent log       {}",
            job.label,
            job.events.display()
        ));
        Ok(dir)
    }

    /// `apply` in the process a `queue` started, which counts a start only once `serves`
    /// finds the runtime answering.
    pub fn finish(self, serves: &dyn Fn(Option<&Path>) -> Result<()>) -> Result<PathBuf> {
        self.perform(Some(serves))
    }

    /// Hand this install, as `approval` names it, to a job of its own, which neither the
    /// service's unload nor this session's end reaches. Returns where it logs.
    pub fn queue(self, approval: &str) -> Result<String> {
        cli::check_enrolled(&self.shown.dir)?;
        let found = self.confirm(prepare(&self.shown.dir)?)?;
        let log = self.log();
        let label = format!("{}.install", found.job.label);
        let job = update_job::OneShot {
            domain: &found.domain,
            label,
            command: update_job::Command::Install { approval },
            program: &found.binary,
            dir: &found.dir,
            log: &found.job.install_log,
        };
        job.queue(&|args| bounded(Command::new("/bin/launchctl").args(args)))?;
        Ok(log)
    }

    /// Require what an install finds now to be what was shown.
    fn confirm(&self, found: Prepared) -> Result<Prepared> {
        ensure!(found == self.shown, INSTALL_CHANGED);
        Ok(found)
    }
}

/// Runs a command to its end, failing unless it succeeds. Says what it was for.
type Run<'a> = &'a dyn Fn(&mut Command, &str) -> Result<()>;

/// Replace the job as `prepared` says, and put back what was there if that fails.
/// `stop_limit` is how long launchd is given to forget a replacement that does not serve.
fn register(prepared: Prepared, run: Run, stop_limit: Duration, serves: Verify) -> Result<PathBuf> {
    let Prepared {
        dir,
        job,
        domain,
        service,
        loaded,
        previous,
        binary,
        contents,
    } = prepared;
    // Only a job that was shown as loaded is unloaded.
    let loaded = loaded.is_some();
    if !loaded {
        let _lock = cli::claim_owner(&dir).context("stop the foreground massrelay run first")?;
    }
    let directory = job.plist.parent().expect("LaunchAgents directory");
    fs::create_dir_all(directory)?;
    fs::create_dir_all(job.events.parent().expect("Logs directory"))?;
    let staged = stage(directory, contents.as_bytes())?;
    run(
        Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(staged.path()),
        "validate the LaunchAgent plist",
    )?;
    let unload = || {
        run(
            &mut launchctl("bootout", &service),
            "unload the LaunchAgent",
        )
    };
    let load = || {
        run(
            launchctl("bootstrap", &domain).arg(&job.plist),
            "load the LaunchAgent",
        )
    };
    if loaded {
        unload()?;
    }
    let registered = (|| {
        staged
            .persist(&job.plist)
            .context("save the LaunchAgent plist")?;
        run(&mut launchctl("enable", &service), "enable the LaunchAgent")?;
        load()?;
        if let Some(serves) = serves {
            serves(Some(&binary)).context("the new service did not come up")?;
        }
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = registered {
        let restore = (|| {
            // A replacement that loaded without serving has to be gone before the previous
            // job can take its name.
            let present = || {
                let mut print = launchctl("print", &service);
                run(&mut print, "look for the LaunchAgent").is_ok()
            };
            if serves.is_some() && present() {
                unload()?;
                let deadline = Instant::now() + stop_limit;
                while present() {
                    ensure!(
                        Instant::now() < deadline,
                        "launchd still has {service} after {} seconds",
                        stop_limit.as_secs()
                    );
                    thread::sleep(Duration::from_millis(100));
                }
            }
            match previous {
                Some(previous) => {
                    stage(directory, &previous.contents)?.persist(&job.plist)?;
                }
                None => match fs::remove_file(&job.plist) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                },
            }
            if loaded {
                load()?;
                if let Some(serves) = serves {
                    serves(None).context("the restored service did not come up")?;
                }
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(restore) = restore {
            return Err(error.context(format!(
                "could not restore the previous LaunchAgent: {restore:#}"
            )));
        }
        return Err(match serves {
            Some(_) if loaded => error.context("the previous service was restored and answers"),
            _ => error,
        });
    }
    println!("Loaded {} for this login session", job.label);
    println!("Event log       {}", job.events.display());
    println!("Read service diagnostics with 'massrelay logs'.");
    Ok(dir)
}

pub fn control(dir: &Path, action: ServiceAction) -> Result<()> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let job = Job::for_profile(&dir)?;
    let result = (|| {
        let metadata = fs::symlink_metadata(&job.plist).with_context(|| {
            format!("find {}. Run massrelay install first", job.plist.display())
        })?;
        ensure!(
            metadata.is_file(),
            "expected a regular file at {}",
            job.plist.display()
        );
        let domain = login_domain()?;
        let service = format!("{domain}/{}", job.label);
        let loaded = launchctl("print", &service).output()?.status.success();
        match action {
            ServiceAction::Stop if loaded => unload(&service),
            ServiceAction::Stop => Ok(()),
            ServiceAction::Start | ServiceAction::Restart if loaded => {
                kickstart(&service, matches!(action, ServiceAction::Restart))
            }
            ServiceAction::Start | ServiceAction::Restart => {
                {
                    let _lock = cli::claim_owner(&dir)
                        .context("stop the foreground massrelay run first")?;
                }
                bootstrap(&domain, &job.plist)
            }
        }
    })();
    action.record(&job.events, &result);
    result?;
    println!("{} {}", action.completed(), job.label);
    Ok(())
}

/// A removal as shown for confirmation, which displays as the changes it would make.
pub struct UninstallPlan {
    /// The canonical state directory, and the job `install` gives it.
    dir: PathBuf,
    job: Job,
    found: Found,
    text: String,
}

impl fmt::Display for UninstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// What there is to unload and remove for this profile. Changes nothing.
pub fn plan_uninstall(dir: &Path) -> Result<UninstallPlan> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let job = Job::for_profile(&dir)?;
    let (found, text) = manage(&dir, &job, |removal| {
        let found = removal.inspect()?;
        let text = removal.describe(&found);
        Ok((found, text))
    })?;
    Ok(UninstallPlan {
        dir,
        job,
        found,
        text,
    })
}

impl UninstallPlan {
    /// Unload this profile's LaunchAgent and remove its property list, with any update job
    /// that has finished, if all are still as they were shown. The profile, its keys and its
    /// logs are kept. A plan that showed nothing to remove succeeds while there is still
    /// nothing.
    ///
    /// A hangup is ignored from the first change until this command ends: a terminal that
    /// reached this device through the service goes away when it stops.
    pub fn apply(self) -> Result<()> {
        manage(&self.dir, &self.job, |removal| {
            let found = removal.confirm(&self.found)?;
            // SAFETY: ignoring a signal installs no handler.
            unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
            let done = removal.remove(found)?;
            // The terminal may be gone, which must not turn a finished removal into a panic.
            let _ = writeln!(io::stdout(), "{done}");
            Ok(())
        })
    }
}

/// Look at one profile's LaunchAgent with macOS's own tools.
fn manage<T>(dir: &Path, job: &Job, work: impl FnOnce(&Removal) -> Result<T>) -> Result<T> {
    work(&Removal {
        dir,
        job,
        shell_host: env::var(crate::private::HOST_ENV)
            .ok()
            .and_then(|value| value.parse().ok()),
        process: std::process::id(),
        stop_limit: STOP_LIMIT,
        run: &tool,
    })
}

/// Runs a program, by its path and with these arguments, within a time limit.
type Tool<'a> = &'a dyn Fn(&str, &[&str]) -> Result<crate::update::Finished>;

/// What there is to remove for a profile.
#[derive(Debug)]
struct Found {
    /// The login session's domain, when there is one to hold jobs.
    domain: Option<String>,
    /// The generated property list.
    plist: Option<Plist>,
    /// The service's job, as launchd has it loaded.
    loaded: Option<Loaded>,
    /// An update job that has ended and that launchd still holds.
    finished_update: Option<Loaded>,
}

impl Found {
    /// Whether removing this is removing `shown`.
    fn is(&self, shown: &Self) -> bool {
        self.plist == shown.plist
            && self.loaded == shown.loaded
            && self.finished_update == shown.finished_update
    }
}

/// A property list as it was read: its bytes, and which writing of the file held them.
#[derive(Debug, PartialEq, Eq)]
struct Plist {
    contents: Vec<u8>,
    /// Device, inode and modification time. An install replaces the file, even with the
    /// same bytes.
    written: (u64, u64, SystemTime),
}

/// What identifies a loaded job: not whether or as which process it runs.
#[derive(Debug, PartialEq, Eq)]
struct Loaded {
    arguments: Vec<String>,
    /// The property list launchd says it loaded the job from.
    path: Option<String>,
}

impl Loaded {
    /// From `launchctl print` output, if the job's arguments can be read there.
    fn read(printed: &str) -> Option<Self> {
        Some(Self {
            arguments: job_arguments(printed)?,
            path: printed
                .lines()
                .find_map(|line| line.trim().strip_prefix("path = "))
                .map(str::to_owned),
        })
    }
}

/// The removal of one profile's LaunchAgent.
struct Removal<'a> {
    /// The canonical state directory.
    dir: &'a Path,
    job: &'a Job,
    /// The runtime serving the MassRelay shell this command says it is in.
    shell_host: Option<u32>,
    /// This command's process ID.
    process: u32,
    stop_limit: Duration,
    run: Tool<'a>,
}

impl Removal<'_> {
    /// Establish that everything to be unloaded or removed is this profile's, and that doing
    /// so is safe now. Changes nothing.
    fn inspect(&self) -> Result<Found> {
        let plist = plist_file(&self.job.plist)?;
        if plist.is_some() {
            self.check_plist()?;
        }
        let domain = user_domain(self.run)?;
        let mut found = Found {
            domain: None,
            plist,
            loaded: None,
            finished_update: None,
        };
        if let Err(error) = check_session(&domain, self.run) {
            // launchd holds a login's jobs only while it lasts. With a property list to
            // remove, whether its job is loaded has to be known.
            return if found.plist.is_none() {
                Ok(found)
            } else {
                Err(error)
            };
        }

        let target = format!("{domain}/{}", self.job.label);
        if let Some(printed) = self.print(&target)? {
            let dir = path_text(self.dir)?;
            let job = Loaded::read(&printed)
                .filter(|job| {
                    job.arguments
                        .get(1..4)
                        .is_some_and(|run| run == ["--state-dir", dir, "run"])
                })
                .with_context(|| {
                    format!(
                        "launchd has a job {target} that cannot be matched to this profile's \
                         service; nothing was changed. Inspect it with 'launchctl print {target}'"
                    )
                })?;
            if let Some(pid) = job_pid(&printed) {
                let processes = (self.run)("/bin/ps", &["-A", "-o", "pid=,ppid="])
                    .context("find what started this command")?;
                ensure!(processes.success, "find what started this command failed");
                ensure!(
                    self.shell_host != Some(pid) && !descends(&processes.stdout, self.process, pid),
                    HOSTED
                );
            }
            found.loaded = Some(job);
        }

        let update = format!("{target}.update");
        if let Some(printed) = self.print(&update)? {
            ensure!(
                finished(&printed),
                "an update of this service is queued or running as {update}; nothing was \
                 changed. Run 'massrelay uninstall' once it has finished, or cancel it while it \
                 waits with 'launchctl bootout {update}'"
            );
            // One that cannot be matched to this profile is left alone.
            let dir = path_text(self.dir)?;
            found.finished_update = Loaded::read(&printed).filter(|job| {
                job.arguments
                    .ends_with(&["--state-dir", dir, "update"].map(String::from))
            });
        }
        found.domain = Some(domain);
        Ok(found)
    }

    /// Inspect again, and require what is there now to be what was shown.
    fn confirm(&self, shown: &Found) -> Result<Found> {
        let found = self.inspect()?;
        ensure!(found.is(shown), CHANGED);
        Ok(found)
    }

    /// Require the property list to be one `install` writes for this profile.
    fn check_plist(&self) -> Result<()> {
        let path = path_text(&self.job.plist)?;
        let read = (self.run)(
            "/usr/bin/plutil",
            &["-convert", "json", "-o", "-", "--", path],
        )
        .context("read the LaunchAgent")?;
        ensure!(
            read.success,
            "could not read {path} as a property list; nothing was changed"
        );
        let plist: serde_json::Value = serde_json::from_str(&read.stdout)
            .with_context(|| format!("read {path}; nothing was changed"))?;
        let argument = |index: usize| plist["ProgramArguments"][index].as_str();
        ensure!(
            plist["Label"].as_str() == Some(&self.job.label)
                && argument(1) == Some("--state-dir")
                && argument(2) == Some(path_text(self.dir)?)
                && argument(3) == Some("run"),
            "{path} was not written by 'massrelay install' for this profile; nothing was changed"
        );
        Ok(())
    }

    /// What launchd prints for a job, when it is loaded.
    fn print(&self, target: &str) -> Result<Option<String>> {
        let printed = (self.run)("/bin/launchctl", &["print", target])
            .with_context(|| format!("look for {target}"))?;
        Ok(printed.success.then_some(printed.stdout))
    }

    fn describe(&self, found: &Found) -> String {
        let (label, dir) = (&self.job.label, self.dir.display());
        let plist = self.job.plist.display();
        let mut steps = vec![];
        if let Some(domain) = &found.domain
            && found.loaded.is_some()
        {
            steps.push(format!(
                "Unload the LaunchAgent {label} from {domain}, which stops it"
            ));
        }
        if found.plist.is_some() {
            steps.push(format!("Remove its property list {plist}"));
        }
        if found.finished_update.is_some() {
            steps.push(format!("Unload the finished update job {label}.update"));
        }
        if steps.is_empty() {
            let mut text = format!(
                "No LaunchAgent to remove for the profile in {dir}: there is no property list \
                 at {plist}"
            );
            if found.domain.is_none() {
                text.push_str("\nThere is no login session to hold a loaded one");
            }
            return text;
        }
        steps.push(format!(
            "Keep the device profile and keys in {dir}, and the logs"
        ));
        steps.join("\n")
    }

    fn remove(&self, found: Found) -> Result<String> {
        if found.loaded.is_none() && found.plist.is_none() && found.finished_update.is_none() {
            return Ok(self.describe(&found));
        }
        let domain = found.domain.as_deref().context("no login session")?;
        let target = format!("{domain}/{}", self.job.label);
        if found.loaded.is_some() {
            // Immediately before the first change.
            ensure!(
                plist_file(&self.job.plist)? == found.plist
                    && self.print(&target)?.as_deref().and_then(Loaded::read) == found.loaded,
                CHANGED
            );
            self.unload(domain, &self.job.label).context(
                "the property list is kept. Run 'massrelay uninstall' again once the service \
                 has stopped",
            )?;
        }
        if let Some(plist) = &found.plist {
            ensure!(
                plist_file(&self.job.plist)?.as_ref() == Some(plist)
                    && self.print(&target)?.is_none(),
                "{} changed, or its job was loaded again; it was not removed",
                self.job.plist.display()
            );
            fs::remove_file(&self.job.plist)
                .with_context(|| format!("remove {}", self.job.plist.display()))?;
        }
        if let Some(job) = &found.finished_update {
            let label = format!("{}.update", self.job.label);
            // Nothing may have started it since it was looked at.
            if let Some(printed) = self.print(&format!("{domain}/{label}"))? {
                ensure!(
                    finished(&printed) && Loaded::read(&printed).as_ref() == Some(job),
                    "{label} changed or started again and was left loaded. Run 'massrelay \
                     uninstall' again once it has finished"
                );
                self.unload(domain, &label)?;
            }
        }
        Ok(format!("Removed {}", self.job.label))
    }

    /// Unload a job, and wait within the limit until launchd no longer has it.
    fn unload(&self, domain: &str, label: &str) -> Result<()> {
        let target = format!("{domain}/{label}");
        let asked = (self.run)("/bin/launchctl", &["bootout", &target])
            .with_context(|| format!("unload {target}"))?;
        let deadline = Instant::now() + self.stop_limit;
        // What is asked for is that the job is gone, whatever `bootout` itself reported.
        while self.print(&target)?.is_some() {
            ensure!(
                Instant::now() < deadline,
                "launchd still has {target} after {} seconds: {}",
                self.stop_limit.as_secs(),
                asked
                    .stderr
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            thread::sleep(Duration::from_millis(100));
        }
        // A session that ended meanwhile answers nothing, which says nothing about the job.
        check_session(domain, self.run)
    }
}

/// Whether `launchctl print` positively says that a loaded job is not running.
fn finished(printed: &str) -> bool {
    let mut lines = printed.lines().map(str::trim);
    !lines.clone().any(|line| line.starts_with("pid = "))
        // The job's own state comes first; nested sections have states of their own.
        && lines.find_map(|line| line.strip_prefix("state = ")) == Some("not running")
}

/// Whether `ancestor` started `process`, at any remove, in `ps -o pid=,ppid=` output.
fn descends(table: &str, process: u32, ancestor: u32) -> bool {
    let parents: std::collections::HashMap<u32, u32> = table
        .lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace().map(str::parse);
            Some((columns.next()?.ok()?, columns.next()?.ok()?))
        })
        .collect();
    std::iter::successors(Some(process), |process| parents.get(process).copied())
        // A listing taken while processes come and go must not be followed for ever.
        .take(parents.len() + 1)
        .any(|found| found == ancestor)
}

/// An installed LaunchAgent, for `massrelay update`.
pub struct Managed {
    dir: PathBuf,
    job: Job,
    domain: String,
}

pub fn managed(dir: &Path) -> Result<Managed> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let job = Job::for_profile(&dir)?;
    let installed = fs::symlink_metadata(&job.plist).is_ok_and(|metadata| metadata.is_file());
    ensure!(
        installed,
        "no installed service for this profile. Run massrelay install first"
    );
    let domain = bounded_domain()?;
    Ok(Managed { dir, job, domain })
}

impl Managed {
    fn target(&self) -> String {
        format!("{}/{}", self.domain, self.job.label)
    }

    /// What launchd prints for the job, when it is loaded.
    fn loaded(&self) -> Result<Option<String>> {
        let printed = bounded(&mut launchctl("print", &self.target()))?;
        Ok(printed.success.then_some(printed.stdout))
    }

    /// Run `massrelay update` for this profile with `program`, the installed program the
    /// service starts, as a launchd job of its own, which outlives the calling command and
    /// its shell. At most one such job runs at a time. Returns what to tell the person who
    /// asked: whether it was started or was already under way, and how to follow it.
    pub fn queue_update(&self, program: &Path) -> Result<String> {
        ensure!(
            crate::update::Service::launches(self, program)?,
            "the service {} is not set up to start {} for this profile. Run 'massrelay \
             install' again, then 'massrelay update'",
            self.job.label,
            program.display()
        );
        update_job::OneShot {
            domain: &self.domain,
            label: format!("{}.update", self.job.label),
            command: update_job::Command::Update,
            program,
            dir: &self.dir,
            log: &self.job.update_log,
        }
        .queue(&|args| bounded(Command::new("/bin/launchctl").args(args)))
    }
}

/// `login_domain`, with each request bounded, for the update.
fn bounded_domain() -> Result<String> {
    let domain = user_domain(&tool)?;
    check_session(&domain, &tool)?;
    Ok(domain)
}

/// This account's login domain, whether or not a session holds it now.
fn user_domain(run: Tool) -> Result<String> {
    let uid = run("/usr/bin/id", &["-u"]).context("read the user ID")?;
    ensure!(uid.success, "read the user ID failed");
    let uid = uid.stdout.trim().parse::<u32>()?;
    ensure!(
        uid != 0,
        "manage MassRelay from your Mac account without sudo"
    );
    Ok(format!("gui/{uid}"))
}

fn check_session(domain: &str, run: Tool) -> Result<()> {
    let session =
        run("/bin/launchctl", &["print", domain]).context("find the macOS login session")?;
    if !session.success {
        let error = session.stderr.trim();
        if error.is_empty() {
            bail!("launchctl print {domain} failed");
        }
        bail!("launchctl print {domain} failed: {}", crate::visible(error));
    }
    Ok(())
}

fn tool(program: &str, args: &[&str]) -> Result<crate::update::Finished> {
    bounded(Command::new(program).args(args))
}

/// A command, within the limit an update gives one request to a service manager.
fn bounded(command: &mut Command) -> Result<crate::update::Finished> {
    crate::update::run_within(command, crate::update::MANAGER_LIMIT)
}

impl crate::update::Service for Managed {
    fn label(&self) -> String {
        self.job.label.clone()
    }

    fn events(&self) -> PathBuf {
        self.job.events.clone()
    }

    fn launches(&self, program: &Path) -> Result<bool> {
        let extracted = bounded(
            Command::new("/usr/bin/plutil")
                .args(["-extract", "ProgramArguments", "json", "-o", "-", "--"])
                .arg(&self.job.plist),
        )
        .context("read the LaunchAgent's program")?;
        ensure!(extracted.success, "read the LaunchAgent's program failed");
        let arguments: Vec<String> = serde_json::from_str(&extracted.stdout)?;
        let expected = [
            path_text(program)?,
            "--state-dir",
            path_text(&self.dir)?,
            "run",
        ];
        let starts = |arguments: &[String]| {
            arguments.len() >= expected.len() && arguments.iter().zip(expected).all(|(a, b)| a == b)
        };
        if !starts(&arguments) {
            return Ok(false);
        }
        // launchd reads the plist when it loads the job, so a loaded job can differ from the
        // file. A job that is not loaded will be loaded from the file.
        Ok(match self.loaded()? {
            Some(printed) => job_arguments(&printed).is_some_and(|loaded| starts(&loaded)),
            None => true,
        })
    }

    /// A job that is not loaded is stopped. A loaded job with a process is running. A loaded
    /// job without one is neither: launchd keeps such a job alive and is about to start it.
    fn state(&self) -> Result<crate::update::Manager> {
        use crate::update::Manager;
        Ok(match self.loaded()? {
            None => Manager::Stopped,
            Some(printed) => match job_pid(&printed) {
                Some(pid) => Manager::Running(pid),
                None => Manager::Pending("as loaded, with no process yet".into()),
            },
        })
    }

    /// Load the job, which starts it. A loaded job is launchd's to start, and is left to it.
    fn start(&self) -> Result<()> {
        if self.loaded()?.is_some() {
            return Ok(());
        }
        let mut command = launchctl("bootstrap", &self.domain);
        command.arg(&self.job.plist);
        let started = bounded(&mut command).context("start the LaunchAgent")?;
        ensure!(
            started.success,
            "start the LaunchAgent failed: {}",
            started
                .stderr
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        );
        Ok(())
    }
}

/// The process ID in `launchctl print` output for a running job.
fn job_pid(printed: &str) -> Option<u32> {
    printed
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = ")?.trim().parse().ok())
}

/// The arguments in `launchctl print` output for a loaded job.
fn job_arguments(printed: &str) -> Option<Vec<String>> {
    let mut lines = printed.lines().map(str::trim);
    lines.find(|line| *line == "arguments = {")?;
    let mut arguments = vec![];
    for line in lines {
        if line == "}" {
            return Some(arguments);
        }
        arguments.push(line.to_owned());
    }
    None
}

fn login_domain() -> Result<String> {
    let uid = checked(Command::new("/usr/bin/id").arg("-u"), "read the user ID")?;
    let uid = std::str::from_utf8(&uid.stdout)?.trim().parse::<u32>()?;
    ensure!(
        uid != 0,
        "manage MassRelay from your Mac account without sudo"
    );
    let domain = format!("gui/{uid}");
    checked(
        &mut launchctl("print", &domain),
        "find the macOS login session",
    )?;
    Ok(domain)
}

#[derive(Debug, PartialEq, Eq)]
struct Job {
    label: String,
    plist: PathBuf,
    events: PathBuf,
    /// The output of the last update that ran as a job of its own.
    update_log: PathBuf,
    /// The same for an install.
    install_log: PathBuf,
}

impl Job {
    fn for_profile(dir: &Path) -> Result<Self> {
        let default = default_state_dir()?.canonicalize().ok();
        let home = BaseDirs::new().context("cannot find the user home directory")?;
        Self::new(home.home_dir(), dir, default.as_deref())
    }

    fn new(home: &Path, dir: &Path, default: Option<&Path>) -> Result<Self> {
        let mut label = LABEL.to_owned();
        let mut name = "MassRelay".to_owned();
        if default != Some(dir) {
            let profile = format!("{:x}", Sha256::digest(path_text(dir)?.as_bytes()));
            label.push('.');
            label.push_str(&profile);
            name.push('-');
            name.push_str(&profile);
        }
        let library = home.join("Library");
        let logs = library.join("Logs");
        Ok(Self {
            plist: library.join("LaunchAgents").join(format!("{label}.plist")),
            events: logs.join(format!("{name}-connections.jsonl")),
            update_log: logs.join(format!("{name}-update.log")),
            install_log: logs.join(format!("{name}-install.log")),
            label,
        })
    }

    fn render(&self, binary: &Path, dir: &Path) -> Result<String> {
        let binary = escape_xml(path_text(binary)?);
        let state = escape_xml(path_text(dir)?);
        let events = escape_xml(path_text(&self.events)?);
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
    <string>{binary}</string>
    <string>--state-dir</string>
    <string>{state}</string>
    <string>run</string>
    <string>--log-file</string>
    <string>{events}</string>
  </array>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
"#
        ))
    }
}

/// A property list's contents, if there is one. Only a regular file is read.
fn read_plist(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(fs::read(path)?)),
        Ok(_) => bail!("expected a regular file at {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// `read_plist`, with which writing of the file was read.
fn plist_file(path: &Path) -> Result<Option<Plist>> {
    use std::os::unix::fs::MetadataExt;

    let Some(contents) = read_plist(path)? else {
        return Ok(None);
    };
    let metadata = fs::symlink_metadata(path)?;
    Ok(Some(Plist {
        contents,
        written: (metadata.dev(), metadata.ino(), metadata.modified()?),
    }))
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}

fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#13;")
}

fn stage(dir: &Path, contents: &[u8]) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new_in(dir)?;
    file.write_all(contents)?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn launchctl(action: &str, target: &str) -> Command {
    let mut command = Command::new("/bin/launchctl");
    command.args([action, target]);
    command
}

fn bootstrap(domain: &str, plist: &Path) -> Result<()> {
    checked(
        launchctl("bootstrap", domain).arg(plist),
        "load the LaunchAgent",
    )?;
    Ok(())
}

fn unload(service: &str) -> Result<()> {
    checked(&mut launchctl("bootout", service), "unload the LaunchAgent")?;
    Ok(())
}

fn kickstart(service: &str, restart: bool) -> Result<()> {
    let mut command = Command::new("/bin/launchctl");
    command.arg("kickstart");
    if restart {
        command.arg("-k");
    }
    let action = if restart {
        "restart the LaunchAgent"
    } else {
        "start the LaunchAgent"
    };
    checked(command.arg(service), action)?;
    Ok(())
}

fn checked(command: &mut Command, action: &str) -> Result<Output> {
    let result = command.output().with_context(|| action.to_owned())?;
    ensure!(
        result.status.success(),
        "{action} failed ({}): {}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    );
    Ok(result)
}

// These read property lists with macOS's own tool.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn launch_agent_records_the_profile_and_preserves_special_characters() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let home = temp.path().join("A & B");
        let dir = home.join("<my profile>");
        let binary = home.join("bin/massrelay");
        let default = Job::new(&home, &dir, Some(&dir))?;
        let custom = Job::new(&home, &dir, None)?;
        assert_eq!(default.label, LABEL);
        assert_ne!(default.plist, custom.plist);
        assert_ne!(default.events, custom.events);
        assert_eq!(
            job_pid("gui/501/com.massrelay.client = {\n\tstate = running\n\tpid = 4242\n}"),
            Some(4242)
        );
        assert_eq!(
            job_pid("\tstate = not running\n\tlast exit code = 0\n"),
            None
        );
        assert_eq!(
            job_arguments(
                "x = {\n\tprogram = /a b/massrelay\n\targuments = {\n\t\t/a b/massrelay\n\t\t--state-dir\n\t\t/s\n\t\trun\n\t}\n\tpid = 7\n}"
            ),
            Some(
                ["/a b/massrelay", "--state-dir", "/s", "run"]
                    .map(String::from)
                    .to_vec()
            )
        );
        assert_eq!(job_arguments("x = {\n\tstate = running\n}"), None);
        let source = custom.render(&binary, &dir)?;
        let file = stage(temp.path(), source.as_bytes())?;
        let args = checked(
            Command::new("/usr/bin/plutil")
                .args(["-extract", "ProgramArguments", "json", "-o", "-", "--"])
                .arg(file.path()),
            "read the serialized LaunchAgent arguments",
        )?;
        assert_eq!(
            serde_json::from_slice::<Vec<String>>(&args.stdout)?,
            [
                path_text(&binary)?,
                "--state-dir",
                path_text(&dir)?,
                "run",
                "--log-file",
                path_text(&custom.events)?,
            ]
        );
        Ok(())
    }
}

/// Planned installs and removals, with macOS's tools stood in for.
#[cfg(all(test, unix))]
mod plan_tests {
    use std::cell::RefCell;

    use super::*;

    /// A login domain with the profile's service and update jobs.
    #[derive(Default)]
    struct Launchd {
        session: bool,
        /// What `print` says of each job, when it is loaded.
        service: Option<String>,
        update: Option<String>,
        /// What `plutil` reads from the property list.
        plist: String,
        /// `bootout` leaves the job loaded.
        stuck: bool,
        changes: Vec<String>,
    }

    impl Launchd {
        fn run(
            state: &RefCell<Self>,
            program: &str,
            args: &[&str],
        ) -> Result<crate::update::Finished> {
            let mut launchd = state.borrow_mut();
            let mut success = true;
            let stdout = match (program, args[0]) {
                ("/usr/bin/id", _) => "501\n".into(),
                ("/usr/bin/plutil", _) => launchd.plist.clone(),
                // This command is process 30, started by 20, which 7 started.
                ("/bin/ps", _) => " 7 1\n 20 7\n 30 20\n".into(),
                ("/bin/launchctl", verb) => {
                    let target = args[1];
                    if target == "gui/501" {
                        success = launchd.session;
                        String::new()
                    } else {
                        let update = target.ends_with(".update");
                        if verb != "print" {
                            launchd.changes.push(target.to_owned());
                        }
                        let stuck = launchd.stuck;
                        let job = if update {
                            &mut launchd.update
                        } else {
                            &mut launchd.service
                        };
                        if verb == "bootout" && !stuck {
                            *job = None;
                        }
                        success = job.is_some() || verb == "bootout";
                        job.clone().unwrap_or_default()
                    }
                }
                _ => anyhow::bail!("unexpected program {program}"),
            };
            Ok(crate::update::Finished {
                success,
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn an_install_applies_only_over_what_was_shown() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let dir = temp.path().join("profile");
        let job = || Job::new(temp.path(), &dir, None).unwrap();
        let plist = job().plist;
        let launchd = RefCell::new(Launchd {
            session: true,
            ..Default::default()
        });
        let run = |program: &str, args: &[&str]| Launchd::run(&launchd, program, args);
        let read = |binary: &str| Prepared::read(dir.clone(), job(), binary.into(), &run);
        let refused = |plan: &InstallPlan, binary: &str| {
            assert!(plan.confirm(read(binary).unwrap()).is_err());
        };
        let loaded = |program: &str, pid: u32| {
            Some(format!(
                "x = {{\n\tpid = {pid}\n\targuments = {{\n\t\t{program}\n\t}}\n}}"
            ))
        };

        // Nothing is installed, and looking makes nothing.
        let plan = InstallPlan::new(read("/m")?);
        plan.confirm(read("/m")?)?;
        assert!(!plist.parent().unwrap().exists());
        refused(&plan, "/other");
        fs::create_dir_all(plist.parent().unwrap())?;
        fs::write(&plist, "installed since")?;
        refused(&plan, "/m");

        // A job loaded since the plan showed none would have to be unloaded.
        let plan = InstallPlan::new(read("/m")?);
        launchd.borrow_mut().service = loaded("/m", 7);
        refused(&plan, "/m");
        // One shown as loaded may restart meanwhile, but not become another, or go.
        let plan = InstallPlan::new(read("/m")?);
        launchd.borrow_mut().service = loaded("/m", 8);
        plan.confirm(read("/m")?)?;
        for changed in [loaded("/other", 8), None] {
            launchd.borrow_mut().service = changed;
            refused(&plan, "/m");
        }
        launchd.borrow_mut().service = loaded("/m", 8);
        // The property list was written anew, even alike.
        let _earlier = fs::File::open(&plist)?;
        stage(plist.parent().unwrap(), b"installed since")?.persist(&plist)?;
        refused(&plan, "/m");
        assert!(launchd.borrow().changes.is_empty());
        assert_eq!(fs::read_to_string(&plist)?, "installed since");
        Ok(())
    }

    #[test]
    fn a_carried_install_keeps_only_a_job_it_would_not_change() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let dir = temp.path().join("profile");
        let binary = temp.path().join("massrelay");
        fs::write(&binary, "program")?;
        let job = || Job::new(temp.path(), &dir, None).unwrap();
        let source = job().render(&binary, &dir)?;
        fs::create_dir_all(job().plist.parent().unwrap())?;
        let runtime = Identity {
            pid: 99,
            executable: binary.to_str().map(str::to_owned),
            version: env!("CARGO_PKG_VERSION").into(),
            endpoint: String::new(),
            held: false,
        };
        let printed = |events: &Path| {
            format!(
                "x = {{\n\tpath = {}\n\tpid = 99\n\targuments = {{\n\t\t{}\n\t\t--state-dir\n\t\t{}\n\
                 \t\trun\n\t\t--log-file\n\t\t{}\n\t}}\n}}",
                job().plist.display(),
                binary.display(),
                dir.display(),
                events.display()
            )
        };
        let launchd = RefCell::new(Launchd {
            session: true,
            service: Some(printed(&job().events)),
            ..Default::default()
        });
        let run = |program: &str, args: &[&str]| Launchd::run(&launchd, program, args);
        let carried = |runtime: &Identity| {
            let read = Prepared::read(dir.clone(), job(), binary.clone(), &run)?;
            let mut plan = InstallPlan::new(read);
            plan.inspect_carrier(runtime, &run)?;
            anyhow::Ok(plan.keeps())
        };

        fs::write(&job().plist, &source)?;
        assert!(carried(&runtime)?);
        let older = Identity {
            version: "0.0.1".into(),
            ..runtime.clone()
        };
        assert!(!carried(&older)?);
        // Loaded with something else than the file says.
        launchd.borrow_mut().service = Some(printed(Path::new("/elsewhere")));
        assert!(carried(&runtime).is_err());
        launchd.borrow_mut().service = Some(printed(&job().events));
        fs::write(&job().plist, job().render(Path::new("/other"), &dir)?)?;
        assert!(carried(&runtime).is_err());
        let foreground = Identity {
            pid: 7,
            ..runtime.clone()
        };
        assert!(carried(&foreground).is_err());
        assert!(launchd.borrow().changes.is_empty());
        Ok(())
    }

    #[test]
    fn a_finished_install_that_does_not_serve_gives_way_to_the_previous_job() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let dir = temp.path().join("profile");
        let job = || Job::new(temp.path(), &dir, None).unwrap();
        let plist = job().plist;
        fs::create_dir_all(plist.parent().unwrap())?;
        let (old, new) = (Path::new("/opt/previous"), Path::new("/opt/replacement"));
        let previous = job().render(old, &dir)?;
        // Install over the loaded previous job, with a runtime that answers only while the
        // property list starts one of `answering`.
        let install = |answering: &[&str], refuse_load: bool| {
            fs::write(&plist, &previous)?;
            let prepared = Prepared {
                dir: dir.clone(),
                job: job(),
                domain: "gui/501".into(),
                service: format!("gui/501/{LABEL}"),
                loaded: Some(None),
                previous: plist_file(&plist)?,
                binary: new.into(),
                contents: job().render(new, &dir)?,
            };
            // Whether launchd has the job, the commands run, and a load still to refuse.
            let asked = RefCell::new((true, Vec::new(), refuse_load));
            let run = |command: &mut Command, _: &str| {
                let verb = command
                    .get_args()
                    .next()
                    .and_then(|verb| verb.to_str())
                    .context("no verb")?
                    .to_owned();
                let (loaded, commands, refuse) = &mut *asked.borrow_mut();
                commands.push(verb.clone());
                match verb.as_str() {
                    "-lint" | "enable" => {}
                    "print" => ensure!(*loaded, "not loaded"),
                    "bootout" => {
                        ensure!(*loaded, "not loaded");
                        *loaded = false;
                    }
                    "bootstrap" => {
                        ensure!(!*loaded && !std::mem::take(refuse), "refused");
                        *loaded = true;
                    }
                    other => bail!("unexpected {other}"),
                }
                Ok(())
            };
            let serves = |program: Option<&Path>| {
                let program = program.map_or_else(String::new, |path| path.display().to_string());
                asked.borrow_mut().1.push(format!("serves {program}"));
                let contents = fs::read_to_string(&plist)?;
                ensure!(
                    answering.iter().any(|program| contents.contains(program)),
                    "nothing answers"
                );
                Ok(())
            };
            let result = register(prepared, &run, Duration::from_secs(5), Some(&serves))
                .map_err(|error| format!("{error:#}"));
            let (loaded, commands, _) = asked.into_inner();
            assert!(loaded, "no job was left loaded: {commands:?}");
            anyhow::Ok((result, commands, fs::read_to_string(&plist)?))
        };
        let replacing = ["-lint", "bootout", "enable", "bootstrap"];

        let (result, commands, left) = install(&["/opt/replacement"], false)?;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(commands[..4], replacing);
        assert_eq!(commands[4..], ["serves /opt/replacement"]);
        assert_ne!(left, previous);

        // The silent replacement is unloaded, and seen to be gone, before the old one loads.
        let (result, commands, left) = install(&["/opt/previous"], false)?;
        let error = result.unwrap_err();
        assert!(error.contains("restored and answers"), "{error}");
        assert_eq!(
            commands[4..],
            [
                "serves /opt/replacement",
                "print",
                "bootout",
                "print",
                "bootstrap",
                "serves "
            ]
        );
        assert_eq!(left, previous);

        // One that never loaded leaves nothing to unload.
        let (result, commands, left) = install(&["/opt/previous"], true)?;
        assert!(result.is_err());
        assert_eq!(commands[4..], ["print", "bootstrap", "serves "]);
        assert_eq!(left, previous);

        let (result, ..) = install(&[], false)?;
        let error = result.unwrap_err();
        assert!(error.contains("could not restore"), "{error}");
        Ok(())
    }

    #[test]
    fn uninstall_unloads_only_this_profiles_jobs_and_can_be_repeated() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let dir = temp.path().join("my profile");
        fs::create_dir(&dir)?;
        let job = Job::new(temp.path(), &dir, None)?;
        fs::create_dir_all(job.plist.parent().unwrap())?;
        fs::write(&job.plist, "generated")?;
        fs::write(dir.join("kept"), "enrollment")?;
        let state = path_text(&dir)?;
        let printed = |pid: &str, run: &str, state: &str| {
            format!(
                "x = {{\n\tstate = {pid}\n\targuments = {{\n\t\t/m\n\t\t--state-dir\n\t\t{state}\n\t\t{run}\n\t}}\n}}"
            )
        };
        let running = |pid| printed(&format!("running\n\tpid = {pid}"), "run", state);
        let plist = |state: &str| {
            serde_json::json!({
                "Label": job.label,
                "ProgramArguments": ["/m", "--state-dir", state, "run"],
            })
            .to_string()
        };
        let launchd = RefCell::new(Launchd {
            session: true,
            service: Some(running(99)),
            update: Some(printed("not running", "update", state)),
            plist: plist(state),
            ..Default::default()
        });
        let run = |program: &str, args: &[&str]| Launchd::run(&launchd, program, args);
        let removal = Removal {
            dir: &dir,
            job: &job,
            shell_host: None,
            process: 30,
            stop_limit: Duration::ZERO,
            run: &run,
        };
        // As the command does it: shown, then applied to what was shown.
        let uninstall = |removal: &Removal| {
            let shown = removal.inspect()?;
            removal.remove(removal.confirm(&shown)?)
        };
        let changes = || std::mem::take(&mut launchd.borrow_mut().changes);
        let refused = |removal: &Removal| {
            let error = format!("{:#}", uninstall(removal).unwrap_err());
            assert!(job.plist.exists(), "{error}");
            assert!(changes().is_empty(), "{error}");
        };

        // A property list, or a loaded job, that is another profile's.
        launchd.borrow_mut().plist = plist("/elsewhere");
        refused(&removal);
        launchd.borrow_mut().plist = plist(state);
        launchd.borrow_mut().service = Some(printed("running", "run", "/elsewhere"));
        refused(&removal);
        launchd.borrow_mut().service = Some(running(99));
        // The command would end with the service: by its shell's host, or as its descendant.
        refused(&Removal {
            shell_host: Some(99),
            ..removal
        });
        launchd.borrow_mut().service = Some(running(7));
        refused(&removal);
        launchd.borrow_mut().service = Some(running(99));
        // An update under way, and a session whose jobs cannot be seen.
        let idle = launchd.borrow_mut().update.replace(running(55));
        refused(&removal);
        launchd.borrow_mut().update = idle;
        launchd.borrow_mut().session = false;
        refused(&removal);
        launchd.borrow_mut().session = true;

        let shown = removal.inspect()?;
        let plan = removal.describe(&shown);
        assert!(plan.contains(&job.label) && plan.contains(path_text(&job.plist)?));
        assert!(changes().is_empty());
        // Another process for the same job leaves the registration as it was.
        launchd.borrow_mut().service = Some(running(98));
        removal.confirm(&shown)?;

        // Nothing shown, or one registration shown: another is not removed in its place.
        fs::remove_file(&job.plist)?;
        let service = launchd.borrow_mut().service.take();
        let update = launchd.borrow_mut().update.take();
        let nothing = removal.inspect()?;
        removal.confirm(&nothing)?;
        fs::write(&job.plist, "generated")?;
        assert!(removal.confirm(&nothing).is_err());
        // A job loaded since, with or without the property list, is refused too.
        fs::remove_file(&job.plist)?;
        launchd.borrow_mut().service = service;
        assert!(removal.confirm(&nothing).is_err());
        fs::write(&job.plist, "generated")?;
        launchd.borrow_mut().update = update;
        let shown = removal.inspect()?;
        // Written anew, even alike. The earlier file is kept open, so that its inode is not
        // used again.
        let replace = || -> Result<fs::File> {
            let earlier = fs::File::open(&job.plist)?;
            stage(job.plist.parent().unwrap(), b"generated")?.persist(&job.plist)?;
            Ok(earlier)
        };
        let _first = replace()?;
        assert!(removal.confirm(&shown).is_err());
        let shown = removal.inspect()?;
        // Replaced after the last inspection, right before the first change.
        let confirmed = removal.confirm(&shown)?;
        let _second = replace()?;
        assert!(removal.remove(confirmed).is_err());
        assert!(changes().is_empty());
        assert!(job.plist.exists());

        // A job launchd does not let go of keeps its property list.
        launchd.borrow_mut().stuck = true;
        assert!(uninstall(&removal).is_err());
        assert!(job.plist.exists());
        assert_eq!(changes(), [format!("gui/501/{}", job.label)]);
        launchd.borrow_mut().stuck = false;

        uninstall(&removal)?;
        assert!(!job.plist.exists());
        assert_eq!(
            changes(),
            [
                format!("gui/501/{}", job.label),
                format!("gui/501/{}.update", job.label)
            ]
        );

        // Nothing left: success, with or without a login session. A job whose file was removed
        // by hand is still found.
        uninstall(&removal)?;
        launchd.borrow_mut().session = false;
        uninstall(&removal)?;
        assert!(changes().is_empty());
        launchd.borrow_mut().session = true;
        launchd.borrow_mut().service = Some(running(99));
        uninstall(&removal)?;
        assert_eq!(changes(), [format!("gui/501/{}", job.label)]);
        assert_eq!(fs::read_to_string(dir.join("kept"))?, "enrollment");
        Ok(())
    }
}
