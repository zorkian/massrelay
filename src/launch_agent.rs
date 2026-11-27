use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result, bail, ensure};
use directories::BaseDirs;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{ServiceAction, default_state_dir, private::cli};

#[path = "launch_agent/update_job.rs"]
mod update_job;

const LABEL: &str = "com.massrelay.client";

/// The audit path used by installed LaunchAgents, including older installs.
pub fn audit_path(dir: &Path) -> Result<PathBuf> {
    Ok(Job::for_profile(dir)?.events)
}

/// Returns the canonical state directory the service was installed for.
pub fn install(dir: &Path) -> Result<PathBuf> {
    cli::check_enrolled(dir)?;
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let job = Job::for_profile(&dir)?;
    let domain = login_domain()?;
    let service = format!("{domain}/{}", job.label);
    let loaded = launchctl("print", &service).output()?.status.success();

    if !loaded {
        let _lock = cli::claim_owner(&dir).context("stop the foreground massrelay run first")?;
    }
    let directory = job.plist.parent().expect("LaunchAgents directory");
    fs::create_dir_all(directory)?;
    fs::create_dir_all(job.events.parent().expect("Logs directory"))?;
    let previous = match fs::symlink_metadata(&job.plist) {
        Ok(metadata) if metadata.is_file() => Some(fs::read(&job.plist)?),
        Ok(_) => bail!("expected a regular file at {}", job.plist.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    ensure!(
        !loaded || previous.is_some(),
        "the loaded LaunchAgent has no plist at {}",
        job.plist.display()
    );
    let binary = env::current_exe().context("find the running MassRelay binary")?;
    let contents = job.render(&binary, &dir)?;
    let staged = stage(directory, contents.as_bytes())?;
    checked(
        Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(staged.path()),
        "validate the LaunchAgent plist",
    )?;
    if loaded {
        unload(&service)?;
    }
    let registered = (|| {
        staged
            .persist(&job.plist)
            .context("save the LaunchAgent plist")?;
        checked(&mut launchctl("enable", &service), "enable the LaunchAgent")?;
        bootstrap(&domain, &job.plist)
    })();
    if let Err(error) = registered {
        let restore = (|| {
            match previous {
                Some(previous) => {
                    stage(directory, &previous)?.persist(&job.plist)?;
                }
                None => match fs::remove_file(&job.plist) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                },
            }
            if loaded {
                bootstrap(&domain, &job.plist)?;
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(restore) = restore {
            return Err(error.context(format!(
                "could not restore the previous LaunchAgent: {restore:#}"
            )));
        }
        return Err(error);
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
            program,
            dir: &self.dir,
            log: &self.job.update_log,
        }
        .queue(&|args| bounded(Command::new("/bin/launchctl").args(args)))
    }
}

/// `login_domain`, with each request bounded, for the update.
fn bounded_domain() -> Result<String> {
    let uid = bounded(Command::new("/usr/bin/id").arg("-u")).context("read the user ID")?;
    ensure!(uid.success, "read the user ID failed");
    let uid = uid.stdout.trim().parse::<u32>()?;
    ensure!(
        uid != 0,
        "manage MassRelay from your Mac account without sudo"
    );
    let domain = format!("gui/{uid}");
    let session =
        bounded(&mut launchctl("print", &domain)).context("find the macOS login session")?;
    ensure!(session.success, "find the macOS login session failed");
    Ok(domain)
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

struct Job {
    label: String,
    plist: PathBuf,
    events: PathBuf,
    /// The output of the last update that ran as a job of its own.
    update_log: PathBuf,
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
