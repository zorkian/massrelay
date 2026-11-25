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

use crate::{ServiceAction, default_state_dir, device, storage};

const LABEL: &str = "com.massrelay.client";

pub fn install(dir: &Path) -> Result<()> {
    device::check_enrolled(dir)?;
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let job = Job::for_profile(&dir)?;
    let domain = login_domain()?;
    let service = format!("{domain}/{}", job.label);
    let loaded = launchctl("print", &service).output()?.status.success();

    if !loaded {
        let _lock = storage::lock(&dir).context("stop the foreground massrelay run first")?;
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
    println!("Service log     {}", job.log.display());
    Ok(())
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
            ServiceAction::Restart => {
                if loaded {
                    unload(&service)?;
                } else {
                    let _lock =
                        storage::lock(&dir).context("stop the foreground massrelay run first")?;
                }
                bootstrap(&domain, &job.plist)
            }
        }
    })();
    action.record(&job.events, &result);
    result?;
    println!(
        "{} {}",
        match action {
            ServiceAction::Restart => "Restarted",
            ServiceAction::Stop => "Stopped",
        },
        job.label
    );
    Ok(())
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
    log: PathBuf,
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
            log: logs.join(format!("{name}.log")),
            label,
        })
    }

    fn render(&self, binary: &Path, dir: &Path) -> Result<String> {
        let binary = escape_xml(path_text(binary)?);
        let state = escape_xml(path_text(dir)?);
        let events = escape_xml(path_text(&self.events)?);
        let log = escape_xml(path_text(&self.log)?);
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

fn checked(command: &mut Command, action: &str) -> Result<Output> {
    let result = command.output().with_context(|| action.to_owned())?;
    ensure!(
        result.status.success(),
        "{action} failed ({}): {}",
        result.status,
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(result)
}

#[cfg(test)]
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
