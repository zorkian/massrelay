//! The Win32 side of the Windows background service: the Service Control Manager, the local
//! security policy, file permissions, and the service control protocol.

use std::{
    env,
    ffi::{OsStr, c_void},
    fs::{self, File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStrExt as _,
        fs::MetadataExt as _,
        io::{AsHandle as _, AsRawHandle as _, FromRawHandle as _},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::sync::Notify;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED,
        ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_LOGON_FAILURE,
        ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_LOGON_FAILED, ERROR_SERVICE_MARKED_FOR_DELETE,
        ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR, ERROR_SHARING_VIOLATION,
        GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE, LocalFree, NO_ERROR,
        NTSTATUS, STATUS_OBJECT_NAME_NOT_FOUND,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authentication::Identity::{
            LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
            LsaEnumerateAccountRights, LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy,
            LsaRemoveAccountRights, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
        },
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT,
        },
        CheckTokenMembership, CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetAce,
        GetTokenInformation, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
        LookupAccountNameW, LookupAccountSidW, OWNER_SECURITY_INFORMATION, PSID,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, READ_CONTROL,
    },
    System::{
        Console::{
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode,
            ReadConsoleW, SetConsoleMode,
        },
        Services::{
            ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
            CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
            QueryServiceConfigW, QueryServiceStatus, QueryServiceStatusEx,
            RegisterServiceCtrlHandlerExW, SC_HANDLE, SC_MANAGER_CONNECT,
            SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_SHUTDOWN,
            SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
            SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN,
            SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG,
            SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
            SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOP_PENDING,
            SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
            StartServiceCtrlDispatcherW, StartServiceW,
        },
        SystemInformation::{ComputerNameNetBIOS, GetComputerNameExW, GetSystemDirectoryW},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

use super::{Ace, AceKind, InstallOptions, Role, Secret, Security};
use crate::{
    ServiceAction,
    installer::{self, Handoff, Verify},
    private::{
        cli,
        diagnostics::{self, Level},
        runtime::Identity,
    },
    update::say,
};

mod queued_update;
pub mod ssh_files;

pub use queued_update::{handoff, wait_for_activation};

const _: () = assert!(super::AUTO_START == SERVICE_AUTO_START);

const ELEVATE: &str =
    "Windows lets only an elevated PowerShell (Run as administrator) manage services";
const SERVICE_LOGON_RIGHT: &str = "SeServiceLogonRight";
const EVENT_LOG: &str = "connections.jsonl";
const POLL: Duration = Duration::from_millis(200);
const START_WAIT: Duration = Duration::from_secs(60);
/// Longer than the runtime's own ordered stop, which is bounded in several steps.
const STOP_WAIT: Duration = Duration::from_secs(90);
/// How long a deleted service's entry is waited for, once it has stopped.
const REMOVAL_WAIT: Duration = Duration::from_secs(10);
/// What the service tells the service manager to expect of a pending start or stop.
const PENDING_HINT_MS: u32 = 60_000;
const INHERIT_ONLY: u8 = 0x8;

// ------------------------------------------------------------------ install

/// Everything `install` settles before it asks for a password or changes anything.
struct Prepared {
    dir: String,
    binary: String,
    shell: String,
    account: Account,
    name: String,
    command: String,
    manager: Handle,
    wide_name: Vec<u16>,
    existing: Option<Handle>,
    /// The existing service's configuration, and whether it was running.
    previous: Option<(Config, bool)>,
    /// Whether the account lacks the right to log on as a service.
    grant: bool,
}

impl Prepared {
    fn approval(&self) -> super::Approval {
        super::Approval {
            dir: self.dir.clone(),
            name: self.name.clone(),
            account: self.account.name(),
            command: self.command.clone(),
            existing: self
                .previous
                .as_ref()
                .map(|(config, running)| (config.registration(), *running)),
            grant: self.grant,
        }
    }
}

fn prepare(dir: &Path, options: &InstallOptions) -> Result<Prepared> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let dir = super::plain(&dir)?;
    let binary = env::current_exe()
        .and_then(|path| path.canonicalize())
        .context("find the running MassRelay binary")?;
    let binary = super::plain(&binary)?;
    let shell = match &options.shell {
        Some(shell) => {
            let path = shell
                .canonicalize()
                .with_context(|| format!("find the shell {}", shell.display()))?;
            ensure!(path.is_file(), "the shell {} is not a file", path.display());
            super::plain(&path)?
        }
        None => powershell()?,
    };

    // The service runs as the account running this command, which must be the one that
    // controls the profile: an elevation that switched accounts is refused here.
    let account = Account::current()?;
    ensure_trusted(&binary, Role::Program, &account)?;
    ensure_trusted(&shell, Role::Program, &account)?;
    ensure_trusted(&dir, Role::Holder, &account)?;
    check_private_profile(&Path::new(&dir).join(cli::DIR_NAME), &account)?;

    let name = super::service_name(&dir);
    let command = super::command_line(&binary, &dir, &name, &shell)?;
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    ensure!(
        options.allow_administrator || !is_administrator()?,
        "{} is an administrator, and Windows runs an administrator's service with full \
         administrator rights: a peer with shell access can request an elevated shell, unlike \
         'massrelay run' in an ordinary terminal. To accept that, run 'massrelay install \
         --allow-administrator'",
        account.name()
    );

    let wide_name = wide(&name)?;
    let existing = open(&manager, &wide_name, SERVICE_ALL_ACCESS)?;
    let previous = match &existing {
        Some(service) => {
            let config = config(service)?;
            ensure!(
                super::is_profile_service(&config.command, &dir, &name),
                "another service already uses the name {name}"
            );
            ensure!(
                service_account_sid(&config.account)? == account.sid,
                "the existing service runs under another account"
            );
            let running = state(service)?.dwCurrentState != SERVICE_STOPPED;
            Some((config, running))
        }
        None => None,
    };
    let grant = !Policy::open()?.may_log_on_as_service(&account)?;
    Ok(Prepared {
        dir,
        binary,
        shell,
        account,
        name,
        command,
        manager,
        wide_name,
        existing,
        previous,
        grant,
    })
}

/// What `install` would register and start. Changes nothing, and so leaves to `apply` the
/// account's password, which this does not ask for, and the checks that open the profile's
/// files for writing.
pub fn plan_install(dir: &Path, options: InstallOptions) -> Result<super::InstallPlan> {
    let shown = prepare(dir, &options)?.approval();
    Ok(super::InstallPlan {
        options,
        shown,
        kept: None,
    })
}

impl super::InstallPlan {
    /// Look again, and require what an install would do to be what was shown.
    fn confirmed(&self) -> Result<Prepared> {
        let prepared = prepare(Path::new(&self.shown.dir), &self.options)?;
        self.confirm(&prepared.approval())?;
        Ok(prepared)
    }

    /// For a command in a session that depends on `runtime`, which has to be this profile's
    /// service. One that is exactly what this install would make is then left running.
    pub fn carried_by(&mut self, runtime: &Identity) -> Result<()> {
        let prepared = self.confirmed()?;
        let service = match &prepared.existing {
            Some(service) => {
                let status = process_status(service)?;
                let running = status.dwCurrentState == SERVICE_RUNNING;
                Some((status.dwProcessId, running))
            }
            None => None,
        };
        let current = installer::is_this_program(runtime, Path::new(&prepared.binary));
        self.consider(runtime, service, current)
    }

    /// Register and start the service, if what an install would replace and do is still as it
    /// was shown. Returns the canonical state directory the service was installed for.
    pub fn apply(self) -> Result<PathBuf> {
        if self.keeps() {
            return self.keep();
        }
        let from_stdin = self.options.password_stdin;
        self.register_with(|account| password(account, from_stdin), None)
    }

    /// `apply` in the process a `queue` started, with what that handed over. It counts a
    /// start only once `serves` finds the runtime answering.
    pub fn finish(
        self,
        handoff: Handoff,
        serves: &dyn Fn(Option<&Path>) -> Result<()>,
    ) -> Result<PathBuf> {
        match handoff.password {
            Some(password) => self.register_with(|_| Ok(password), Some(serves)),
            None => self.keep(),
        }
    }

    /// Hand this install, as `approval` names it, to a detached process, which neither the
    /// service's restart nor this session's end reaches. A password is asked for here, and
    /// goes to that process over their pipe. Returns where it logs.
    pub fn queue(self, approval: &str) -> Result<String> {
        let prepared = self.confirmed()?;
        cli::check_enrolled(Path::new(&prepared.dir))?;
        let password = if self.keeps() {
            None
        } else {
            let password = password(&prepared.account, self.options.password_stdin)?;
            // A wrong one is reported while the person who typed it is there to hear it. An
            // account that has yet to be allowed this logon cannot try it beforehand.
            if !self.shown.grant {
                check_logon(&prepared.account, &password)?;
            }
            Some(password)
        };
        // No handle is kept while the password is waited for.
        drop(prepared);
        let prepared = self.confirmed()?;
        let command = super::install_command_line(
            &prepared.binary,
            &prepared.dir,
            self.options.shell.as_ref().map(|_| prepared.shell.as_str()),
            self.options.allow_administrator,
        )?;
        let message = super::handoff_message(approval, password.as_ref())?;
        queued_update::queue_install(
            &prepared.account,
            Path::new(&prepared.dir),
            &prepared.binary,
            &command,
            &message,
        )
    }

    /// Leave the service running, if it is still exactly what this install would make.
    fn keep(mut self) -> Result<PathBuf> {
        let runtime = self
            .kept
            .take()
            .context("the service was not found running as this install would register it")?;
        cli::check_enrolled(Path::new(&self.shown.dir))?;
        self.carried_by(&runtime)?;
        ensure!(self.keeps(), Self::CHANGED);
        say(format!("Kept {} running", self.shown.name));
        Ok(self.shown.dir.into())
    }

    /// Register the service with the password `password` gives, and restart it.
    fn register_with(
        self,
        password: impl FnOnce(&Account) -> Result<Secret>,
        serves: Verify,
    ) -> Result<PathBuf> {
        let prepared = self.confirmed()?;
        // Only now that the profile is known to be private is its store opened.
        cli::check_enrolled(Path::new(&prepared.dir))?;
        if !prepared
            .previous
            .as_ref()
            .is_some_and(|(_, running)| *running)
        {
            let _lock = cli::claim_owner(Path::new(&prepared.dir))
                .context("stop the foreground massrelay run first")?;
        }
        let password = password(&prepared.account)?;
        // No handle is kept while the password is waited for, and what is there is looked at
        // again right before the first change.
        drop(prepared);
        register(&self, self.confirmed()?, password, serves)
    }
}

fn register(
    plan: &super::InstallPlan,
    prepared: Prepared,
    password: Secret,
    serves: Verify,
) -> Result<PathBuf> {
    let Prepared {
        dir,
        binary,
        shell,
        account,
        name,
        command,
        manager,
        wide_name,
        existing,
        previous,
        ..
    } = prepared;

    let policy = Policy::open()?;
    let granted = plan.grant(!policy.may_log_on_as_service(&account)?)?;
    if granted {
        policy
            .set_service_logon(&account, true)
            .context("allow the account to log on as a service")?;
    }

    let account_name = wide(account.name())?;
    let command = wide(&command)?;
    let mut description = wide(format!(
        "Keeps the MassRelay device in {dir} reachable as {}. Managed by 'massrelay install'.",
        account.name()
    ))?;
    let mut created = None;
    let mut changed = false;
    let applied = (|| {
        // Checked before the service manager is touched, so a mistyped password cannot break
        // a service that works.
        check_logon(&account, &password)?;
        let service = match &existing {
            Some(service) => {
                changed = true;
                let logon = Some((account_name.as_slice(), &password));
                reconfigure(service, SERVICE_AUTO_START, &command, logon)?;
                service
            }
            None => &*created.insert(create(
                &manager,
                &wide_name,
                &command,
                &account_name,
                &password,
            )?),
        };
        annotate(service, &mut description)?;
        // A running service takes up its new registration by restarting.
        stop(service)?;
        start(service)?;
        if let Some(serves) = serves {
            serves(Some(Path::new(&binary))).context("the new service did not come up")?;
        }
        Ok::<_, anyhow::Error>(())
    })();
    drop(password);

    if let Err(error) = applied {
        let restored = (|| {
            let mut running_again = false;
            if let Some(service) = &created {
                let _ = stop(service);
                // SAFETY: the handle is an open service handle with delete access.
                ensure!(
                    unsafe { DeleteService(service.0) } != 0,
                    "remove the new service: {}",
                    io::Error::last_os_error()
                );
            } else if let (true, Some(service), Some((config, running))) =
                (changed, &existing, &previous)
            {
                // The account and its (now verified) password stay as stored.
                reconfigure(service, config.start, &wide(&config.command)?, None)?;
                if *running {
                    if serves.is_some() {
                        // The replacement may be running: only a restart takes up what was
                        // restored.
                        stop(service)?;
                    }
                    start(service)?;
                    running_again = true;
                }
            }
            if granted {
                policy.set_service_logon(&account, false)?;
            }
            if running_again && let Some(serves) = serves {
                serves(None).context("the restored service did not come up")?;
            }
            Ok::<_, anyhow::Error>(running_again)
        })();
        return Err(match restored {
            Ok(true) if serves.is_some() => {
                error.context("the previous service was restored and answers")
            }
            Ok(_) => error,
            Err(restore) => error.context(format!(
                "could not restore the previous service state: {restore:#}"
            )),
        });
    }

    println!(
        "Started {name} as {}; Windows starts it at boot, before sign-in",
        account.name()
    );
    if granted {
        println!("Allowed {} to log on as a service", account.name());
    }
    println!("Shell           {shell}");
    println!(
        "Event log       {}",
        Path::new(&dir).join(EVENT_LOG).display()
    );
    println!("Read service diagnostics with 'massrelay logs'.");
    Ok(dir.into())
}

pub fn control(dir: &Path, action: ServiceAction) -> Result<()> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let dir = super::plain(&dir)?;
    let name = super::service_name(&dir);
    let result = (|| {
        let manager = manager(SC_MANAGER_CONNECT)?;
        let access = SERVICE_QUERY_STATUS
            | match action {
                ServiceAction::Start => SERVICE_START,
                ServiceAction::Stop => SERVICE_STOP,
                ServiceAction::Restart => SERVICE_START | SERVICE_STOP,
            };
        let Some(service) = open(&manager, &wide(&name)?, access)? else {
            bail!("no installed service for this profile. Run massrelay install first");
        };
        match action {
            ServiceAction::Stop => stop(&service),
            ServiceAction::Restart => {
                stop(&service)?;
                start(&service)
            }
            ServiceAction::Start => {
                if state(&service)?.dwCurrentState == SERVICE_STOPPED {
                    let _lock = cli::claim_owner(Path::new(&dir))
                        .context("stop the foreground massrelay run first")?;
                }
                start(&service)
            }
        }
    })();
    action.record(&Path::new(&dir).join(EVENT_LOG), &result);
    result?;
    println!("{} {name}", action.completed());
    Ok(())
}

// ---------------------------------------------------------------- uninstall

/// This profile's service as it is registered now, checked for removal.
struct Installed {
    dir: String,
    name: String,
    manager: Handle,
    /// The registration, and the service opened to stop and delete it.
    service: Option<(super::Registration, Handle)>,
}

fn installed(dir: &Path) -> Result<Installed> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let dir = super::plain(&dir)?;
    let name = super::service_name(&dir);
    let manager = manager(SC_MANAGER_CONNECT)?;
    let access = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | super::DELETE;
    let service = match open(&manager, &wide(&name)?, access)? {
        Some(service) => {
            let config = config(&service)?;
            let account = Account::current()?;
            let status = process_status(&service)?;
            let shell_host = env::var(crate::private::HOST_ENV)
                .ok()
                .and_then(|value| value.parse().ok());
            super::check_removable(
                &super::Registered {
                    command: &config.command,
                    // An account that cannot be resolved is not shown to be this one.
                    own_account: service_account_sid(&config.account)
                        .is_ok_and(|sid| sid == account.sid),
                    process: Some(status.dwProcessId).filter(|&process| process != 0),
                },
                &dir,
                &name,
                shell_host,
                update_queued(Path::new(&dir))?,
            )?;
            Some((config.registration(), service))
        }
        None => None,
    };
    Ok(Installed {
        dir,
        name,
        manager,
        service,
    })
}

/// Whether a queued update, or its helper, holds the profile's update lock.
fn update_queued(dir: &Path) -> Result<bool> {
    match File::open(dir.join(super::UPDATE_LOCK)) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => Ok(true),
        Err(error) => Err(error).context("check for a queued update"),
    }
}

/// The service there is to delete for this profile. Makes the checks removal makes, including
/// that this process may stop and delete the service, and changes nothing.
pub fn plan_uninstall(dir: &Path) -> Result<super::UninstallPlan> {
    let Installed {
        dir, name, service, ..
    } = installed(dir)?;
    Ok(super::UninstallPlan {
        dir,
        name,
        shown: service.map(|(registration, _)| registration),
    })
}

impl super::UninstallPlan {
    /// Delete this profile's service and stop it, if it is still registered as it was shown.
    /// The profile, its keys, its logs and the account's rights are kept: nothing records
    /// whether an install granted the right to log on as a service. A plan that showed no
    /// service succeeds while there is still none.
    pub fn apply(self) -> Result<()> {
        use std::io::Write as _;

        let Installed {
            name,
            manager,
            service,
            ..
        } = installed(Path::new(&self.dir))?;
        // What is confirmed is removed through the very handle it was read from.
        let done = match self.confirm(&name, service)? {
            Some(service) => {
                super::unregister(&service)?;
                // The entry goes once every handle to it is closed.
                drop(service);
                let wide_name = wide(&name)?;
                let deadline = Instant::now() + REMOVAL_WAIT;
                loop {
                    if open(&manager, &wide_name, SERVICE_QUERY_STATUS)?.is_none() {
                        break format!("Removed {name}");
                    }
                    if Instant::now() >= deadline {
                        break format!(
                            "Stopped {name} and marked it for deletion. Windows removes it once \
                             other programs, such as the Services console, close it"
                        );
                    }
                    thread::sleep(POLL);
                }
            }
            None => self.to_string(),
        };
        // The terminal may be gone, which must not turn a finished removal into a panic.
        let _ = writeln!(io::stdout(), "{done}");
        Ok(())
    }
}

impl super::Unregister for Handle {
    fn delete(&self) -> Result<()> {
        // SAFETY: the handle is an open service handle with delete access.
        if unsafe { DeleteService(self.0) } != 0 {
            return Ok(());
        }
        match last_error() {
            ERROR_SERVICE_MARKED_FOR_DELETE => Ok(()),
            code => Err(denied(code, "delete the service")),
        }
    }

    fn stop(&self) -> Result<()> {
        stop(self)
    }
}

/// An installed service, for `massrelay update`.
pub struct Managed {
    dir: String,
    name: String,
}

pub fn managed(dir: &Path) -> Result<Managed> {
    let dir = dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let dir = super::plain(&dir)?;
    let name = super::service_name(&dir);
    let service = Managed { dir, name };
    service.open(SERVICE_QUERY_STATUS)?;
    Ok(service)
}

impl Managed {
    fn open(&self, access: u32) -> Result<Handle> {
        let manager = manager(SC_MANAGER_CONNECT)?;
        open(&manager, &wide(&self.name)?, access)?
            .context("no installed service for this profile. Run massrelay install first")
    }
}

impl crate::update::Service for Managed {
    fn label(&self) -> String {
        self.name.clone()
    }

    fn events(&self) -> PathBuf {
        Path::new(&self.dir).join(EVENT_LOG)
    }

    fn launches(&self, program: &Path) -> Result<bool> {
        let program = program
            .canonicalize()
            .with_context(|| format!("find {}", program.display()))?;
        let program = super::quote(&super::plain(&program)?)?;
        let command = config(&self.open(SERVICE_QUERY_CONFIG)?)?.command;
        Ok(super::is_profile_service(&command, &self.dir, &self.name)
            && command.starts_with(&format!("{program} ")))
    }

    fn controllable(&self) -> Result<()> {
        self.open(SERVICE_QUERY_STATUS | SERVICE_START).map(drop)
    }

    /// A path the update writes beside or runs gets the check the install gives the program:
    /// only this account and administrators may modify it or any directory above it. It must
    /// also be reached without a reparse point, so that what is checked is what is used.
    fn trusts(&self, path: &Path) -> Result<()> {
        for part in path.ancestors() {
            // A drive's root has no entry of its own to be a reparse point.
            if part.parent().is_none() {
                break;
            }
            let attributes = fs::symlink_metadata(part)
                .with_context(|| format!("find {}", part.display()))?
                .file_attributes();
            ensure!(
                attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "{} is a link or mount point; 'massrelay update' does not follow one to the \
                 installed program",
                part.display()
            );
        }
        let resolved = path
            .canonicalize()
            .with_context(|| format!("find {}", path.display()))?;
        // Include the ACLs that files created in a staging directory will inherit.
        let role = if resolved.is_dir() {
            Role::Staging
        } else {
            Role::Program
        };
        ensure_trusted(&super::plain(&resolved)?, role, &Account::current()?)
    }

    /// The service manager's own state for the service. Only `SERVICE_STOPPED` is stopped:
    /// a start or a stop that is pending, and any other state, is in between, and the program
    /// is not replaced or started while it lasts.
    fn state(&self) -> Result<crate::update::Manager> {
        use crate::update::Manager;
        let status = process_status(&self.open(SERVICE_QUERY_STATUS)?)?;
        Ok(match status.dwCurrentState {
            SERVICE_RUNNING if status.dwProcessId != 0 => Manager::Running(status.dwProcessId),
            SERVICE_STOPPED => Manager::Stopped,
            SERVICE_START_PENDING => Manager::Pending("as starting".into()),
            SERVICE_STOP_PENDING => Manager::Pending("as stopping".into()),
            other => Manager::Pending(format!("in state {other}")),
        })
    }

    fn start(&self) -> Result<()> {
        start(&self.open(SERVICE_QUERY_STATUS | SERVICE_START)?)
    }
}

fn system_directory() -> Result<PathBuf> {
    let mut buffer = [0u16; 260];
    // SAFETY: the buffer is writable for the length given.
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    ensure!(
        len > 0 && len < buffer.len(),
        "cannot find the Windows system directory"
    );
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
}

/// Windows PowerShell, by its full path in the system directory.
fn powershell() -> Result<String> {
    let path = system_directory()?.join(r"WindowsPowerShell\v1.0\powershell.exe");
    ensure!(
        path.is_file(),
        "Windows PowerShell is not at {}; choose a shell with --shell",
        path.display()
    );
    super::plain(&path)
}

pub fn is_default_shell(shell: &Path) -> bool {
    shell
        .canonicalize()
        .ok()
        .and_then(|path| super::plain(&path).ok())
        .zip(powershell().ok())
        .is_some_and(|(shell, default)| shell.eq_ignore_ascii_case(&default))
}

// ------------------------------------------------------------------ account

/// The account running this command.
struct Account {
    /// A `TOKEN_USER`, whose SID pointer points into this same buffer.
    token_user: Vec<u64>,
    sid: String,
    user: String,
    domain: String,
}

impl Account {
    fn current() -> Result<Self> {
        let mut token = null_mut();
        // SAFETY: the pseudo-handle of this process is always valid; `token` receives a
        // handle that is closed below.
        ensure!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
            "read this account's identity: {}",
            io::Error::last_os_error()
        );
        let mut needed = 0u32;
        // SAFETY: a size query; nothing is written but `needed`.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
        // u64 elements keep the structure aligned.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        // SAFETY: the buffer is writable for at least `needed` bytes.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        let error = last_error();
        // SAFETY: `token` was opened above and is not used again.
        unsafe { CloseHandle(token) };
        if read == 0 {
            return Err(os_error(error).context("read this account's identity"));
        }
        let mut account = Self {
            token_user: buffer,
            sid: String::new(),
            user: String::new(),
            domain: String::new(),
        };
        account.sid = sid_text(account.psid())?;
        (account.user, account.domain) = lookup(account.psid())?;
        Ok(account)
    }

    fn psid(&self) -> PSID {
        // SAFETY: the buffer holds the TOKEN_USER that GetTokenInformation wrote, and lives
        // as long as `self`.
        unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn name(&self) -> String {
        format!("{}\\{}", self.domain, self.user)
    }
}

/// The account and domain names of a SID.
fn lookup(sid: PSID) -> Result<(String, String)> {
    let (mut name, mut domain) = ([0u16; 257], [0u16; 257]);
    let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
    let mut kind = 0;
    // SAFETY: `sid` is a valid SID and both buffers are writable for the lengths given.
    let found = unsafe {
        LookupAccountSidW(
            null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    ensure!(
        found != 0,
        "find the account's name: {}",
        io::Error::last_os_error()
    );
    Ok((
        String::from_utf16_lossy(&name[..name_len as usize]),
        String::from_utf16_lossy(&domain[..domain_len as usize]),
    ))
}

fn service_account_sid(name: &str) -> Result<String> {
    let lookup_name = if let Some(user) = name.strip_prefix(".\\") {
        // SCM stores local users with a dot qualifier. LookupAccountNameW expects
        // the actual computer name as the qualifier for a local SID lookup.
        let mut computer = [0u16; 256];
        let mut len = computer.len() as u32;
        // SAFETY: `computer` and `len` are writable for the lengths given.
        ensure!(
            unsafe { GetComputerNameExW(ComputerNameNetBIOS, computer.as_mut_ptr(), &mut len) }
                != 0,
            "read the local computer name: {}",
            io::Error::last_os_error()
        );
        format!("{}\\{user}", String::from_utf16(&computer[..len as usize])?)
    } else {
        name.to_owned()
    };
    let wide_name = wide(&lookup_name)?;
    let mut sid = [0u32; 17];
    let mut sid_len = size_of_val(&sid) as u32;
    let mut domain = [0u16; 257];
    let mut domain_len = domain.len() as u32;
    let mut kind = 0;
    // SAFETY: both output buffers are writable and `name` is NUL-terminated.
    let found = unsafe {
        LookupAccountNameW(
            null(),
            wide_name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    ensure!(
        found != 0,
        "resolve the existing service account {name}: {}",
        io::Error::last_os_error()
    );
    sid_text(sid.as_mut_ptr().cast())
}

fn sid_text(sid: PSID) -> Result<String> {
    let mut out = null_mut();
    // SAFETY: `sid` is a valid SID; `out` receives a string freed below.
    ensure!(
        unsafe { ConvertSidToStringSidW(sid, &mut out) } != 0,
        "read a security identifier: {}",
        io::Error::last_os_error()
    );
    // SAFETY: `out` is the NUL-terminated string just allocated for us.
    let sid = unsafe { text(out) };
    // SAFETY: `out` was allocated by ConvertSidToStringSidW and is not used again.
    unsafe { LocalFree(out.cast()) };
    Ok(sid)
}

/// A SID with its account name, for a message.
fn describe(sid: &str) -> String {
    if sid.is_empty() {
        return "An access entry of an unrecognized kind".into();
    }
    let named = (|| {
        let wide = wide(sid).ok()?;
        let mut psid = null_mut();
        // SAFETY: `wide` is NUL-terminated; `psid` receives a SID freed below.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut psid) } == 0 {
            return None;
        }
        let found = lookup(psid).ok();
        // SAFETY: `psid` was allocated by ConvertStringSidToSidW and is not used again.
        unsafe { LocalFree(psid) };
        found
    })();
    match named {
        Some((user, domain)) if !domain.is_empty() => format!("{domain}\\{user} ({sid})"),
        Some((user, _)) => format!("{user} ({sid})"),
        None => sid.to_owned(),
    }
}

/// Whether this process holds the machine's administrator rights.
fn is_administrator() -> Result<bool> {
    // SECURITY_MAX_SID_SIZE is 68 bytes; u32 elements keep the SID aligned.
    let mut sid = [0u32; 17];
    let mut size = size_of_val(&sid) as u32;
    // SAFETY: the buffer is writable for `size` bytes.
    ensure!(
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        } != 0,
        "name the Administrators group: {}",
        io::Error::last_os_error()
    );
    let mut member = 0;
    // SAFETY: a null token checks this thread's own; `sid` is the SID built above.
    ensure!(
        unsafe { CheckTokenMembership(null_mut(), sid.as_mut_ptr().cast(), &mut member) } != 0,
        "check for administrator rights: {}",
        io::Error::last_os_error()
    );
    Ok(member != 0)
}

// -------------------------------------------------------------- permissions

/// Refuse `path` unless only the account and the machine's administrators control it and
/// every directory above it.
fn ensure_trusted(path: &str, leaf: Role, account: &Account) -> Result<()> {
    for (depth, part) in Path::new(path).ancestors().enumerate() {
        let role = match (depth, leaf) {
            (0, role) => role,
            (1, Role::Program) => Role::Holder,
            _ => Role::Ancestor,
        };
        check(part, role, account)?;
    }
    Ok(())
}

fn check(path: &Path, role: Role, account: &Account) -> Result<()> {
    if let Some(sid) = super::untrusted(&security(path)?, role, &account.sid) {
        bail!(
            "{} has unsafe access to {}. Keep the binary and profile in a private directory \
             controlled by {} and administrators",
            describe(sid),
            path.display(),
            account.name()
        );
    }
    Ok(())
}

fn check_private_profile(path: &Path, account: &Account) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "the private profile contains a reparse point at {}",
        path.display()
    );
    check(path, Role::Private, account)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            check_private_profile(&entry?.path(), account)?;
        }
    }
    Ok(())
}

struct PrivateFile(SECURITY_ATTRIBUTES);

impl PrivateFile {
    fn new(account: &Account) -> Result<Self> {
        Self::inheriting(account, "")
    }

    /// Owned by the account, whose ordinary token keeps access to what an elevated one
    /// creates, and open only to it, SYSTEM and administrators. `flags` say what a
    /// directory's entries pass on.
    fn inheriting(account: &Account, flags: &str) -> Result<Self> {
        let sid = &account.sid;
        let sddl = wide(format!(
            "O:{sid}D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)(A;{flags};FA;;;{sid})"
        ))?;
        let mut descriptor = null_mut();
        // SAFETY: `sddl` is NUL-terminated and the output is writable.
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } != 0,
            "prepare private file permissions: {}",
            io::Error::last_os_error()
        );
        Ok(Self(SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        }))
    }

    fn open(&self, path: &Path, access: u32, disposition: u32) -> io::Result<File> {
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        self.open_sharing(path, access, share, disposition)
    }

    /// `open`, letting others have only the access in `share` while the file stays open.
    fn open_sharing(
        &self,
        path: &Path,
        access: u32,
        share: u32,
        disposition: u32,
    ) -> io::Result<File> {
        let name: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: the path is NUL-terminated and the security descriptor is live.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                share,
                &self.0,
                disposition,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this is a new owned file handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

impl Drop for PrivateFile {
    fn drop(&mut self) {
        // SAFETY: Windows allocated this descriptor and all opens have returned.
        unsafe { LocalFree(self.0.lpSecurityDescriptor) };
    }
}

/// Validate the directory whose children inherit the permissions for ephemeral SSH files.
pub fn ssh_private_dir(path: &Path) -> Result<()> {
    let path = std::path::absolute(path)?;
    for part in path.ancestors().filter(|part| part.parent().is_some()) {
        let metadata = fs::symlink_metadata(part)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "the MassRelay SSH directory must have a path without reparse points"
        );
    }
    ensure_trusted(&super::plain(&path)?, Role::Private, &Account::current()?)
}

/// Create the control marker with its own ACL before writing the control key.
pub fn private_marker(dir: &Path) -> Result<tempfile::NamedTempFile> {
    let permissions = PrivateFile::new(&Account::current()?)?;
    tempfile::Builder::new()
        .make_in(dir, |path| {
            permissions.open(path, GENERIC_READ | GENERIC_WRITE, CREATE_NEW)
        })
        .context("create a private control marker")
}

pub fn private_audit(path: &Path) -> Result<File> {
    let account = Account::current()?;
    // Windows applies the descriptor only when creating a new file.
    let file = PrivateFile::new(&account)?.open(
        path,
        FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        OPEN_ALWAYS,
    )?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "the audit log must be a regular file"
    );
    let permissions = handle_security(path, &file)?;
    ensure!(
        super::untrusted(&permissions, Role::Private, &account.sid).is_none(),
        "the audit log has unsafe permissions; restrict access before restarting MassRelay"
    );
    Ok(file)
}

/// The permissions of an open file.
fn handle_security(path: &Path, file: &File) -> Result<Security> {
    read_security(path, |owner, dacl, descriptor| {
        // SAFETY: the handle is live and the outputs are writable.
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                owner,
                null_mut(),
                dacl,
                null_mut(),
                descriptor,
            )
        }
    })
}

fn security(path: &Path) -> Result<Security> {
    let name = wide(path)?;
    read_security(path, |owner, dacl, descriptor| {
        // SAFETY: `name` is NUL-terminated and the outputs are writable.
        unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                owner,
                null_mut(),
                dacl,
                null_mut(),
                descriptor,
            )
        }
    })
}

fn read_security(
    path: &Path,
    get: impl FnOnce(&mut PSID, &mut *mut ACL, &mut *mut c_void) -> u32,
) -> Result<Security> {
    let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut::<ACL>(), null_mut());
    let code = get(&mut owner, &mut dacl, &mut descriptor);
    if code != 0 {
        return Err(os_error(code).context(format!("read the permissions of {}", path.display())));
    }
    let result = (|| {
        let owner = sid_text(owner)?;
        if dacl.is_null() {
            return Ok(Security { owner, dacl: None });
        }
        let mut aces = Vec::new();
        // SAFETY: a non-null `dacl` points at the descriptor's access list.
        for index in 0..unsafe { (*dacl).AceCount } {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: `index` is below the list's entry count.
            ensure!(
                unsafe { GetAce(dacl, index.into(), &mut ace) } != 0,
                "read an access entry of {}",
                path.display()
            );
            // SAFETY: every entry starts with this header.
            let header = unsafe { *ace.cast::<ACE_HEADER>() };
            // Plain and conditional entries, which share one layout.
            let kind = match header.AceType {
                0 | 9 => AceKind::Allow,
                1 | 10 => AceKind::Deny,
                _ => AceKind::Other,
            };
            let (mask, sid) = if kind == AceKind::Other {
                (0, String::new())
            } else {
                let entry = ace.cast::<ACCESS_ALLOWED_ACE>();
                // SAFETY: entries of these kinds hold a mask and then the SID, which starts
                // at `SidStart`.
                unsafe {
                    let sid = (&raw mut (*entry).SidStart).cast::<c_void>();
                    ((*entry).Mask, sid_text(sid)?)
                }
            };
            aces.push(Ace {
                kind,
                inherit_only: header.AceFlags & INHERIT_ONLY != 0,
                mask,
                sid,
            });
        }
        Ok(Security {
            owner,
            dacl: Some(aces),
        })
    })();
    // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW; nothing points into it
    // any more.
    unsafe { LocalFree(descriptor) };
    result
}

// ----------------------------------------------------------------- password

/// The account's password, NUL-terminated, for the service manager to store. It is never
/// written to a file by MassRelay.
fn password(account: &Account, from_stdin: bool) -> Result<Secret> {
    let mut secret = if from_stdin {
        stdin_line()?
    } else {
        eprintln!(
            "Windows runs the service as {} and needs that account's password. It goes to the \
             Windows service manager and is not saved by MassRelay.",
            account.name()
        );
        console_line(&format!("Password for {}: ", account.name()))?
    };
    // Every buffer has room for these edits, so no copy is left behind by a reallocation.
    while matches!(secret.0.last(), Some(0x0A | 0x0D)) {
        secret.0.pop();
    }
    if secret.0.first() == Some(&0xFEFF) {
        secret.0.remove(0);
    }
    ensure!(
        !secret.0.is_empty(),
        "Windows cannot run a service as an account without a password"
    );
    ensure!(!secret.0.contains(&0), "the password contains a NUL");
    secret.0.push(0);
    Ok(secret)
}

/// This process's standard input without a buffer. The standard library's own handle keeps
/// what it reads ahead, which must never be a password.
fn standard_input() -> Result<File> {
    let handle = io::stdin()
        .as_handle()
        .try_clone_to_owned()
        .context("use standard input")?;
    Ok(File::from(handle))
}

fn stdin_line() -> Result<Secret> {
    const LIMIT: usize = 1024;
    let input = standard_input()?;
    let mut mode = 0;
    // A console is read as one: its bytes are not UTF-8, and it would echo them.
    // SAFETY: the handle is open and `mode` is writable.
    if unsafe { GetConsoleMode(input.as_raw_handle(), &mut mode) } != 0 {
        return console_line("");
    }
    let bytes =
        super::read_secret_line(input, LIMIT).context("read the password from standard input")?;
    let text = std::str::from_utf8(&bytes.0)
        .map_err(|_| anyhow!("the password on standard input is not UTF-8"))?;
    // Room for the NUL as well, so that adding it leaves no copy behind.
    let mut units = Vec::with_capacity(bytes.0.len() + 1);
    units.extend(text.encode_utf16());
    Ok(Secret(units))
}

/// Read one line from the console with echo off.
fn console_line(prompt: &str) -> Result<Secret> {
    const LIMIT: usize = 512;
    let console = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .context("there is no console to ask for the password; pass --password-stdin")?;
    let handle = console.as_raw_handle();
    let mut mode = 0;
    // SAFETY: `handle` is the open console input handle.
    ensure!(
        unsafe { GetConsoleMode(handle, &mut mode) } != 0,
        "read the console mode: {}",
        io::Error::last_os_error()
    );
    eprint!("{prompt}");
    let quiet = (mode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & !ENABLE_ECHO_INPUT;
    let mut secret: Secret = Secret(vec![0; LIMIT + 1]);
    let mut read = 0u32;
    // SAFETY: `handle` stays open; the buffer is writable for LIMIT UTF-16 units. The
    // console's mode is restored whatever the read returns.
    let (done, error) = unsafe {
        SetConsoleMode(handle, quiet);
        let done = ReadConsoleW(
            handle,
            secret.0.as_mut_ptr().cast(),
            LIMIT as u32,
            &mut read,
            null(),
        );
        let error = GetLastError();
        SetConsoleMode(handle, mode);
        (done, error)
    };
    eprintln!();
    if done == 0 {
        return Err(os_error(error).context("read the password"));
    }
    secret.0.truncate(read as usize);
    Ok(secret)
}

/// Log on once the way the service manager will, so a wrong password or a refused logon is
/// reported here and not as a service that will not start.
fn check_logon(account: &Account, password: &Secret) -> Result<()> {
    let (user, domain) = (wide(&account.user)?, wide(&account.domain)?);
    let mut token = null_mut();
    // SAFETY: the three strings are NUL-terminated; `token` receives a handle closed below.
    let logged_on = unsafe {
        LogonUserW(
            user.as_ptr(),
            domain.as_ptr(),
            password.0.as_ptr(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    if logged_on == 0 {
        return Err(match last_error() {
            ERROR_LOGON_FAILURE => anyhow!(
                "Windows did not accept that password for {}. Enter the account's password, \
                 not a PIN",
                account.name()
            ),
            code => os_error(code).context(format!(
                "log on as {} the way a service does",
                account.name()
            )),
        });
    }
    // SAFETY: `token` was returned by LogonUserW and is not used again.
    unsafe { CloseHandle(token) };
    Ok(())
}

// ------------------------------------------------------- "log on as a service"

/// The local security policy, which holds each account's logon rights.
struct Policy(LSA_HANDLE);

impl Drop for Policy {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by LsaOpenPolicy and is not used again.
        unsafe { LsaClose(self.0) };
    }
}

impl Policy {
    fn open() -> Result<Self> {
        let attributes = LSA_OBJECT_ATTRIBUTES {
            Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let mut handle = 0;
        let access = (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32;
        // SAFETY: a null system name is this machine; `attributes` is initialized as the
        // API requires; `handle` receives a handle closed on drop.
        lsa(unsafe { LsaOpenPolicy(null(), &attributes, access, &mut handle) })
            .context("open the local security policy")?;
        Ok(Self(handle))
    }

    /// Whether the account itself (not a group it is in) holds the right already.
    fn may_log_on_as_service(&self, account: &Account) -> Result<bool> {
        let (mut rights, mut count) = (null_mut::<LSA_UNICODE_STRING>(), 0u32);
        // SAFETY: the SID is valid; `rights` receives an array freed below.
        let status =
            unsafe { LsaEnumerateAccountRights(self.0, account.psid(), &mut rights, &mut count) };
        // An account with no rights of its own has no entry.
        if status == STATUS_OBJECT_NAME_NOT_FOUND {
            return Ok(false);
        }
        lsa(status).context("read the account's logon rights")?;
        let held = (0..count as usize).any(|index| {
            // SAFETY: the array holds `count` strings, each `Length` bytes of UTF-16.
            let name = unsafe {
                let right = &*rights.add(index);
                std::slice::from_raw_parts(right.Buffer, usize::from(right.Length) / 2)
            };
            String::from_utf16_lossy(name) == SERVICE_LOGON_RIGHT
        });
        // SAFETY: `rights` was allocated by LsaEnumerateAccountRights and is not used again.
        unsafe { LsaFreeMemory(rights.cast()) };
        Ok(held)
    }

    fn set_service_logon(&self, account: &Account, allow: bool) -> Result<()> {
        let mut name: Vec<u16> = SERVICE_LOGON_RIGHT.encode_utf16().collect();
        let bytes = (name.len() * 2) as u16;
        let right = LSA_UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: name.as_mut_ptr(),
        };
        // SAFETY: the SID is valid and `right` describes `name`, which outlives the call.
        lsa(unsafe {
            if allow {
                LsaAddAccountRights(self.0, account.psid(), &right, 1)
            } else {
                LsaRemoveAccountRights(self.0, account.psid(), false, &right, 1)
            }
        })
    }
}

fn lsa(status: NTSTATUS) -> Result<()> {
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: a pure conversion.
    Err(os_error(unsafe { LsaNtStatusToWinError(status) }))
}

// ---------------------------------------------------------- service manager

/// A service manager or service handle.
struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is open and not used again.
        unsafe { CloseServiceHandle(self.0) };
    }
}

struct Config {
    command: String,
    start: u32,
    account: String,
}

impl Config {
    fn registration(&self) -> super::Registration {
        super::Registration {
            command: self.command.clone(),
            account: self.account.clone(),
            start: self.start,
        }
    }
}

fn denied(code: u32, action: &str) -> anyhow::Error {
    if code == ERROR_ACCESS_DENIED {
        anyhow!(ELEVATE)
    } else {
        os_error(code).context(action.to_owned())
    }
}

fn manager(access: u32) -> Result<Handle> {
    // SAFETY: null names select this machine's active service database.
    let handle = unsafe { OpenSCManagerW(null(), null(), access) };
    if handle.is_null() {
        return Err(denied(
            last_error(),
            "connect to the Windows service manager",
        ));
    }
    Ok(Handle(handle))
}

fn open(manager: &Handle, name: &[u16], access: u32) -> Result<Option<Handle>> {
    // SAFETY: the manager handle is open and `name` is NUL-terminated.
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if !handle.is_null() {
        return Ok(Some(Handle(handle)));
    }
    match last_error() {
        ERROR_SERVICE_DOES_NOT_EXIST => Ok(None),
        code => Err(denied(code, "open the service")),
    }
}

fn create(
    manager: &Handle,
    name: &[u16],
    command: &[u16],
    account: &[u16],
    password: &Secret,
) -> Result<Handle> {
    // SAFETY: every string is NUL-terminated and outlives the call. The service manager
    // copies the password into its own protected store.
    let handle = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            name.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            null(),
            null_mut(),
            null(),
            account.as_ptr(),
            password.0.as_ptr(),
        )
    };
    if handle.is_null() {
        return Err(denied(last_error(), "register the service"));
    }
    Ok(Handle(handle))
}

/// Change a service's start type and command line, and its logon when one is given.
fn reconfigure(
    service: &Handle,
    start: u32,
    command: &[u16],
    logon: Option<(&[u16], &Secret)>,
) -> Result<()> {
    let (account, password) = logon.map_or((null(), null()), |(account, password)| {
        (account.as_ptr(), password.0.as_ptr())
    });
    // SAFETY: the handle is open; the strings are NUL-terminated or null (unchanged).
    let changed = unsafe {
        ChangeServiceConfigW(
            service.0,
            SERVICE_WIN32_OWN_PROCESS,
            start,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            null(),
            null_mut(),
            null(),
            account,
            password,
            null(),
        )
    };
    ensure!(
        changed != 0,
        "update the service: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

/// Describe the service in the Windows service manager.
fn annotate(service: &Handle, description: &mut [u16]) -> Result<()> {
    let text = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_mut_ptr(),
    };
    // SAFETY: the handle and description are live for the call.
    ensure!(
        unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_DESCRIPTION,
                (&raw const text).cast(),
            )
        } != 0,
        "set the service description: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

fn config(service: &Handle) -> Result<Config> {
    // The service manager never returns more than 8 KiB. u64 elements keep it aligned.
    let mut buffer = vec![0u64; 1024];
    let mut needed = 0;
    // SAFETY: the handle is open and the buffer is writable for the size given.
    ensure!(
        unsafe {
            QueryServiceConfigW(
                service.0,
                buffer.as_mut_ptr().cast(),
                size_of_val(buffer.as_slice()) as u32,
                &mut needed,
            )
        } != 0,
        "read the service configuration: {}",
        io::Error::last_os_error()
    );
    // SAFETY: the call filled the buffer with this structure, whose strings point into it.
    unsafe {
        let config = &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        Ok(Config {
            command: text(config.lpBinaryPathName),
            start: config.dwStartType,
            account: text(config.lpServiceStartName),
        })
    }
}

fn state(service: &Handle) -> Result<SERVICE_STATUS> {
    let mut status = SERVICE_STATUS::default();
    // SAFETY: the handle is open and `status` is writable.
    ensure!(
        unsafe { QueryServiceStatus(service.0, &mut status) } != 0,
        "read the service status: {}",
        io::Error::last_os_error()
    );
    Ok(status)
}

/// The service's status, with the ID of its process.
fn process_status(service: &Handle) -> Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    // SAFETY: the handle is open and the buffer is this structure, writable for its size.
    ensure!(
        unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } != 0,
        "read the service status: {}",
        io::Error::last_os_error()
    );
    Ok(status)
}

/// Start the service and wait until its runtime is up. A running service is left as it is.
fn start(service: &Handle) -> Result<()> {
    // SAFETY: the handle is open; no arguments are passed.
    if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
        match last_error() {
            ERROR_SERVICE_ALREADY_RUNNING => {}
            ERROR_SERVICE_LOGON_FAILED => bail!(
                "Windows could not log the service on. If the account's password changed, \
                 run 'massrelay install' again to store the new one"
            ),
            code => return Err(denied(code, "start the service")),
        }
    }
    let deadline = Instant::now() + START_WAIT;
    loop {
        let status = state(service)?;
        match status.dwCurrentState {
            SERVICE_RUNNING => return Ok(()),
            SERVICE_STOPPED => {
                let code = match status.dwWin32ExitCode {
                    ERROR_SERVICE_SPECIFIC_ERROR => status.dwServiceSpecificExitCode,
                    code => code,
                };
                bail!("the service stopped while starting (exit code {code}); see 'massrelay logs'")
            }
            _ => ensure!(
                Instant::now() < deadline,
                "the service did not finish starting in {} seconds",
                START_WAIT.as_secs()
            ),
        }
        thread::sleep(POLL);
    }
}

/// Stop the service and wait for its runtime to release the profile.
fn stop(service: &Handle) -> Result<()> {
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        let mut status = state(service)?;
        match status.dwCurrentState {
            SERVICE_STOPPED => return Ok(()),
            SERVICE_RUNNING => {
                // SAFETY: the handle is open and `status` is writable.
                let asked = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
                match last_error() {
                    _ if asked != 0 => {}
                    // It stopped, or began stopping, in the meantime.
                    ERROR_SERVICE_NOT_ACTIVE | ERROR_SERVICE_CANNOT_ACCEPT_CTRL => {}
                    code => return Err(denied(code, "stop the service")),
                }
            }
            // Still starting or already stopping.
            _ => {}
        }
        ensure!(
            Instant::now() < deadline,
            "the service did not stop in {} seconds",
            STOP_WAIT.as_secs()
        );
        thread::sleep(POLL);
    }
}

// ------------------------------------------------ the service control protocol

type Body = Box<dyn FnOnce() -> u32 + Send>;

static NAME: OnceLock<Vec<u16>> = OnceLock::new();
static BODY: Mutex<Option<Body>> = Mutex::new(None);
/// The handle this service reports its status on; null until the service manager started it.
static STATUS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CHECKPOINT: AtomicU32 = AtomicU32::new(0);
static STOPPING: AtomicBool = AtomicBool::new(false);
static STOP: Notify = Notify::const_new();

/// Run `body` under the service manager and return once the service stops.
pub fn serve(
    name: &str,
    dir: PathBuf,
    body: impl FnOnce() -> Result<i32> + Send + 'static,
) -> Result<i32> {
    let body: Body = Box::new(move || {
        diagnostics::start(&dir);
        let trusted = Account::current()
            .and_then(|account| check_private_profile(&dir.join(cli::DIR_NAME), &account));
        if trusted.is_err() {
            diagnostics::quiet(
                Level::Error,
                "the service cannot use an insecure or inaccessible profile",
            );
            return 1;
        }
        match body() {
            Ok(code) => code as u32,
            Err(_) => {
                diagnostics::quiet(Level::Error, "the Windows service failed");
                1
            }
        }
    });
    *BODY
        .lock()
        .map_err(|_| anyhow!("service state is poisoned"))? = Some(body);
    let name = NAME.get_or_init(|| name.encode_utf16().chain([0]).collect());
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table ends with a null entry, and it and the name outlive the call, which
    // returns when the service has stopped.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(match last_error() {
            ERROR_FAILED_SERVICE_CONTROLLER_CONNECT => {
                anyhow!("this command is run by the Windows service manager; use 'massrelay start'")
            }
            code => os_error(code).context("connect to the Windows service manager"),
        });
    }
    Ok(0)
}

/// Whether this process is running as a service under the service manager.
pub fn serving() -> bool {
    !STATUS.load(Ordering::SeqCst).is_null()
}

/// Report the service as running, then wait for the service manager's stop request.
pub async fn until_stopped() {
    if !STOPPING.load(Ordering::SeqCst) {
        report(SERVICE_RUNNING, 0);
    }
    STOP.notified().await;
}

fn report(state: u32, exit: u32) {
    let handle = STATUS.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let pending = matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING);
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if exit == 0 {
            NO_ERROR
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: exit,
        dwCheckPoint: if pending {
            CHECKPOINT.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            0
        },
        dwWaitHint: if pending { PENDING_HINT_MS } else { 0 },
    };
    // SAFETY: `handle` is the status handle the service manager gave this service.
    unsafe { SetServiceStatus(handle, &status) };
}

/// Called by the service manager on its own thread once it has started this service.
unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
    let Some(name) = NAME.get() else { return };
    // SAFETY: `name` is NUL-terminated and static; the handler is a plain function.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), null()) };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0);
    let body = BODY.lock().ok().and_then(|mut body| body.take());
    // A panic must not unwind into the service manager's frame.
    let exit = body.map_or(1, |body| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(1)
    });
    // Windows may end the process as soon as this is reported.
    report(SERVICE_STOPPED, exit);
}

/// Called by the service manager for each control request.
unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOPPING.store(true, Ordering::SeqCst);
            report(SERVICE_STOP_PENDING, 0);
            // Holds a permit if the runtime is not waiting yet.
            STOP.notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

// ------------------------------------------------------------------ helpers

/// NUL-terminated UTF-16 for a Windows call.
fn wide(text: impl AsRef<OsStr>) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = text.as_ref().encode_wide().collect();
    ensure!(!wide.contains(&0), "text for Windows contains a NUL");
    wide.push(0);
    Ok(wide)
}

/// The text of a NUL-terminated UTF-16 string from Windows.
///
/// # Safety
/// `text` is null or points at a NUL-terminated UTF-16 string.
unsafe fn text(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so every unit read is inside it.
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    }
}

fn last_error() -> u32 {
    // SAFETY: reads this thread's last error code.
    unsafe { GetLastError() }
}

fn os_error(code: u32) -> anyhow::Error {
    io::Error::from_raw_os_error(code as i32).into()
}

#[cfg(test)]
mod service_fixture {
    use super::*;
    use crate::private::pty::Pty;
    use serde::Deserialize;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;

    /// Typed into PowerShell, which inspects its own token and exits with what it found: 32,
    /// plus 1 if it is an administrator, 2 at medium integrity, 4 at high integrity and 8 if
    /// it holds the privilege to debug other accounts' processes.
    const REPORT: &str = concat!(
        "$i=[Security.Principal.WindowsIdentity]::GetCurrent();",
        "$a=([Security.Principal.WindowsPrincipal]$i)",
        ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);",
        "$w=whoami /groups /priv /fo csv;",
        "exit (32+[int]$a+2*[int][bool]($w -match 'S-1-16-8192')",
        "+4*[int][bool]($w -match 'S-1-16-12288')",
        "+8*[int][bool]($w -match 'SeDebugPrivilege'))\r",
    );
    const REGULAR: i32 = 32 + 2;
    const ELEVATED: i32 = 32 + 1 + 4 + 8;

    #[derive(Deserialize)]
    struct Probe {
        name: String,
        state: PathBuf,
        result: PathBuf,
    }

    #[test]
    #[ignore = "started by Windows SCM with a disposable service configuration"]
    fn scm_powershell_probe() -> Result<()> {
        let config = env::current_exe()?.with_extension("json");
        let probe: Probe = serde_json::from_reader(File::open(config)?)?;
        as_service(
            &probe.name,
            probe.state,
            probe.result,
            exercise_as_administrator,
        )
    }

    /// Run `work` as the service `name` under the service manager, and write what came of it
    /// to `result`.
    fn as_service<F: Future<Output = Result<()>> + 'static>(
        name: &str,
        state: PathBuf,
        result: PathBuf,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> Result<()> {
        serve(name, state, move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let (_, recorded) = tokio::join!(until_stopped(), async {
                    let came = match work().await {
                        Ok(()) => "ok".into(),
                        Err(error) => format!("{error:#}"),
                    };
                    fs::write(result, came)
                });
                recorded?;
                Ok(0)
            })
        })?;
        Ok(())
    }

    #[derive(Deserialize)]
    struct Hosted {
        name: String,
        state: PathBuf,
        result: PathBuf,
        /// The installed program, and the process of the service installed with it.
        program: PathBuf,
        service_process: u32,
        /// The explicitly configured shell, which the second install replaces with the default.
        other_shell: PathBuf,
        /// A pipe that gives the account's password to this account alone.
        password_pipe: String,
    }

    #[test]
    #[ignore = "started by Windows SCM beside a disposable installed service"]
    fn scm_hosted_install_probe() -> Result<()> {
        let config = env::current_exe()?.with_extension("json");
        let hosted: Hosted = serde_json::from_reader(File::open(config)?)?;
        let (name, state, result) = (
            hosted.name.clone(),
            hosted.state.clone(),
            hosted.result.clone(),
        );
        as_service(&name, state, result, move || async move {
            install_from_a_shell(&hosted).await
        })
    }

    /// Install from a shell made as the service makes a peer's, marked as the installed
    /// service's own: first with nothing to change, then registering the default shell, which
    /// restarts it. That shell is ended as soon as the install says it is queued.
    async fn install_from_a_shell(hosted: &Hosted) -> Result<()> {
        // This probe, like the installed service, is started by the service manager. Looked
        // at independently of what it tests: no job object holds it, so none can excuse a
        // handoff that fails.
        let mut member = 0;
        // SAFETY: the pseudo-handle of this process is always valid; a null job asks about
        // any job.
        ensure!(
            unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut member) } != 0,
            "check this process's job membership: {}",
            io::Error::last_os_error()
        );
        ensure!(member == 0, "the probe service runs in a job object");

        let mut password = String::new();
        let mut pipe = File::open(format!(r"\\.\pipe\{}", hosted.password_pipe))
            .context("open the password pipe")?;
        io::Read::read_to_string(&mut pipe, &mut password)?;
        ensure!(!password.is_empty(), "no password was given");

        let shell = PathBuf::from(powershell()?);
        let mut pty = Pty::spawn_with_privilege(250, 50, Some(&shell), Arc::new(()), true)
            .context("start a shell")?;
        let teardown = pty.teardown();
        let mut output = Vec::new();
        {
            let mut reader = pty.reader();
            let mut writer = pty.writer();
            let install = format!(
                "& '{}' --state-dir '{}' install --allow-administrator",
                hosted.program.display(),
                hosted.state.display()
            );
            // The last line prints text that the typed command does not contain.
            let unchanged = format!(
                "$env:{}='{}'\r{install} --shell '{}' --yes; \"EXIT$LASTEXITCODE.\"\r",
                crate::private::HOST_ENV,
                hosted.service_process,
                hosted.other_shell.display()
            );
            writer.write_all(unchanged.as_bytes()).await?;
            shown(&mut reader, &mut output, "EXIT0.", true).await?;
            ensure!(
                screen(&output).contains("KeptMassRelay-"),
                "the unchanged service was not kept"
            );

            let replacing = format!("{install}\r");
            writer.write_all(replacing.as_bytes()).await?;
            shown(&mut reader, &mut output, "Proceed?[y/N]", true).await?;
            writer.write_all(b"y\r").await?;
            shown(&mut reader, &mut output, "Passwordfor", true).await?;
            writer.write_all(format!("{password}\r").as_bytes()).await?;
            shown(&mut reader, &mut output, "Queued.", false).await?;
            ensure!(
                !screen(&output).contains(&password),
                "the shell showed the password"
            );
        }
        // The session ends here, with whatever still runs on its console.
        drop(pty);
        timeout(Duration::from_secs(30), teardown.wait()).await?;
        Ok(())
    }

    /// Read the shell's output until its screen shows `wanted`, written without spaces.
    async fn shown(
        reader: &mut (impl AsyncReadExt + Unpin),
        output: &mut Vec<u8>,
        wanted: &str,
        show_transcript: bool,
    ) -> Result<()> {
        let read = timeout(Duration::from_secs(120), async {
            let mut chunk = [0u8; 4096];
            while !screen(output).contains(wanted) {
                let read = reader.read(&mut chunk).await?;
                ensure!(read > 0, "the shell's output ended");
                output.extend_from_slice(&chunk[..read]);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        read.map_err(|_| anyhow!("it was not shown in 120 seconds"))
            .flatten()
            .with_context(|| {
                if !show_transcript {
                    return format!("waiting for {wanted:?} after entering the password");
                }
                let end = &output[output.len().saturating_sub(4096)..];
                format!(
                    "waiting for {wanted:?}; the output ends {:?}",
                    String::from_utf8_lossy(end)
                )
            })
    }

    /// The text of terminal output without control sequences and spaces, both of which the
    /// console host places as it redraws.
    fn screen(output: &[u8]) -> String {
        let text = String::from_utf8_lossy(output);
        let mut characters = text.chars();
        let mut screen = String::new();
        while let Some(character) = characters.next() {
            match character {
                '\x1b' => match characters.next() {
                    // A control sequence ends with a letter or a sign like one.
                    Some('[') => {
                        characters.find(|end| ('@'..='~').contains(end));
                    }
                    // A system command ends with a bell or a string terminator.
                    Some(']') => {
                        if characters.find(|end| ['\x07', '\x1b'].contains(end)) == Some('\x1b') {
                            characters.next();
                        }
                    }
                    _ => {}
                },
                other if other.is_whitespace() || other.is_control() => {}
                other => screen.push(other),
            }
        }
        screen
    }

    /// The same shells from whatever runs the tests: an elevated terminal has an
    /// administrator's token like the service does, and an ordinary one must be refused an
    /// elevated shell.
    #[tokio::test]
    #[ignore = "starts native ConPTY shells and Windows PowerShell"]
    async fn conpty_shells_run_at_the_requested_privilege() -> Result<()> {
        exercise_privileges().await
    }

    /// The service case: an administrator's service logon in the services session, which
    /// has no limited token to fall back on.
    async fn exercise_as_administrator() -> Result<()> {
        ensure!(
            is_administrator()?,
            "the probe service does not run with administrator rights"
        );
        exercise_privileges().await
    }

    /// A regular shell holds no administrator rights whatever this process holds. An
    /// elevated shell holds this process's administrator rights, or is refused when there
    /// are none. Starting either leaves this process's own rights as they were.
    async fn exercise_privileges() -> Result<()> {
        let administrator = is_administrator()?;
        let shell = PathBuf::from(powershell()?);
        let start =
            |elevated| Pty::spawn_with_privilege(80, 24, Some(&shell), Arc::new(()), elevated);
        let regular = start(false).context("start a regular shell")?;
        let elevated = match start(true) {
            Ok(pty) if administrator => Some(pty),
            Ok(_) => bail!("a process without administrator rights started an elevated shell"),
            Err(error) if administrator => return Err(error).context("start an elevated shell"),
            Err(error) => {
                ensure!(
                    error.kind() == io::ErrorKind::PermissionDenied,
                    "an elevated shell was not refused as a permission error: {error}"
                );
                None
            }
        };
        // Both at once, as two sessions of one service would be.
        let (regular, elevated) = tokio::join!(report(regular, "regular", REGULAR), async {
            match elevated {
                Some(pty) => report(pty, "elevated", ELEVATED).await,
                None => Ok(()),
            }
        });
        regular?;
        elevated?;
        ensure!(
            is_administrator()? == administrator,
            "starting shells changed this process's own administrator rights"
        );
        Ok(())
    }

    /// Have the shell report on its own token, and check the report.
    async fn report(mut pty: Pty, kind: &str, expected: i32) -> Result<()> {
        let mut exit = pty.take_exit();
        let teardown = pty.teardown();
        let mut output = Vec::new();
        let code = {
            let mut reader = pty.reader();
            timeout(Duration::from_secs(30), async {
                pty.writer().write_all(REPORT.as_bytes()).await?;
                // Keep reading, so the console host never waits on a full output pipe.
                let mut chunk = [0u8; 4096];
                loop {
                    tokio::select! {
                        code = &mut exit => return Ok::<_, anyhow::Error>(code??),
                        read = reader.read(&mut chunk) => match read {
                            Ok(read) if read > 0 => output.extend_from_slice(&chunk[..read]),
                            // The output ended; the exit code follows.
                            _ => return Ok((&mut exit).await??),
                        },
                    }
                }
            })
            .await
        };
        drop(pty);
        timeout(Duration::from_secs(10), teardown.wait()).await?;
        let seen = String::from_utf8_lossy(&output[output.len().saturating_sub(2048)..]);
        let code = code
            .map_err(|_| anyhow!("the {kind} shell did not report in 30 seconds"))
            .flatten()
            .with_context(|| format!("the {kind} shell failed; its output ended {seen:?}"))?;
        ensure!(
            code == expected,
            "the {kind} shell reported {} instead of {}; its output ended {seen:?}",
            reading(code),
            reading(expected)
        );
        Ok(())
    }

    /// A report's exit code in words.
    fn reading(code: i32) -> String {
        match code - 32 {
            flags @ 0..16 => format!(
                "exit code {code} (administrator: {}, medium integrity: {}, high integrity: {}, \
                 debug privilege: {})",
                flags & 1 != 0,
                flags & 2 != 0,
                flags & 4 != 0,
                flags & 8 != 0
            ),
            _ => format!("exit code {code}, which is not a report"),
        }
    }
}
