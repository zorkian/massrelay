use std::{
    fs::File,
    io::Write,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use iroh::EndpointId;
use serde::Serialize;

use crate::wire::{Member, Service};

pub struct ConnectionLog {
    file: Option<Mutex<File>>,
    counter: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Serialize)]
struct Event<'a> {
    timestamp: String,
    pid: u32,
    event: &'static str,
    peer_id: Option<String>,
    peer_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<Service>,
}

#[derive(Serialize)]
struct SessionEvent<'a> {
    #[serde(flatten)]
    details: Event<'a>,
    session: u64,
    direction: Direction,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

/// Audit fields are selected at the call site. Never serialize a request, reply or raw error.
#[derive(Default, Serialize)]
pub struct Audit {
    pub operation: &'static str,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<EndpointId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<EndpointId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

#[derive(Serialize)]
struct AuditEvent<'a> {
    #[serde(flatten)]
    details: Event<'a>,
    #[serde(flatten)]
    audit: Audit,
}

pub struct Session<'a> {
    log: &'a ConnectionLog,
    id: u64,
    direction: Direction,
    peer_id: Option<EndpointId>,
    peer_name: Option<String>,
    service: Option<Service>,
    connected: bool,
    ended: bool,
}

impl ConnectionLog {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let file = path
            .map(|path| {
                #[cfg(windows)]
                let file = crate::windows_service::private_audit(path);
                #[cfg(not(windows))]
                let file = (|| {
                    let mut opts = std::fs::OpenOptions::new();
                    opts.create(true).append(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        opts.mode(0o600);
                    }
                    Ok::<_, anyhow::Error>(opts.open(path)?)
                })();
                file.with_context(|| format!("open event log {}", path.display()))
                    .map(Mutex::new)
            })
            .transpose()?;
        Ok(Self {
            file,
            counter: AtomicU64::new(1),
        })
    }

    /// A log that records nothing, for callers that run without one.
    pub fn disabled() -> Self {
        Self {
            file: None,
            counter: AtomicU64::new(1),
        }
    }

    pub fn session(
        &self,
        direction: Direction,
        peer_id: Option<EndpointId>,
        peer_name: Option<String>,
    ) -> Session<'_> {
        Session {
            log: self,
            id: self.counter.fetch_add(1, Ordering::Relaxed),
            direction,
            peer_id,
            peer_name,
            service: None,
            connected: false,
            ended: false,
        }
    }

    pub fn state(&self, event: &'static str, member: Option<&Member>, service: Option<Service>) {
        self.write(Event::new(
            event,
            member.map(|member| member.id),
            member.map(|member| member.name.as_str()),
            service,
        ));
    }

    /// A state event about a peer known by endpoint ID and, optionally, a local name.
    pub fn peer(
        &self,
        event: &'static str,
        peer_id: Option<EndpointId>,
        peer_name: Option<&str>,
        service: Option<Service>,
    ) {
        self.write(Event::new(event, peer_id, peer_name, service));
    }

    pub fn audit(&self, event: &'static str, audit: Audit, service: Option<Service>) {
        self.write(AuditEvent {
            details: Event::new(event, None, None, service),
            audit,
        });
    }

    fn write(&self, event: impl Serialize) {
        let Some(file) = &self.file else {
            return;
        };
        let mut line = match serde_json::to_vec(&event) {
            Ok(line) => line,
            Err(error) => {
                eprintln!("massrelay: could not serialize event: {error:#}");
                return;
            }
        };
        line.push(b'\n');
        let result = file
            .lock()
            .map_err(|_| anyhow::anyhow!("event log lock poisoned"))
            .and_then(|mut file| file.write_all(&line).map_err(Into::into));
        if let Err(error) = result {
            eprintln!("massrelay: could not write event log: {error:#}");
        }
    }
}

impl<'a> Event<'a> {
    fn new(
        event: &'static str,
        peer_id: Option<EndpointId>,
        peer_name: Option<&'a str>,
        service: Option<Service>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            pid: std::process::id(),
            event,
            peer_id: peer_id.map(|id| id.to_string()),
            peer_name,
            service,
        }
    }
}

impl Session<'_> {
    pub(crate) fn service_details(&self) -> Option<(u64, Direction, Service)> {
        Some((self.id, self.direction, self.service?))
    }

    pub fn identify(&mut self, id: EndpointId, name: Option<String>) {
        self.peer_id = Some(id);
        self.peer_name = name;
    }

    pub fn set_service(&mut self, service: Service) {
        self.service = Some(service);
    }

    pub fn connected(&mut self) {
        self.connected = true;
        self.record("connected", None, None);
    }

    pub fn end(&mut self, reason: &'static str, exit_code: Option<i32>) {
        self.ended = true;
        let event = if self.connected {
            "disconnected"
        } else {
            "connection_failed"
        };
        self.record(event, Some(reason), exit_code);
    }

    fn record(&self, event: &'static str, reason: Option<&'static str>, exit_code: Option<i32>) {
        self.log.write(SessionEvent {
            details: Event::new(event, self.peer_id, self.peer_name.as_deref(), self.service),
            session: self.id,
            direction: self.direction,
            reason,
            exit_code,
        });
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if !self.ended {
            self.end("interrupted", None);
        }
    }
}
