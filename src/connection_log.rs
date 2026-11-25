use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
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

use crate::wire::Service;

pub struct ConnectionLog {
    file: Option<Mutex<File>>,
    counter: AtomicU64,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Serialize)]
struct Event<'a> {
    timestamp: String,
    pid: u32,
    session: u64,
    direction: Direction,
    event: &'static str,
    peer_id: Option<String>,
    peer_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<Service>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
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
                let mut opts = OpenOptions::new();
                opts.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                opts.open(path)
                    .with_context(|| format!("open connection log {}", path.display()))
                    .map(Mutex::new)
            })
            .transpose()?;
        Ok(Self {
            file,
            counter: AtomicU64::new(1),
        })
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

    fn write(&self, event: Event<'_>) {
        let result = (|| -> Result<()> {
            let mut line = serde_json::to_vec(&event)?;
            line.push(b'\n');
            match &self.file {
                Some(file) => file
                    .lock()
                    .map_err(|_| anyhow::anyhow!("connection log lock poisoned"))?
                    .write_all(&line)?,
                None => io::stderr().lock().write_all(&line)?,
            }
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("massrelay: could not write connection event: {error:#}");
        }
    }
}

impl Session<'_> {
    pub fn set_peer(&mut self, id: EndpointId, name: String) {
        self.peer_id = Some(id);
        self.peer_name = Some(name);
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
        self.log.write(Event {
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            pid: std::process::id(),
            session: self.id,
            direction: self.direction,
            event,
            peer_id: self.peer_id.map(|id| id.to_string()),
            peer_name: self.peer_name.as_deref(),
            service: self.service,
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
