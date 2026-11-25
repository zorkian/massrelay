//! Which peers may use which services on this device.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::wire::{GrantRule, GrantView, Service};

/// Persistent grants are saved with the device state. Exposures last only while the command that
/// asked for them runs, so they are never saved. A peer holds at most one of the two per service.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Grants {
    persistent: BTreeMap<EndpointId, BTreeMap<Service, Grant>>,
    #[serde(skip)]
    exposed: BTreeMap<(EndpointId, Service), Exposure>,
    #[serde(skip)]
    issued: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct Grant {
    /// The pairing generation the owner granted it in. It confers nothing in any other.
    generation: u64,
    /// Tells a grant apart from an earlier one for the same peer and service, so sessions that
    /// began under a removed grant cannot continue under its replacement.
    #[serde(skip)]
    instance: u64,
}

#[derive(Clone)]
struct Exposure {
    grant: Grant,
    target: Option<String>,
}

/// What an authorized session may reach.
pub struct Access {
    pub instance: GrantInstance,
    /// An address chosen by this device's owner. `None` means loopback on the service's port.
    pub target: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantInstance {
    Peer(u64),
    Default(u64),
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceDefaults {
    settings: BTreeMap<Service, DefaultSetting>,
    #[serde(skip)]
    issued: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct DefaultSetting {
    enabled: bool,
    excluded: BTreeSet<EndpointId>,
    #[serde(skip)]
    instance: u64,
}

impl ServiceDefaults {
    pub fn set(&mut self, service: Service, enabled: bool) -> bool {
        if self
            .settings
            .get(&service)
            .is_some_and(|setting| setting.enabled)
            == enabled
        {
            return false;
        }
        let setting = self.settings.entry(service).or_default();
        self.issued += 1;
        setting.instance = self.issued;
        setting.enabled = enabled;
        true
    }

    pub fn exclude(&mut self, peer: EndpointId, service: Service) -> bool {
        self.settings
            .get_mut(&service)
            .is_some_and(|setting| setting.enabled && setting.excluded.insert(peer))
    }

    pub fn clear_exclusion(&mut self, peer: EndpointId, service: Service) -> bool {
        self.settings
            .get_mut(&service)
            .is_some_and(|setting| setting.excluded.remove(&peer))
    }

    pub fn access(&self, peer: EndpointId, service: Service) -> Option<Access> {
        let setting = self.settings.get(&service)?;
        (setting.enabled && !setting.excluded.contains(&peer)).then_some(Access {
            instance: GrantInstance::Default(setting.instance),
            target: None,
        })
    }

    pub fn list(&self, name: impl Fn(EndpointId) -> Option<String>) -> Vec<GrantView> {
        let mut rules = Vec::new();
        for (&service, setting) in &self.settings {
            if setting.enabled {
                rules.push(GrantView {
                    service,
                    peer: Some("all paired peers".into()),
                    id: None,
                    temporary: false,
                    target: None,
                    rule: Some(GrantRule::Default),
                });
            }
            rules.extend(setting.excluded.iter().map(|&id| GrantView {
                service,
                peer: name(id),
                id: Some(id),
                temporary: false,
                target: None,
                rule: Some(GrantRule::Excluded),
            }));
        }
        rules
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RemovedGrant {
    Persistent,
    Exposure,
}

impl Grants {
    pub fn access(&self, peer: EndpointId, service: Service, generation: u64) -> Option<Access> {
        let (grant, target) = match self.exposed.get(&(peer, service)) {
            Some(exposure) => (exposure.grant, exposure.target.clone()),
            None => (*self.persistent.get(&peer)?.get(&service)?, None),
        };
        (grant.generation == generation).then_some(Access {
            instance: GrantInstance::Peer(grant.instance),
            target,
        })
    }

    fn issue(&mut self, generation: u64) -> Grant {
        self.issued += 1;
        Grant {
            generation,
            instance: self.issued,
        }
    }

    /// Add a persistent grant. Returns false if it already exists.
    pub fn enable(
        &mut self,
        peer: EndpointId,
        name: &str,
        service: Service,
        generation: u64,
    ) -> Result<bool> {
        if self.exposed.contains_key(&(peer, service)) {
            bail!(
                "{service} is currently exposed to {name}; \
                 stop that command or run massrelay disable {service} {name} first"
            );
        }
        let existing = self.persistent.get(&peer).and_then(|all| all.get(&service));
        if existing.is_some_and(|grant| grant.generation == generation) {
            return Ok(false);
        }
        let grant = self.issue(generation);
        self.persistent
            .entry(peer)
            .or_default()
            .insert(service, grant);
        Ok(true)
    }

    /// Register a temporary grant and return its instance. It never replaces an existing grant.
    pub fn expose(
        &mut self,
        peer: EndpointId,
        name: &str,
        service: Service,
        generation: u64,
        target: Option<String>,
    ) -> Result<u64> {
        if self.exposed.contains_key(&(peer, service)) {
            bail!(
                "{service} is already exposed to {name}; \
                 stop that command or run massrelay disable {service} {name} first"
            );
        }
        if self
            .persistent
            .get(&peer)
            .is_some_and(|services| services.contains_key(&service))
        {
            bail!(
                "{service} is already enabled for {name}; \
                 run massrelay disable {service} {name} first"
            );
        }
        let grant = self.issue(generation);
        self.exposed
            .insert((peer, service), Exposure { grant, target });
        Ok(grant.instance)
    }

    pub fn is_exposed(&self, peer: EndpointId, service: Service, instance: u64) -> bool {
        self.exposed
            .get(&(peer, service))
            .is_some_and(|exposure| exposure.grant.instance == instance)
    }

    /// End one exposure, leaving any grant that has since replaced it.
    pub fn withdraw(&mut self, peer: EndpointId, service: Service, instance: u64) -> bool {
        if self.is_exposed(peer, service, instance) {
            return self.exposed.remove(&(peer, service)).is_some();
        }
        false
    }

    pub fn disable(&mut self, peer: EndpointId, service: Service) -> Option<RemovedGrant> {
        if self.exposed.remove(&(peer, service)).is_some() {
            return Some(RemovedGrant::Exposure);
        }
        let services = self.persistent.get_mut(&peer)?;
        let removed = services.remove(&service).is_some();
        if services.is_empty() {
            self.persistent.remove(&peer);
        }
        removed.then_some(RemovedGrant::Persistent)
    }

    /// Drop every grant for which the peer and pairing generation are no longer current.
    pub fn retain(
        &mut self,
        current: impl Fn(EndpointId, u64) -> bool,
    ) -> Vec<(EndpointId, Service, RemovedGrant)> {
        let mut removed = Vec::new();
        self.persistent.retain(|peer, services| {
            services.retain(|service, grant| {
                let keep = current(*peer, grant.generation);
                if !keep {
                    removed.push((*peer, *service, RemovedGrant::Persistent));
                }
                keep
            });
            !services.is_empty()
        });
        self.exposed.retain(|(peer, service), exposure| {
            let keep = current(*peer, exposure.grant.generation);
            if !keep {
                removed.push((*peer, *service, RemovedGrant::Exposure));
            }
            keep
        });
        removed
    }

    /// Every grant, ordered by service, then peer name, then endpoint ID.
    pub fn list(&self, name: impl Fn(EndpointId) -> Option<String>) -> Vec<GrantView> {
        let persistent = self.persistent.iter().flat_map(|(&id, services)| {
            services
                .keys()
                .map(move |&service| (id, service, false, None))
        });
        let exposed = self
            .exposed
            .iter()
            .map(|(&(id, service), exposure)| (id, service, true, exposure.target.clone()));
        let mut list: Vec<_> = persistent
            .chain(exposed)
            .map(|(id, service, temporary, target)| GrantView {
                service,
                peer: name(id),
                id: Some(id),
                temporary,
                target,
                rule: None,
            })
            .collect();
        list.sort_by_cached_key(|grant| {
            let name = grant.peer.as_deref().map(str::to_ascii_lowercase);
            (grant.service, name, grant.id)
        });
        list
    }
}
