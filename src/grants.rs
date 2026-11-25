//! Which peers may use which services on this device.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::wire::{GrantView, Service};

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
    pub instance: u64,
    /// An address chosen by this device's owner. `None` means loopback on the service's port.
    pub target: Option<String>,
}

impl Grants {
    pub fn access(&self, peer: EndpointId, service: Service, generation: u64) -> Option<Access> {
        let (grant, target) = match self.exposed.get(&(peer, service)) {
            Some(exposure) => (exposure.grant, exposure.target.clone()),
            None => (*self.persistent.get(&peer)?.get(&service)?, None),
        };
        (grant.generation == generation).then_some(Access {
            instance: grant.instance,
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
    pub fn withdraw(&mut self, peer: EndpointId, service: Service, instance: u64) {
        if self.is_exposed(peer, service, instance) {
            self.exposed.remove(&(peer, service));
        }
    }

    /// Remove either kind of grant. Returns whether saved state changed.
    pub fn disable(&mut self, peer: EndpointId, service: Service) -> bool {
        self.exposed.remove(&(peer, service));
        let Some(services) = self.persistent.get_mut(&peer) else {
            return false;
        };
        let removed = services.remove(&service).is_some();
        if services.is_empty() {
            self.persistent.remove(&peer);
        }
        removed
    }

    /// Drop every grant for which the peer and pairing generation are no longer current.
    pub fn retain(&mut self, current: impl Fn(EndpointId, u64) -> bool) {
        self.persistent.retain(|peer, services| {
            services.retain(|_, grant| current(*peer, grant.generation));
            !services.is_empty()
        });
        self.exposed
            .retain(|(peer, _), exposure| current(*peer, exposure.grant.generation));
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
                id,
                temporary,
                target,
            })
            .collect();
        list.sort_by_cached_key(|grant| {
            let name = grant.peer.as_deref().map(str::to_ascii_lowercase);
            (grant.service, name, grant.id)
        });
        list
    }
}
