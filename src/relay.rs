use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, RelayUrl, SecretKey};
use iroh_relay::server::{Access, AccessControl, ClientRequest, RelayConfig, Server, ServerConfig};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};

use crate::{
    bind_endpoint, storage,
    wire::{self, Decision, Member, PairView, Peer, Reply, Request, Roster, ServerAddr, Ticket},
};

const STATE_FILE: &str = "relay.json";
const INVITE_SECONDS: u64 = 600;

#[derive(Clone, Serialize, Deserialize)]
struct RelayState {
    key: [u8; 32],
    server: ServerAddr,
    create_secret: String,
    networks: BTreeMap<String, Network>,
    invites: BTreeMap<String, Invite>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Invite {
    network: String,
    issuer: EndpointId,
    expires: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Network {
    members: BTreeMap<EndpointId, Member>,
    revoked: Vec<EndpointId>,
    pairs: Vec<Pair>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Pair {
    left: EndpointId,
    right: EndpointId,
    generation: u64,
    left_vote: Option<Decision>,
    right_vote: Option<Decision>,
}

impl Pair {
    fn contains(&self, a: EndpointId, b: EndpointId) -> bool {
        (self.left == a && self.right == b) || (self.left == b && self.right == a)
    }

    fn view(&self, who: EndpointId) -> PairView {
        let (ours, theirs) = if who == self.left {
            (self.left_vote, self.right_vote)
        } else {
            (self.right_vote, self.left_vote)
        };
        PairView {
            generation: self.generation,
            ours,
            theirs,
        }
    }

    fn vote(&mut self, who: EndpointId, decision: Decision) -> Result<()> {
        if decision == Decision::Decline {
            self.generation = self
                .generation
                .checked_add(1)
                .context("pair generation exhausted")?;
            self.left_vote = None;
            self.right_vote = None;
        }
        if who == self.left {
            self.left_vote = Some(decision);
        } else {
            self.right_vote = Some(decision);
        }
        Ok(())
    }
}

impl Network {
    fn roster(&self, network: &str, who: EndpointId) -> Roster {
        let peers = self
            .members
            .values()
            .filter(|member| member.id != who)
            .map(|member| {
                let pair = self
                    .pairs
                    .iter()
                    .find(|pair| pair.contains(who, member.id))
                    .map_or_else(PairView::default, |pair| pair.view(who));
                Peer {
                    member: member.clone(),
                    pair,
                }
            })
            .collect();
        Roster {
            network: network.into(),
            peers,
        }
    }

    fn pair(
        &mut self,
        who: EndpointId,
        peer: EndpointId,
        decision: Decision,
        generation: u64,
    ) -> Result<()> {
        ensure!(
            who != peer && self.members.contains_key(&peer),
            "unknown peer"
        );
        let index = self.pairs.iter().position(|pair| pair.contains(who, peer));
        let current = index.map_or(0, |index| self.pairs[index].generation);
        ensure!(
            generation == current,
            "pairing changed, check peers and try again"
        );
        if let Some(index) = index {
            return self.pairs[index].vote(who, decision);
        }
        let mut pair = Pair {
            left: who,
            right: peer,
            generation: 0,
            left_vote: None,
            right_vote: None,
        };
        pair.vote(who, decision)?;
        self.pairs.push(pair);
        Ok(())
    }
}

impl RelayState {
    fn apply(&mut self, who: EndpointId, request: Request) -> Result<Reply> {
        if self
            .networks
            .values()
            .any(|network| network.revoked.contains(&who))
        {
            return Ok(Reply::Revoked);
        }
        let current = self
            .networks
            .iter()
            .find(|(_, network)| network.members.contains_key(&who))
            .map(|(id, _)| id.clone());

        if let Request::Enroll {
            secret,
            name,
            create,
        } = request
        {
            if let Some(id) = current {
                return Ok(Reply::Roster(self.networks[&id].roster(&id, who)));
            }
            return self.enroll(who, &secret, name, create);
        }

        let id = current.context("device is not enrolled")?;
        let network = self.networks.get_mut(&id).context("network vanished")?;
        match request {
            Request::Sync { addr } => {
                ensure!(
                    addr.id == who && addr.addrs.len() <= 32,
                    "invalid advertised address"
                );
                let member = network.members.get_mut(&who).context("member vanished")?;
                // Keep only directly observed address candidates. All peers already have the relay URL.
                member.addr = Some(
                    iroh::EndpointAddr::new(who)
                        .with_addrs(addr.ip_addrs().copied().map(iroh::TransportAddr::Ip)),
                );
                member.last_seen = Some(storage::now());
            }
            Request::Invite => {
                let now = storage::now();
                self.invites.retain(|_, invite| invite.expires > now);
                ensure!(self.invites.len() < 512, "too many open invites");
                let secret = wire::token()?;
                self.invites.insert(
                    secret.clone(),
                    Invite {
                        network: id,
                        issuer: who,
                        expires: now + INVITE_SECONDS,
                    },
                );
                return Ok(Reply::Invite(secret));
            }
            Request::Pair {
                peer,
                decision,
                generation,
            } => network.pair(who, peer, decision, generation)?,
            Request::Revoke { peer } => {
                ensure!(peer != who, "choose another device to revoke");
                ensure!(network.members.remove(&peer).is_some(), "unknown peer");
                network.revoked.push(peer);
                network
                    .pairs
                    .retain(|pair| pair.left != peer && pair.right != peer);
                self.invites.retain(|_, invite| invite.issuer != peer);
            }
            Request::Enroll { .. } => unreachable!(),
        }
        Ok(Reply::Roster(network.roster(&id, who)))
    }

    fn enroll(
        &mut self,
        who: EndpointId,
        secret: &str,
        name: String,
        create: bool,
    ) -> Result<Reply> {
        ensure!(
            !name.is_empty()
                && name.len() <= 32
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "name must contain 1–32 ASCII letters, digits, hyphens, or underscores"
        );

        let id = if create {
            ensure!(
                bool::from(self.create_secret.as_bytes().ct_eq(secret.as_bytes())),
                "invalid create ticket"
            );
            ensure!(self.networks.len() < 64, "relay network limit reached");
            let id = wire::token()?;
            // A create ticket is also a one-use credential.
            self.create_secret = wire::token()?;
            self.networks.insert(id.clone(), Network::default());
            id
        } else {
            let invite = self
                .invites
                .get(secret)
                .context("invalid or already used invite")?;
            ensure!(invite.expires > storage::now(), "invite expired");
            invite.network.clone()
        };

        let network = self.networks.get_mut(&id).context("network vanished")?;
        ensure!(network.members.len() < 128, "network is full");
        ensure!(
            !network
                .members
                .values()
                .any(|m| m.name.eq_ignore_ascii_case(&name)),
            "name already in use"
        );
        network.members.insert(
            who,
            Member {
                id: who,
                name,
                addr: None,
                last_seen: None,
            },
        );
        self.invites.remove(secret);
        Ok(Reply::Roster(network.roster(&id, who)))
    }
}

pub fn init(dir: &Path, udp: SocketAddr, relay: RelayUrl) -> Result<()> {
    let _lock = storage::lock(dir)?;
    ensure!(!dir.join(STATE_FILE).exists(), "relay already initialized");
    ensure!(
        !udp.ip().is_unspecified() && udp.port() != 0,
        "specify the relay's reachable UDP address"
    );
    let key = wire::random()?;
    let state = RelayState {
        key,
        server: ServerAddr {
            id: SecretKey::from_bytes(&key).public(),
            udp,
            relay,
        },
        create_secret: wire::token()?,
        networks: BTreeMap::new(),
        invites: BTreeMap::new(),
    };
    storage::save(dir, STATE_FILE, &state)?;
    print_ticket(state)
}

pub fn create_ticket(dir: &Path) -> Result<()> {
    // Atomic state replacement allows this local read while the relay runs.
    print_ticket(storage::load(dir, STATE_FILE)?)
}

fn print_ticket(state: RelayState) -> Result<()> {
    println!(
        "{}",
        Ticket {
            server: state.server,
            secret: state.create_secret
        }
        .encode()?
    );
    Ok(())
}

struct RelayAccess(Arc<Mutex<RelayState>>);

impl std::fmt::Debug for RelayAccess {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("MassRelay membership access")
    }
}

impl AccessControl for RelayAccess {
    async fn on_connect(&self, client: &ClientRequest) -> Access {
        let state = self.0.lock().await;
        let peer = client.endpoint_id();
        if peer == state.server.id
            || state
                .networks
                .values()
                .any(|network| network.members.contains_key(&peer))
        {
            Access::Allow
        } else {
            Access::Deny { reason: None }
        }
    }
}

pub async fn run(dir: PathBuf, udp_bind: SocketAddr, relay_bind: SocketAddr) -> Result<()> {
    let _lock = storage::lock(&dir)?;
    let config: RelayState = storage::load(&dir, STATE_FILE)?;
    let endpoint_key = SecretKey::from_bytes(&config.key);
    let relay_url = config.server.relay.clone();
    let state = Arc::new(Mutex::new(config));

    let mut relay = RelayConfig::new(relay_bind);
    relay.access = Arc::new(RelayAccess(state.clone()));
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let mut server = Server::spawn(config).await?;
    let relay_service = server
        .relay_service()
        .context("relay service unavailable")?
        .clone();
    let endpoint = bind_endpoint(
        endpoint_key,
        udp_bind,
        Some(relay_url),
        wire::CONTROL,
        false,
    )
    .await?;
    eprintln!("MassRelay listening on {udp_bind} UDP and {relay_bind} TCP");
    let limit = Arc::new(Semaphore::new(64));
    let shutdown = crate::shutdown();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            ended = server.join() => {
                ended??;
                bail!("relay service stopped");
            }
            signal = &mut shutdown => break signal?,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { bail!("control endpoint closed") };
                // Own the whole request for the bounded lifetime of its permit.
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let (dir, state) = (dir.clone(), state.clone());
                let relay_service = relay_service.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(wire::RPC_TIMEOUT, async {
                        let connection = incoming.await?;
                        let who = connection.remote_id();
                        let (mut tx, mut rx) = connection.accept_bi().await?;
                        let request: Request = wire::recv(&mut rx).await?;
                        let revoked_peer = match &request {
                            Request::Revoke { peer } => Some(*peer),
                            _ => None,
                        };
                        let reply = dispatch(&state, &dir, who, request).await;
                        if let (Some(peer), Reply::Roster(_)) = (revoked_peer, &reply) {
                            relay_service.clients().disconnect(peer, None);
                        }
                        wire::send(&mut tx, reply).await?;
                        tx.finish()?;
                        // Keep the connection alive until the client has read the reply.
                        let _ = tx.stopped().await;
                        Ok::<_, anyhow::Error>(())
                    }).await;
                });
            }
        }
    }
    endpoint.close().await;
    server.shutdown().await?;
    Ok(())
}

async fn dispatch(
    state: &Mutex<RelayState>,
    dir: &Path,
    who: EndpointId,
    request: Request,
) -> Reply {
    let mut state = state.lock().await;
    if matches!(request, Request::Sync { .. }) {
        return state
            .apply(who, request)
            .unwrap_or_else(|err| Reply::Error(err.to_string()));
    }

    let mut next = state.clone();
    match next.apply(who, request) {
        Ok(reply) => match storage::save(dir, STATE_FILE, &next) {
            Ok(()) => {
                *state = next;
                reply
            }
            Err(err) => Reply::Error(format!("relay state could not be saved: {err}")),
        },
        Err(err) => Reply::Error(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn network(ids: &[EndpointId]) -> Network {
        Network {
            members: ids
                .iter()
                .map(|&id| {
                    (
                        id,
                        Member {
                            id,
                            name: id.to_string(),
                            addr: None,
                            last_seen: None,
                        },
                    )
                })
                .collect(),
            ..Network::default()
        }
    }

    #[test]
    fn a_decline_invalidates_in_flight_approvals() {
        let (a, b) = (id(1), id(2));
        let mut network = network(&[a, b]);
        network.pair(a, b, Decision::Approve, 0).unwrap();
        network.pair(b, a, Decision::Decline, 0).unwrap();
        assert!(network.pair(a, b, Decision::Approve, 0).is_err());

        network.pair(b, a, Decision::Approve, 1).unwrap();
        let pair = network.roster("example", b).peers[0].pair;
        assert_eq!(pair.ours, Some(Decision::Approve));
        assert_eq!(pair.theirs, None);
        network.pair(a, b, Decision::Approve, 1).unwrap();
        assert_eq!(
            network.roster("example", b).peers[0].pair.theirs,
            Some(Decision::Approve)
        );
    }

    #[test]
    fn only_members_can_revoke_and_revocation_invalidates_unused_invites() {
        let (a, b, outsider) = (id(1), id(2), id(3));
        let mut relay = RelayState {
            key: [4; 32],
            server: ServerAddr {
                id: id(4),
                udp: "127.0.0.1:4433".parse().unwrap(),
                relay: "http://127.0.0.1:3340".parse().unwrap(),
            },
            create_secret: String::new(),
            networks: BTreeMap::from([("example".into(), network(&[a, b]))]),
            invites: BTreeMap::new(),
        };
        assert!(relay.apply(outsider, Request::Revoke { peer: b }).is_err());
        let Reply::Invite(secret) = relay.apply(b, Request::Invite).unwrap() else {
            panic!("expected an invite");
        };
        relay.apply(a, Request::Revoke { peer: b }).unwrap();
        assert!(matches!(
            relay.apply(b, Request::Invite).unwrap(),
            Reply::Revoked
        ));
        assert!(
            relay
                .apply(
                    outsider,
                    Request::Enroll {
                        secret,
                        name: "outsider".into(),
                        create: false,
                    }
                )
                .is_err()
        );
    }
}
