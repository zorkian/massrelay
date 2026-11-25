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
use tokio::sync::Mutex;

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
    /// Whether any device may create a network. State saved before this field stays ticket-only.
    #[serde(default)]
    shared: bool,
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
    #[serde(default)]
    first_invite: Option<FirstInvite>,
}

/// The latest invite handed to a founder by open creation, kept so a retry can receive it again.
#[derive(Clone, Serialize, Deserialize)]
struct FirstInvite {
    founder: EndpointId,
    secret: String,
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
    fn add(&mut self, id: EndpointId, name: String) -> Result<()> {
        ensure!(
            !self
                .members
                .values()
                .any(|m| m.name.eq_ignore_ascii_case(&name)),
            wire::NAME_IN_USE
        );
        self.members.insert(
            id,
            Member {
                id,
                name,
                addr: None,
                last_seen: None,
            },
        );
        Ok(())
    }

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
    fn new(udp: SocketAddr, relay: RelayUrl, shared: bool) -> Result<Self> {
        ensure!(
            !udp.ip().is_unspecified() && udp.port() != 0,
            "specify the relay's reachable UDP address"
        );
        let key = wire::random()?;
        Ok(Self {
            key,
            server: ServerAddr {
                id: SecretKey::from_bytes(&key).public(),
                udp,
                relay,
            },
            create_secret: wire::token()?,
            networks: BTreeMap::new(),
            invites: BTreeMap::new(),
            shared,
        })
    }

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
        if let Request::Create { name } = request {
            ensure!(
                self.shared,
                "this relay requires an operator creation ticket"
            );
            return self.create(who, current, name);
        }

        let id = current.context("device is not enrolled")?;
        let network = self.networks.get_mut(&id).context("network vanished")?;
        match request {
            Request::Sync { addr } => {
                ensure!(
                    addr.id == who,
                    "advertised address does not match device identity"
                );
                let member = network.members.get_mut(&who).context("member vanished")?;
                // Keep only directly observed address candidates. All peers already have the relay URL.
                member.addr = Some(
                    iroh::EndpointAddr::new(who)
                        .with_addrs(addr.ip_addrs().copied().map(iroh::TransportAddr::Ip)),
                );
                member.last_seen = Some(storage::now());
            }
            Request::Invite => return Ok(Reply::Invite(self.issue_invite(id, who)?)),
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
            Request::Enroll { .. } | Request::Create { .. } => unreachable!(),
        }
        Ok(Reply::Roster(network.roster(&id, who)))
    }

    fn issue_invite(&mut self, network: String, issuer: EndpointId) -> Result<String> {
        let now = storage::now();
        self.invites.retain(|_, invite| invite.expires > now);
        let secret = wire::token()?;
        self.invites.insert(
            secret.clone(),
            Invite {
                network,
                issuer,
                expires: now + INVITE_SECONDS,
            },
        );
        Ok(secret)
    }

    fn create(&mut self, who: EndpointId, current: Option<String>, name: String) -> Result<Reply> {
        let (id, live) = match current {
            // A founder retrying after a lost reply keeps the same network and unspent invite.
            Some(id) => {
                let first = self.networks[&id]
                    .first_invite
                    .as_ref()
                    .filter(|first| first.founder == who)
                    .context("this device already belongs to a pocket network on this relay")?;
                let live = self
                    .invites
                    .get(&first.secret)
                    .is_some_and(|invite| invite.expires > storage::now())
                    .then(|| first.secret.clone());
                (id, live)
            }
            None => {
                wire::check_name(&name)?;
                let id = wire::token()?;
                let mut network = Network::default();
                network.add(who, name)?;
                self.networks.insert(id.clone(), network);
                (id, None)
            }
        };
        let invite = match live {
            Some(secret) => secret,
            None => self.issue_invite(id.clone(), who)?,
        };
        let network = self.networks.get_mut(&id).context("network vanished")?;
        network.first_invite = Some(FirstInvite {
            founder: who,
            secret: invite.clone(),
        });
        Ok(Reply::Created {
            name: network.members[&who].name.clone(),
            roster: network.roster(&id, who),
            invite,
        })
    }

    fn enroll(
        &mut self,
        who: EndpointId,
        secret: &str,
        name: String,
        create: bool,
    ) -> Result<Reply> {
        wire::check_name(&name)?;

        let id = if create {
            ensure!(
                bool::from(self.create_secret.as_bytes().ct_eq(secret.as_bytes())),
                wire::INVALID_CREATE_TICKET
            );
            let id = wire::token()?;
            // A create ticket is also a one-use credential.
            self.create_secret = wire::token()?;
            self.networks.insert(id.clone(), Network::default());
            id
        } else {
            let invite = self
                .invites
                .get(secret)
                .context(wire::INVALID_JOIN_INVITE)?;
            ensure!(invite.expires > storage::now(), wire::EXPIRED_INVITE);
            invite.network.clone()
        };

        let network = self.networks.get_mut(&id).context("network vanished")?;
        network.add(who, name)?;
        self.invites.remove(secret);
        Ok(Reply::Roster(network.roster(&id, who)))
    }
}

/// Initialize a ticket-only relay.
pub fn init(dir: &Path, udp: SocketAddr, relay: RelayUrl) -> Result<()> {
    let _lock = storage::lock(dir)?;
    ensure!(!dir.join(STATE_FILE).exists(), "relay already initialized");
    let state = RelayState::new(udp, relay, false)?;
    storage::save(dir, STATE_FILE, &state)?;
    print_ticket(state)
}

/// Load the saved relay, or build a new shared one when given its advertised addresses and no
/// state exists. Returns whether the state is new and still needs saving. Advertised addresses
/// never alter saved state; they must match it.
fn configure(dir: &Path, advertised: Option<(SocketAddr, RelayUrl)>) -> Result<(RelayState, bool)> {
    if !dir.join(STATE_FILE).try_exists()? {
        let (udp, relay) = advertised.context(
            "relay is not initialized; pass --public-udp and --url to start a shared relay, \
             or use relay-init for a ticket-only relay",
        )?;
        return Ok((RelayState::new(udp, relay, true)?, true));
    }
    let state: RelayState = storage::load(dir, STATE_FILE)?;
    if let Some((udp, relay)) = advertised {
        ensure!(
            state.shared,
            "this relay requires operator creation tickets and will not become shared; \
             start it without --public-udp and --url, or use a new state directory"
        );
        ensure!(
            state.server.udp == udp && state.server.relay == relay,
            "this relay is saved with --public-udp {} --url {}; \
             use those values or omit both, or use a new state directory",
            state.server.udp,
            state.server.relay
        );
    }
    Ok((state, false))
}

/// Print a shared relay's public locator.
pub fn info(dir: &Path) -> Result<()> {
    let state: RelayState = storage::load(dir, STATE_FILE)?;
    ensure!(
        state.shared,
        "this relay requires operator creation tickets; use relay-ticket"
    );
    println!("{}", state.server.locator()?);
    Ok(())
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

pub async fn run(
    dir: PathBuf,
    udp_bind: SocketAddr,
    relay_bind: SocketAddr,
    advertised: Option<(SocketAddr, RelayUrl)>,
) -> Result<()> {
    let _lock = storage::lock(&dir)?;
    let (config, new) = configure(&dir, advertised)?;
    let endpoint_key = SecretKey::from_bytes(&config.key);
    let relay_url = config.server.relay.clone();
    let locator = config.shared.then(|| config.server.locator()).transpose()?;
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
    // Save a new relay only once both listeners work, before it can accept a control request.
    if new {
        storage::save(&dir, STATE_FILE, &*state.lock().await)?;
    }
    if let Some(locator) = locator {
        eprintln!("Shared relay locator (public): {locator}");
    }
    eprintln!("MassRelay listening on {udp_bind} UDP and {relay_bind} TCP");
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
                let (dir, state) = (dir.clone(), state.clone());
                let relay_service = relay_service.clone();
                tokio::spawn(async move {
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
            shared: false,
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

    fn addresses() -> (SocketAddr, RelayUrl) {
        (
            "127.0.0.1:4433".parse().unwrap(),
            "http://127.0.0.1:3340".parse().unwrap(),
        )
    }

    fn relay(shared: bool) -> RelayState {
        let (udp, url) = addresses();
        RelayState::new(udp, url, shared).unwrap()
    }

    fn create(name: &str) -> Request {
        Request::Create { name: name.into() }
    }

    fn join(secret: &str, name: &str) -> Request {
        Request::Enroll {
            secret: secret.into(),
            name: name.into(),
            create: false,
        }
    }

    fn created(reply: Reply) -> (String, Roster, String) {
        let Reply::Created {
            name,
            roster,
            invite,
        } = reply
        else {
            panic!("expected a created network");
        };
        (name, roster, invite)
    }

    #[tokio::test]
    async fn retried_creation_keeps_one_network_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (founder, second, third) = (id(1), id(2), id(3));
        let state = Mutex::new(relay(true));
        let (_, roster, invite) =
            created(dispatch(&state, dir.path(), founder, create("first")).await);

        // The reply is lost and the relay restarts before the founder retries.
        let state = Mutex::new(storage::load(dir.path(), STATE_FILE).unwrap());
        let (name, retried, again) =
            created(dispatch(&state, dir.path(), founder, create("renamed")).await);
        assert_eq!(
            (name.as_str(), &retried.network, &again),
            ("first", &roster.network, &invite)
        );

        let mut state = state.into_inner();
        state.apply(second, join(&invite, "second")).unwrap();
        assert!(state.apply(third, join(&invite, "third")).is_err());
        assert!(state.apply(second, create("second")).is_err());

        // A spent invite is replaced, and so is an expired one. Neither works again.
        let (_, _, replacement) = created(state.apply(founder, create("first")).unwrap());
        assert_ne!(replacement, invite);
        state.invites.get_mut(&replacement).unwrap().expires = 0;
        assert!(state.apply(third, join(&replacement, "third")).is_err());
        let (_, _, fresh) = created(state.apply(founder, create("first")).unwrap());
        assert_ne!(fresh, replacement);
        for spent in [&invite, &replacement] {
            assert!(state.apply(third, join(spent, "third")).is_err());
        }
        state.apply(third, join(&fresh, "third")).unwrap();
        assert_eq!(state.networks.len(), 1);
    }

    #[test]
    fn shared_relay_networks_cannot_reach_each_other() {
        let (a, b, c) = (id(1), id(2), id(3));
        let mut relay = relay(true);
        let (_, first, _) = created(relay.apply(a, create("host")).unwrap());
        let (_, second, invite) = created(relay.apply(b, create("host")).unwrap());
        assert_ne!(first.network, second.network);
        assert!(second.peers.is_empty());

        let Reply::Roster(roster) = relay.apply(c, join(&invite, "other")).unwrap() else {
            panic!("expected a roster");
        };
        assert_eq!(roster.network, second.network);
        assert!(roster.peers.iter().map(|p| p.member.id).eq([b]));
        for outsider in [b, c] {
            let pair = Request::Pair {
                peer: a,
                decision: Decision::Approve,
                generation: 0,
            };
            assert!(relay.apply(outsider, pair).is_err());
            assert!(relay.apply(outsider, Request::Revoke { peer: a }).is_err());
        }
        assert!(relay.networks[&first.network].members.contains_key(&a));
    }

    #[test]
    fn startup_never_widens_or_readvertises_a_saved_relay() {
        let dir = tempfile::tempdir().unwrap();
        let (udp, url) = addresses();
        assert!(configure(dir.path(), None).is_err());
        let (shared, new) = configure(dir.path(), Some((udp, url.clone()))).unwrap();
        assert!(new && shared.shared);
        storage::save(dir.path(), STATE_FILE, &shared).unwrap();

        for advertised in [None, Some((udp, url.clone()))] {
            let (saved, new) = configure(dir.path(), advertised).unwrap();
            assert!(!new && saved.shared && saved.key == shared.key);
        }
        let other_udp = "127.0.0.1:4434".parse().unwrap();
        let other_url = "http://127.0.0.1:3341".parse().unwrap();
        assert!(configure(dir.path(), Some((other_udp, url.clone()))).is_err());
        assert!(configure(dir.path(), Some((udp, other_url))).is_err());

        // State written before shared relays existed has neither new field.
        let mut private = relay(false);
        let member = id(1);
        let ticket = Request::Enroll {
            secret: private.create_secret.clone(),
            name: "member".into(),
            create: true,
        };
        private.apply(member, ticket).unwrap();
        let mut legacy = serde_json::to_value(&private).unwrap();
        legacy.as_object_mut().unwrap().remove("shared").unwrap();
        for network in legacy["networks"].as_object_mut().unwrap().values_mut() {
            network
                .as_object_mut()
                .unwrap()
                .remove("first_invite")
                .unwrap();
        }
        storage::save(dir.path(), STATE_FILE, &legacy).unwrap();

        assert!(configure(dir.path(), Some((udp, url))).is_err());
        let (mut saved, _) = configure(dir.path(), None).unwrap();
        assert!(!saved.shared);
        assert!(saved.apply(id(2), create("stranger")).is_err());
        assert!(saved.apply(member, create("member")).is_err());
        assert!(matches!(
            saved.apply(member, Request::Invite).unwrap(),
            Reply::Invite(_)
        ));
    }
}
