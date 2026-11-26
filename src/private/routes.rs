//! Local direct-route hints learned from authenticated peer connections.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex,
};

use iroh::{EndpointId, TransportAddr, endpoint::Connection};

const FILE: &str = "direct-routes.json";
type Addresses = BTreeMap<EndpointId, SocketAddr>;

pub(super) struct Routes {
    dir: PathBuf,
    addresses: Mutex<Addresses>,
}

impl Routes {
    pub fn open(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            addresses: Mutex::new(crate::storage::load(dir, FILE).unwrap_or_default()),
        }
    }

    pub fn get(&self, peer: EndpointId) -> Option<SocketAddr> {
        self.addresses
            .lock()
            .expect("direct routes")
            .get(&peer)
            .copied()
    }

    /// The connection has already proved mutual group authorization. Save
    /// validated direct routes as they become selected during the session.
    pub async fn watch(&self, conn: &Connection) {
        let mut paths = conn.paths_stream();
        let mut last = None;
        while let Some(path) = paths
            .wait_any(|path| {
                path.is_selected()
                    && match path.remote_addr() {
                        TransportAddr::Ip(address) => Some(*address) != last,
                        _ => false,
                    }
            })
            .await
        {
            if let TransportAddr::Ip(address) = path.remote_addr() {
                last = Some(*address);
                self.remember(conn.remote_id(), *address);
            }
        }
        // Closure is handled by the service future.
        std::future::pending::<()>().await;
    }

    fn remember(&self, peer: EndpointId, addr: SocketAddr) {
        let mut addresses = self.addresses.lock().expect("direct routes");
        if addresses.get(&peer) != Some(&addr) {
            addresses.insert(peer, addr);
            if let Err(error) = crate::storage::save(&self.dir, FILE, &*addresses) {
                super::diagnostics::event(
                    super::diagnostics::Level::Warning,
                    format!("could not save direct routes: {error}"),
                );
            }
        }
    }
}
