//! The node side of the transport (SPEC §6.1): admission, key rotation,
//! deadlines and revocation. The cryptography is in `oracle-transport`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oracle_transport::{
    BroadcastSealer, CloseReason, EpochKey, HandshakeMessage, NodeHandshake, NodeKeySchedule,
    Opener, Sealer, Tick, TransportError, eligible, os_rng, session_deadline,
};
use oracle_wire::{Signer, VerifiedClientList};
use tokio::sync::{Semaphore, mpsc};
use tracing::{info, warn};

use crate::hub::{Hub, Subscriber};

/// Room for control replies and key pushes on one connection. A client this
/// far behind on control messages is closed rather than buffered.
const OUTBOX_CAPACITY: usize = 64;

/// Limits for the transport.
#[derive(Clone, Copy, Debug)]
pub struct TransportConfig {
    /// Handshakes in progress at once. Further upgrades get 503.
    pub max_handshakes: usize,
    /// Time from upgrade to `auth_ok`.
    pub handshake_timeout: Duration,
    /// Refuse new sessions when no fetch has confirmed the client list for
    /// this long, seconds.
    pub admit_within: u64,
    /// Close every session when no fetch has confirmed the client list for
    /// this long, seconds.
    pub serve_within: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_handshakes: 256,
            handshake_timeout: Duration::from_secs(10),
            admit_within: 3 * 3_600,
            serve_within: 24 * 3_600,
        }
    }
}

/// Something the writer of one connection must seal and send, in order.
#[derive(Debug)]
pub enum Outbound {
    /// An application control reply, JSON.
    App(Vec<u8>),
    /// A broadcast key.
    Key(Arc<EpochKey>),
    /// The deadline moved.
    Deadline(u64),
    /// End the session.
    Close(CloseReason),
}

/// What a connection needs once its handshake succeeds.
pub struct Established {
    /// The hub mailbox.
    pub subscriber: Arc<Subscriber>,
    /// Node → client control channel, continuing after the initial keys.
    pub sealer: Sealer,
    /// Client → node control channel.
    pub opener: Opener,
    /// Pushes from rotation and revocation, and the reader's replies.
    pub outbox: mpsc::Receiver<Outbound>,
    /// Where the reader queues its replies, behind any pushed key.
    pub replies: mpsc::Sender<Outbound>,
    /// The session deadline, unix seconds.
    pub deadline: u64,
}

struct Session {
    client_id: String,
    pubkey: oracle_wire::CompressedPublicKey,
    deadline: u64,
    push: mpsc::Sender<Outbound>,
    subscriber: Arc<Subscriber>,
}

struct Keys {
    schedule: NodeKeySchedule,
    sessions: HashMap<u64, Session>,
}

/// One node's transport state.
pub struct NodeTransport {
    node_id: String,
    signer: Arc<Signer>,
    hub: Arc<Hub>,
    sealer: Arc<BroadcastSealer>,
    clients: RwLock<VerifiedClientList>,
    /// When a fetch last proved the client list current, unix seconds.
    confirmed_at: AtomicU64,
    keys: Mutex<Keys>,
    handshakes: Arc<Semaphore>,
    config: TransportConfig,
}

/// Wall-clock unix seconds, the reference for every deadline and epoch.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl NodeTransport {
    /// Builds the transport and the sealer the hub publishes through.
    #[must_use]
    pub fn new(
        node_id: &str,
        signer: Arc<Signer>,
        clients: VerifiedClientList,
        config: TransportConfig,
        max_pending: usize,
        now: u64,
    ) -> Arc<Self> {
        let schedule = NodeKeySchedule::new(node_id, clients.epoch_secs(), now, &mut os_rng());
        let sealer = Arc::new(BroadcastSealer::new(Arc::clone(schedule.current())));
        Arc::new(Self {
            node_id: node_id.to_owned(),
            signer,
            hub: Arc::new(Hub::new(max_pending, Arc::clone(&sealer))),
            sealer,
            clients: RwLock::new(clients),
            confirmed_at: AtomicU64::new(now),
            keys: Mutex::new(Keys {
                schedule,
                sessions: HashMap::new(),
            }),
            handshakes: Arc::new(Semaphore::new(config.max_handshakes.max(1))),
            config,
        })
    }

    /// Returns the hub that seals each update once.
    #[must_use]
    pub const fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    /// Returns the node id.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Returns the limits.
    #[must_use]
    pub const fn config(&self) -> TransportConfig {
        self.config
    }

    /// Returns the handshake gate.
    #[must_use]
    pub fn handshakes(&self) -> Arc<Semaphore> {
        Arc::clone(&self.handshakes)
    }

    /// Returns the open session count.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.lock_keys().sessions.len()
    }

    /// Returns the client-list version in use.
    #[must_use]
    pub fn clients_version(&self) -> u64 {
        self.read_clients().version()
    }

    /// Returns the key sealing now, for tests and diagnostics.
    #[must_use]
    pub fn current_key(&self) -> Arc<EpochKey> {
        self.sealer.current()
    }

    fn lock_keys(&self) -> std::sync::MutexGuard<'_, Keys> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn read_clients(&self) -> std::sync::RwLockReadGuard<'_, VerifiedClientList> {
        self.clients.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a handshake: the challenge to send first.
    #[must_use]
    pub fn start(&self) -> (NodeHandshake, HandshakeMessage) {
        NodeHandshake::start(&self.node_id, &mut os_rng())
    }

    /// Checks a client's `Auth` and, if it passes, opens the session.
    ///
    /// Runs under the client-list read guard and the key lock, so a list swap
    /// or a rotation lands either wholly before the session or wholly after it.
    ///
    /// # Errors
    ///
    /// Returns the reason the client is refused.
    pub fn admit(
        &self,
        handshake: NodeHandshake,
        auth: &HandshakeMessage,
        now: u64,
    ) -> Result<(HandshakeMessage, Established), TransportError> {
        let clients = self.read_clients();
        if self.unconfirmed_for(now) > self.config.admit_within {
            return Err(TransportError::Malformed(
                "the node's client list is stale; try another node".to_owned(),
            ));
        }
        let admitted = handshake.verify(auth, &clients, now)?;
        let pubkey = clients
            .get(admitted.client_id())
            .map(|entry| entry.pubkey)
            .ok_or_else(|| TransportError::UnknownClient(admitted.client_id().to_owned()))?;

        let mut keys = self.lock_keys();
        let offered = keys.schedule.keys_for(admitted.deadline());
        let client_id = admitted.client_id().to_owned();
        let deadline = admitted.deadline();
        let (auth_ok, session) = admitted.accept(&self.signer, &offered, &mut os_rng())?;

        let subscriber = self.hub.subscribe(&client_id);
        let (push, outbox) = mpsc::channel(OUTBOX_CAPACITY);
        let replies = push.clone();
        keys.sessions.insert(
            subscriber.id(),
            Session {
                client_id: client_id.clone(),
                pubkey,
                deadline,
                push,
                subscriber: Arc::clone(&subscriber),
            },
        );
        drop(keys);
        drop(clients);
        info!(%client_id, deadline, "client session opened");
        Ok((
            auth_ok,
            Established {
                subscriber,
                sealer: session.sealer,
                opener: session.opener,
                outbox,
                replies,
                deadline,
            },
        ))
    }

    /// Forgets a session whose connection ended.
    pub fn release(&self, subscriber_id: u64) {
        self.lock_keys().sessions.remove(&subscriber_id);
        self.hub.unsubscribe(subscriber_id);
    }

    /// Advances the key schedule, closes sessions past their deadline, and
    /// enforces the freshness limit. Call about once a second.
    pub fn tick(&self, now: u64) {
        let stale = self.unconfirmed_for(now) > self.config.serve_within;
        let mut keys = self.lock_keys();
        if stale {
            close_all(&mut keys.sessions, CloseReason::Stale);
            return;
        }
        match keys.schedule.tick(now, &mut os_rng()) {
            Tick::Unchanged => {}
            Tick::NextReady(next) => deliver(&mut keys.sessions, &next),
            Tick::Switched { key, announced } => {
                if !announced {
                    deliver(&mut keys.sessions, &key);
                }
                // After the deliveries are queued, so no session sees a frame
                // under a key it has not been sent.
                self.sealer.install(key);
            }
        }
        keys.sessions.retain(|_, session| {
            if session.deadline <= now {
                end(session, CloseReason::Expired);
                false
            } else {
                true
            }
        });
    }

    /// Takes a client list a certified fetch returned. The version in use
    /// counts as a confirmation and returns `None`; a newer one is adopted and
    /// returns the number of sessions it revoked.
    ///
    /// Adoption closes sessions whose client was removed, rekeyed or cut
    /// short; if any were, the keys rotate off the grid so what those clients
    /// hold stops working. Extensions are pushed.
    ///
    /// # Errors
    ///
    /// Returns the verification error if `next` is neither the list in use nor
    /// a valid successor.
    pub fn offer_clients(
        &self,
        next: &oracle_wire::ClientList,
        now: u64,
    ) -> Result<Option<usize>, oracle_wire::VerifyError> {
        if next.version == self.clients_version() {
            self.confirm_clients(now);
            return Ok(None);
        }
        self.replace_clients(next, now).map(Some)
    }

    fn confirm_clients(&self, now: u64) {
        self.confirmed_at.fetch_max(now, Ordering::Relaxed);
    }

    fn unconfirmed_for(&self, now: u64) -> u64 {
        now.saturating_sub(self.confirmed_at.load(Ordering::Relaxed))
    }

    fn replace_clients(
        &self,
        next: &oracle_wire::ClientList,
        now: u64,
    ) -> Result<usize, oracle_wire::VerifyError> {
        let mut clients = self.clients.write().unwrap_or_else(PoisonError::into_inner);
        let verified = clients.accept_successor(next)?;
        let epoch_secs = verified.epoch_secs();
        let mut keys = self.lock_keys();
        let mut revoked = 0_usize;
        let pending: Vec<Arc<EpochKey>> = std::iter::once(keys.schedule.current())
            .chain(keys.schedule.next())
            .cloned()
            .collect();
        keys.sessions.retain(|_, session| {
            let new_deadline = verified
                .get(&session.client_id)
                .filter(|entry| entry.pubkey == session.pubkey)
                .map(|entry| session_deadline(entry.expires_at, epoch_secs));
            match new_deadline {
                Some(deadline) if deadline >= session.deadline && deadline > now => {
                    if deadline > session.deadline {
                        let old = session.deadline;
                        session.deadline = deadline;
                        let _ = session.push.try_send(Outbound::Deadline(deadline));
                        for key in &pending {
                            let context = key.context();
                            if !eligible(context, old) && eligible(context, deadline) {
                                let _ = session.push.try_send(Outbound::Key(Arc::clone(key)));
                            }
                        }
                    }
                    true
                }
                _ => {
                    end(session, CloseReason::Revoked);
                    revoked += 1;
                    false
                }
            }
        });
        if revoked > 0 {
            let fresh = keys.schedule.force_rotate(now, &mut os_rng());
            for key in &fresh {
                deliver(&mut keys.sessions, key);
            }
            if let Some(current) = fresh.first() {
                self.sealer.install(Arc::clone(current));
            }
            warn!(revoked, "client sessions revoked; broadcast keys rotated");
        }
        *clients = verified;
        self.confirm_clients(now);
        Ok(revoked)
    }
}

fn deliver(sessions: &mut HashMap<u64, Session>, key: &Arc<EpochKey>) {
    sessions.retain(|_, session| {
        if !eligible(key.context(), session.deadline) {
            return true;
        }
        if session
            .push
            .try_send(Outbound::Key(Arc::clone(key)))
            .is_err()
        {
            // A full or closed outbox: the client cannot keep up with keys.
            end(session, CloseReason::Lagged);
            return false;
        }
        true
    });
}

fn end(session: &Session, reason: CloseReason) {
    let _ = session.push.try_send(Outbound::Close(reason));
    session.subscriber.close();
}

fn close_all(sessions: &mut HashMap<u64, Session>, reason: CloseReason) {
    for session in sessions.values() {
        end(session, reason);
    }
    sessions.clear();
}
