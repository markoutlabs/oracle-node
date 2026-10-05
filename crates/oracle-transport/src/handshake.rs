//! The handshake (SPEC §6.1).
//!
//! The client proves its API key over a transcript that binds the node's
//! address, the node's challenge, its own nonce and a fresh X25519 key. The
//! node proves its key over that transcript plus the HPKE encapsulation, the
//! deadline and the first keys. Each side reaches a session only through the
//! other side's signature.

use std::sync::Arc;

use hpke::aead::ExportOnlyAead;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::CryptoRng;
use hpke::{Deserializable as _, HpkeError, Kem as _, OpModeR, OpModeS, Serializable as _};
use oracle_wire::{
    Address, CompressedPublicKey, Signature, Signer, TRANSPORT_PROTOCOL, VerifiedClientList,
    auth_ok_payload, auth_ok_transcript, client_auth_payload, client_auth_transcript, keccak256,
    recover_payload_signer,
};
use zeroize::Zeroizing;

use crate::TransportError;
use crate::broadcast::KeyRing;
use crate::schedule::{EpochKey, eligible, put_prefixed, session_deadline};
use crate::session::{C2N_LABEL, Control, KeyGrant, N2C_LABEL, Opener, Sealer};

type Kem = X25519HkdfSha256;
type EphemeralSecret = <Kem as hpke::Kem>::PrivateKey;
type EphemeralPublic = <Kem as hpke::Kem>::PublicKey;

const EXPORT_N2C: &[u8] = b"price-oracle/2 n2c";
const EXPORT_C2N: &[u8] = b"price-oracle/2 c2n";
const MAX_INITIAL_KEYS: usize = 4;

/// The handshake messages. JSON text frames; byte fields are hex.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HandshakeMessage {
    /// Node → client, first message on the connection.
    Challenge {
        /// Must be [`TRANSPORT_PROTOCOL`].
        proto: String,
        /// The node's address, its id in the registry.
        node: Address,
        /// Fresh for this connection and used once.
        #[serde(with = "hex::serde")]
        challenge: [u8; 32],
    },
    /// Client → node.
    Auth {
        /// The client's API key. Its address is the client's id in the list.
        client_pubkey: CompressedPublicKey,
        /// The client's X25519 key for this connection only.
        #[serde(with = "hex::serde")]
        eph: [u8; 32],
        /// Fresh for this connection.
        #[serde(with = "hex::serde")]
        client_nonce: [u8; 32],
        /// The API key's signature over the client transcript.
        sig: Signature,
    },
    /// Node → client: the session is open.
    AuthOk {
        /// The HPKE encapsulation to `eph`.
        #[serde(with = "hex::serde")]
        enc: [u8; 32],
        /// The session ends here, unix seconds, unless a `session_update` moves it.
        session_deadline: u64,
        /// The first broadcast keys, sealed on the control channel.
        #[serde(with = "hex_list")]
        initial: Vec<Vec<u8>>,
        /// The node's key over the node transcript.
        node_sig: Signature,
    },
    /// Node → client: no session. The connection closes after it.
    Refused {
        /// Why, for the operator's logs.
        reason: String,
    },
}

mod hex_list {
    use serde::de::Error as _;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(items: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(items.iter().map(hex::encode))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|text| hex::decode(text).map_err(D::Error::custom))
            .collect()
    }
}

fn initial_digest(initial: &[Vec<u8>]) -> [u8; 32] {
    let mut out = Vec::with_capacity(4 + initial.len() * 96);
    out.extend_from_slice(
        &u32::try_from(initial.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for sealed in initial {
        put_prefixed(&mut out, sealed);
    }
    keccak256(&out)
}

type SessionKeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

fn export_keys(
    export: impl Fn(&[u8], &mut [u8]) -> Result<(), HpkeError>,
) -> Result<SessionKeys, TransportError> {
    let mut n2c = Zeroizing::new([0_u8; 32]);
    let mut c2n = Zeroizing::new([0_u8; 32]);
    export(EXPORT_N2C, n2c.as_mut()).map_err(|_| TransportError::KeyAgreement)?;
    export(EXPORT_C2N, c2n.as_mut()).map_err(|_| TransportError::KeyAgreement)?;
    Ok((n2c, c2n))
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(bytes);
    out
}

/// The node's side, from challenge to admission.
#[derive(Debug)]
pub struct NodeHandshake {
    node: Address,
    challenge: [u8; 32],
}

impl NodeHandshake {
    /// Opens a handshake with a fresh challenge. Send the returned message first.
    pub fn start(node: Address, rng: &mut impl CryptoRng) -> (Self, HandshakeMessage) {
        let mut challenge = [0_u8; 32];
        rng.fill_bytes(&mut challenge);
        let message = HandshakeMessage::Challenge {
            proto: TRANSPORT_PROTOCOL.to_owned(),
            node,
            challenge,
        };
        (Self { node, challenge }, message)
    }

    /// Checks the client's `Auth`, cheapest check first. Consumes the
    /// handshake, so a challenge serves one attempt.
    ///
    /// `clients` must be fresh; judging that is the caller's job.
    ///
    /// # Errors
    ///
    /// Returns the first rule the message breaks.
    pub fn verify(
        self,
        message: &HandshakeMessage,
        clients: &VerifiedClientList,
        now: u64,
    ) -> Result<Admitted, TransportError> {
        let HandshakeMessage::Auth {
            client_pubkey,
            eph,
            client_nonce,
            sig,
        } = message
        else {
            return Err(TransportError::Malformed("expected auth".to_owned()));
        };
        let client = client_pubkey.address()?;
        let entry = clients
            .get(client)
            .ok_or(TransportError::UnknownClient(client))?;
        let deadline = session_deadline(entry.expires_at, clients.epoch_secs());
        if now >= deadline {
            return Err(TransportError::Expired { deadline, now });
        }
        let transcript =
            client_auth_transcript(self.node, &self.challenge, client_nonce, client_pubkey, eph)?;
        let signer = recover_payload_signer(&client_auth_payload(&transcript), sig)
            .map_err(|_| TransportError::BadSignature)?;
        if signer != client {
            return Err(TransportError::BadSignature);
        }
        let eph = EphemeralPublic::from_bytes(eph)
            .map_err(|_| TransportError::Malformed("bad X25519 key".to_owned()))?;
        Ok(Admitted {
            client,
            transcript,
            eph,
            deadline,
        })
    }
}

/// A client that passed every check, before the node commits to a session.
pub struct Admitted {
    client: Address,
    transcript: [u8; 32],
    eph: EphemeralPublic,
    deadline: u64,
}

impl Admitted {
    /// Returns the client's address.
    #[must_use]
    pub const fn client(&self) -> Address {
        self.client
    }

    /// Returns the session deadline, unix seconds.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Opens the session: HPKE to the client's X25519 key, the eligible keys
    /// sealed on the new channel, and the node's signature over all of it.
    /// Keys past the deadline are dropped here, whatever the caller passes.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::KeyAgreement`] if HPKE fails.
    pub fn accept(
        self,
        node_signer: &Signer,
        keys: &[Arc<EpochKey>],
        rng: &mut impl CryptoRng,
    ) -> Result<(HandshakeMessage, NodeSession), TransportError> {
        let (enc, context) = hpke::setup_sender_with_rng::<ExportOnlyAead, HkdfSha256, Kem>(
            &OpModeS::Base,
            &self.eph,
            &self.transcript,
            rng,
        )
        .map_err(|_| TransportError::KeyAgreement)?;
        let (n2c, c2n) = export_keys(|info, out| context.export(info, out))?;
        let mut sealer = Sealer::new(&n2c, N2C_LABEL);
        let initial = keys
            .iter()
            .filter(|key| eligible(key.context(), self.deadline))
            .take(MAX_INITIAL_KEYS)
            .map(|key| sealer.seal(&Control::KeyUpdate(KeyGrant::from_key(key))))
            .collect::<Result<Vec<_>, _>>()?;

        let enc = array32(&enc.to_bytes());
        let node_transcript = auth_ok_transcript(
            &self.transcript,
            &enc,
            self.deadline,
            &initial_digest(&initial),
        )?;
        let message = HandshakeMessage::AuthOk {
            enc,
            session_deadline: self.deadline,
            initial,
            node_sig: node_signer.sign_payload(&auth_ok_payload(&node_transcript)),
        };
        let session = NodeSession {
            client: self.client,
            deadline: self.deadline,
            sealer,
            opener: Opener::new(&c2n, C2N_LABEL),
        };
        Ok((message, session))
    }
}

/// The node's half of an open session.
pub struct NodeSession {
    /// The client's address.
    pub client: Address,
    /// The session deadline, unix seconds.
    pub deadline: u64,
    /// Node → client control channel. Its first messages were the initial keys.
    pub sealer: Sealer,
    /// Client → node control channel.
    pub opener: Opener,
}

/// The client's side, before the challenge arrives.
pub struct ClientHandshake {
    node: Address,
    eph_secret: EphemeralSecret,
    eph_public: [u8; 32],
    client_nonce: [u8; 32],
}

impl ClientHandshake {
    /// Prepares a handshake with the node the client is dialling.
    pub fn new(node: Address, rng: &mut impl CryptoRng) -> Self {
        let (eph_secret, eph_public) = Kem::gen_keypair_with_rng(rng);
        let mut client_nonce = [0_u8; 32];
        rng.fill_bytes(&mut client_nonce);
        Self {
            node,
            eph_secret,
            eph_public: array32(&eph_public.to_bytes()),
            client_nonce,
        }
    }

    /// Answers the node's challenge with a signed `Auth`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Protocol`] or [`TransportError::WrongNode`]
    /// if the challenge is not from the node dialled over this protocol.
    pub fn respond(
        self,
        message: &HandshakeMessage,
        api_key: &Signer,
    ) -> Result<(HandshakeMessage, AwaitingAuthOk), TransportError> {
        let HandshakeMessage::Challenge {
            proto,
            node,
            challenge,
        } = message
        else {
            return Err(TransportError::Malformed("expected challenge".to_owned()));
        };
        if proto != TRANSPORT_PROTOCOL {
            return Err(TransportError::Protocol(proto.clone()));
        }
        if *node != self.node {
            return Err(TransportError::WrongNode {
                expected: self.node,
                got: *node,
            });
        }
        let client_pubkey = api_key.public_key();
        let transcript = client_auth_transcript(
            self.node,
            challenge,
            &self.client_nonce,
            &client_pubkey,
            &self.eph_public,
        )?;
        let auth = HandshakeMessage::Auth {
            client_pubkey,
            eph: self.eph_public,
            client_nonce: self.client_nonce,
            sig: api_key.sign_payload(&client_auth_payload(&transcript)),
        };
        Ok((
            auth,
            AwaitingAuthOk {
                node: self.node,
                eph_secret: self.eph_secret,
                transcript,
            },
        ))
    }
}

/// The client after `Auth`, waiting for the node to prove itself.
#[cfg_attr(test, derive(Clone))]
pub struct AwaitingAuthOk {
    node: Address,
    eph_secret: EphemeralSecret,
    transcript: [u8; 32],
}

impl AwaitingAuthOk {
    /// Verifies `AuthOk` against the dialled address, then opens the session
    /// and its first keys. Nothing in the message is used before the
    /// signature checks.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UntrustedNode`] for any signer but the dialled
    /// node, and an error for a refusal or a malformed message.
    pub fn finish(self, message: &HandshakeMessage) -> Result<ClientSession, TransportError> {
        let HandshakeMessage::AuthOk {
            enc,
            session_deadline,
            initial,
            node_sig,
        } = message
        else {
            return Err(match message {
                HandshakeMessage::Refused { reason } => {
                    TransportError::Malformed(format!("refused: {reason}"))
                }
                _ => TransportError::Malformed("expected auth_ok".to_owned()),
            });
        };
        if initial.len() > MAX_INITIAL_KEYS {
            return Err(TransportError::Malformed(
                "too many initial keys".to_owned(),
            ));
        }
        let node_transcript = auth_ok_transcript(
            &self.transcript,
            enc,
            *session_deadline,
            &initial_digest(initial),
        )?;
        let found = recover_payload_signer(&auth_ok_payload(&node_transcript), node_sig)?;
        if found != self.node {
            return Err(TransportError::UntrustedNode {
                found,
                expected: self.node,
            });
        }

        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc)
            .map_err(|_| TransportError::Malformed("bad encapsulation".to_owned()))?;
        let context = hpke::setup_receiver::<ExportOnlyAead, HkdfSha256, Kem>(
            &OpModeR::Base,
            &self.eph_secret,
            &enc,
            &self.transcript,
        )
        .map_err(|_| TransportError::KeyAgreement)?;
        let (n2c, c2n) = export_keys(|info, out| context.export(info, out))?;
        let mut opener = Opener::new(&n2c, N2C_LABEL);
        let mut keys = KeyRing::new(self.node);
        for sealed in initial {
            match opener.open(sealed)? {
                Control::KeyUpdate(grant) => keys.insert(grant),
                _ => {
                    return Err(TransportError::Malformed(
                        "initial messages must be keys".to_owned(),
                    ));
                }
            }
        }
        Ok(ClientSession {
            node: self.node,
            deadline: *session_deadline,
            sealer: Sealer::new(&c2n, C2N_LABEL),
            opener,
            keys,
        })
    }
}

/// The client's half of an open session.
#[derive(Debug)]
pub struct ClientSession {
    /// The node, as dialled.
    pub node: Address,
    /// The session deadline the node announced, unix seconds.
    pub deadline: u64,
    /// Client → node control channel.
    pub sealer: Sealer,
    /// Node → client control channel.
    pub opener: Opener,
    /// The node's broadcast keys this client holds.
    pub keys: KeyRing,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer")
    }
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opener")
    }
}

#[cfg(test)]
mod tests {
    use oracle_wire::{ClientEntry, ClientList};

    use super::*;
    use crate::broadcast::BroadcastSealer;
    use crate::schedule::NodeKeySchedule;
    use crate::{CloseReason, os_rng};

    const NOW: u64 = 1_754_582_430; // 30 s into an epoch
    const T: u64 = 60;

    fn key(seed: u8) -> Signer {
        Signer::from_secret_bytes([seed; 32]).expect("valid key")
    }

    fn governance() -> Signer {
        key(0xC0)
    }

    fn node_key() -> Signer {
        key(0x10)
    }

    fn node() -> Address {
        node_key().address()
    }

    fn clients(entries: &[(u8, u64)]) -> VerifiedClientList {
        let list = ClientList::sign(
            &governance(),
            1,
            NOW,
            T,
            entries
                .iter()
                .map(|&(seed, expires_at)| ClientEntry {
                    address: key(seed).address(),
                    expires_at,
                })
                .collect(),
        )
        .expect("signs");
        list.verify(governance().address(), 0).expect("verifies")
    }

    struct Pair {
        node: NodeSession,
        client: ClientSession,
    }

    fn connect(
        schedule: &NodeKeySchedule,
        list: &VerifiedClientList,
        api_key: &Signer,
    ) -> Result<Pair, TransportError> {
        let (handshake, challenge) = NodeHandshake::start(node(), &mut os_rng());
        let (auth, waiting) =
            ClientHandshake::new(node(), &mut os_rng()).respond(&challenge, api_key)?;
        let admitted = handshake.verify(&auth, list, NOW)?;
        let keys = schedule.keys_for(admitted.deadline());
        let (auth_ok, node) = admitted.accept(&node_key(), &keys, &mut os_rng())?;
        let client = waiting.finish(&auth_ok)?;
        Ok(Pair { node, client })
    }

    fn schedule() -> NodeKeySchedule {
        NodeKeySchedule::new(node(), T, NOW, &mut os_rng())
    }

    #[test]
    fn a_listed_client_gets_a_session_and_the_current_key() {
        let s = schedule();
        let list = clients(&[(1, NOW + 3_600)]);
        let mut pair = connect(&s, &list, &key(1)).expect("connects");
        assert_eq!(pair.node.client, key(1).address());
        assert_eq!(pair.client.deadline, session_deadline(NOW + 3_600, T));
        assert_eq!(pair.client.keys.len(), 1);

        let frame = vec![7_u8; oracle_wire::FRAME_SIZE];
        let sealed = BroadcastSealer::new(Arc::clone(s.current())).seal(&frame, &mut os_rng());
        assert_eq!(pair.client.keys.open(&sealed).expect("opens"), frame);

        let up = pair
            .client
            .sealer
            .seal(&Control::App(b"subscribe".to_vec()))
            .expect("seals");
        assert_eq!(
            pair.node.opener.open(&up).expect("opens"),
            Control::App(b"subscribe".to_vec())
        );
        let down = pair
            .node
            .sealer
            .seal(&Control::Close(CloseReason::Expired))
            .expect("seals");
        assert_eq!(
            pair.client.opener.open(&down).expect("opens"),
            Control::Close(CloseReason::Expired)
        );
    }

    #[test]
    fn the_handshake_messages_round_trip_through_json() {
        let (_, challenge) = NodeHandshake::start(node(), &mut os_rng());
        let json = serde_json::to_string(&challenge).expect("serialises");
        assert!(json.contains(r#""op":"challenge""#), "{json}");
        let parsed: HandshakeMessage = serde_json::from_str(&json).expect("parses");
        assert_eq!(parsed, challenge);
    }

    #[test]
    fn the_node_refuses_unknown_expired_and_forged_clients() {
        let s = schedule();
        let list = clients(&[(1, NOW + 3_600), (2, NOW - 1)]);
        let attempt = |api_key: &Signer| connect(&s, &list, api_key).map(|_| ());
        assert_eq!(
            attempt(&key(9)),
            Err(TransportError::UnknownClient(key(9).address()))
        );
        assert!(matches!(
            attempt(&key(2)),
            Err(TransportError::Expired { .. })
        ));

        // The listed key, but a signature by someone else.
        let (handshake, challenge) = NodeHandshake::start(node(), &mut os_rng());
        let (auth, _) = ClientHandshake::new(node(), &mut os_rng())
            .respond(&challenge, &key(1))
            .expect("responds");
        let HandshakeMessage::Auth {
            client_pubkey,
            eph,
            client_nonce,
            ..
        } = auth
        else {
            panic!("auth");
        };
        let forged = HandshakeMessage::Auth {
            client_pubkey,
            eph,
            client_nonce,
            sig: key(3).sign_payload(&[0; 34]),
        };
        assert_eq!(
            handshake.verify(&forged, &list, NOW).err(),
            Some(TransportError::BadSignature)
        );
    }

    #[test]
    fn the_deadline_is_exclusive_and_snapped_to_the_grid() {
        let s = schedule();
        let boundary = NOW - NOW % T + T; // the next boundary
        let at = |expires_at: u64, now: u64| {
            let list = clients(&[(1, expires_at)]);
            let (handshake, challenge) = NodeHandshake::start(node(), &mut os_rng());
            let (auth, _) = ClientHandshake::new(node(), &mut os_rng())
                .respond(&challenge, &key(1))
                .expect("responds");
            handshake.verify(&auth, &list, now).map(|admitted| {
                let keys = s.keys_for(admitted.deadline());
                (admitted.deadline(), keys.len())
            })
        };
        assert_eq!(at(boundary, NOW).ok(), Some((boundary, 1)), "on a boundary");
        assert_eq!(at(boundary + 1, NOW).ok(), Some((boundary, 1)));
        assert!(
            matches!(at(boundary - 1, NOW), Err(TransportError::Expired { .. })),
            "one second before the boundary snaps to the epoch already running"
        );
        assert_eq!(at(boundary, boundary - 1).ok(), Some((boundary, 1)));
        assert!(matches!(
            at(boundary, boundary),
            Err(TransportError::Expired { .. })
        ));
    }

    /// The client signs over the node and the challenge, so its `Auth` is good
    /// for one connection to one node.
    #[test]
    fn an_auth_cannot_be_replayed_or_relayed() {
        let list = clients(&[(1, NOW + 3_600)]);
        let other = key(0x11).address();
        let (node_a, challenge_a) = NodeHandshake::start(node(), &mut os_rng());
        let (auth, _) = ClientHandshake::new(node(), &mut os_rng())
            .respond(&challenge_a, &key(1))
            .expect("responds");
        node_a.verify(&auth, &list, NOW).expect("first use");

        let (node_a_again, _) = NodeHandshake::start(node(), &mut os_rng());
        assert_eq!(
            node_a_again.verify(&auth, &list, NOW).err(),
            Some(TransportError::BadSignature),
            "a new connection has a new challenge"
        );
        let (node_b, _) = NodeHandshake::start(other, &mut os_rng());
        assert_eq!(
            node_b.verify(&auth, &list, NOW).err(),
            Some(TransportError::BadSignature),
            "another node"
        );

        let (_, challenge_b) = NodeHandshake::start(other, &mut os_rng());
        assert_eq!(
            ClientHandshake::new(node(), &mut os_rng())
                .respond(&challenge_b, &key(1))
                .err(),
            Some(TransportError::WrongNode {
                expected: node(),
                got: other
            })
        );
    }

    /// A MITM can make its own HPKE context to the client's public X25519 key,
    /// but it cannot get the node's signature over it. Every swap is checked
    /// against the same handshake, so only the swapped field can be the cause.
    #[test]
    fn the_client_accepts_nothing_the_node_did_not_sign() {
        let s = schedule();
        let list = clients(&[(1, NOW + 3_600)]);
        let (handshake, challenge) = NodeHandshake::start(node(), &mut os_rng());
        let (auth, waiting) = ClientHandshake::new(node(), &mut os_rng())
            .respond(&challenge, &key(1))
            .expect("responds");
        let admitted = handshake.verify(&auth, &list, NOW).expect("admits");
        let deadline = admitted.deadline();
        let (genuine, _) = admitted
            .accept(&node_key(), &s.keys_for(deadline), &mut os_rng())
            .expect("accepts");
        let HandshakeMessage::AuthOk {
            enc,
            session_deadline,
            initial,
            node_sig,
        } = genuine.clone()
        else {
            panic!("auth_ok");
        };

        let mut other_enc = enc;
        other_enc[0] ^= 1;
        let mut other_initial = initial.clone();
        if let Some(byte) = other_initial.first_mut().and_then(|blob| blob.last_mut()) {
            *byte ^= 1;
        }
        let swaps = [
            HandshakeMessage::AuthOk {
                enc: other_enc,
                session_deadline,
                initial: initial.clone(),
                node_sig,
            },
            HandshakeMessage::AuthOk {
                enc,
                session_deadline: session_deadline + T,
                initial: initial.clone(),
                node_sig,
            },
            HandshakeMessage::AuthOk {
                enc,
                session_deadline,
                initial: other_initial,
                node_sig,
            },
            HandshakeMessage::AuthOk {
                enc,
                session_deadline,
                initial: Vec::new(),
                node_sig,
            },
        ];
        for swapped in swaps {
            assert!(
                matches!(
                    waiting.clone().finish(&swapped),
                    Err(TransportError::UntrustedNode { .. })
                ),
                "a swapped field must break the node signature"
            );
        }
        // Every field genuine, but signed by another node's key.
        let (
            HandshakeMessage::Challenge { challenge, .. },
            HandshakeMessage::Auth {
                client_pubkey,
                eph,
                client_nonce,
                ..
            },
        ) = (&challenge, &auth)
        else {
            panic!("challenge and auth");
        };
        let client_transcript =
            client_auth_transcript(node(), challenge, client_nonce, client_pubkey, eph)
                .expect("encodes");
        let node_transcript = auth_ok_transcript(
            &client_transcript,
            &enc,
            session_deadline,
            &initial_digest(&initial),
        )
        .expect("encodes");
        let signed_elsewhere = HandshakeMessage::AuthOk {
            enc,
            session_deadline,
            initial,
            node_sig: key(0x11).sign_payload(&auth_ok_payload(&node_transcript)),
        };
        assert!(
            matches!(
                waiting.clone().finish(&signed_elsewhere),
                Err(TransportError::UntrustedNode { .. })
            ),
            "a genuine message, signed by another node's key"
        );
        waiting
            .finish(&genuine)
            .expect("the genuine message from the dialled node opens the session");
    }

    /// Check 7: after a revocation and a forced rotation, nothing the revoked
    /// client ever held opens the new frames.
    #[test]
    fn a_revoked_client_cannot_open_frames_after_the_forced_rotation() {
        let mut s = schedule();
        let list = clients(&[(1, NOW + 3_600), (2, NOW + 3_600)]);
        let mut a = connect(&s, &list, &key(1)).expect("a connects");
        let mut b = connect(&s, &list, &key(2)).expect("b connects");
        let sealer = BroadcastSealer::new(Arc::clone(s.current()));
        let before = vec![1_u8; oracle_wire::FRAME_SIZE];
        let sealed_before = sealer.seal(&before, &mut os_rng());
        assert!(b.client.keys.open(&sealed_before).is_ok());

        // B is revoked: its session is dropped, then the keys rotate.
        let fresh = s.force_rotate(NOW + 1, &mut os_rng());
        let mut updates_for_a = Vec::new();
        for key in &fresh {
            updates_for_a.push(
                a.node
                    .sealer
                    .seal(&Control::KeyUpdate(KeyGrant::from_key(key)))
                    .expect("seals"),
            );
        }
        sealer.install(Arc::clone(s.current()));
        let after = vec![2_u8; oracle_wire::FRAME_SIZE];
        let sealed_after = sealer.seal(&after, &mut os_rng());

        // B holds the old key and its own channel, and obtains A's traffic.
        assert_eq!(
            b.client.keys.open(&sealed_after),
            Err(TransportError::UnknownKey)
        );
        for update in &updates_for_a {
            assert!(
                b.client.opener.open(update).is_err(),
                "B cannot read A's key delivery"
            );
        }
        // Even if B relabels the frame with its old key id, its old key fails.
        let mut relabelled = sealed_after.clone();
        let old_id = *sealer_key_id(&sealed_before);
        if let Some(slot) = relabelled.get_mut(2..18) {
            slot.copy_from_slice(&old_id);
        }
        assert_eq!(
            b.client.keys.open(&relabelled),
            Err(TransportError::Decrypt)
        );

        for update in &updates_for_a {
            let Control::KeyUpdate(grant) = a.client.opener.open(update).expect("opens") else {
                panic!("key update");
            };
            a.client.keys.insert(grant);
        }
        assert_eq!(a.client.keys.open(&sealed_after).expect("opens"), after);
    }

    fn sealer_key_id(sealed: &[u8]) -> &[u8; 16] {
        sealed
            .get(2..18)
            .and_then(|slice| slice.try_into().ok())
            .expect("a sealed frame has a key id")
    }
}
