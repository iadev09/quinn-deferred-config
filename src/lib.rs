//! Prototype: ClientHello-based deferred `ServerConfig` selection for Quinn,
//! implemented entirely outside of Quinn (no fork) and outside of rustls
//! (no patch). Targets Quinn 0.11 + rustls 0.23 as published on crates.io.

use std::any::Any;
use std::sync::Arc;

use quinn_proto::crypto::rustls::{NoInitialCipherSuite, QuicServerConfig};
use quinn_proto::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, ServerConfig, Session,
    UnsupportedVersion,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::ConnectionId;
use quinn_proto::Side;
use quinn_proto::TransportError;
use quinn_proto::TransportErrorCode;

mod parse;
use parse::Parse;

fn protocol_violation(reason: &'static str) -> TransportError {
    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: reason.into(),
    }
}

/// Application-supplied selector: given a view of the `ClientHello`, pick
/// the `rustls::ServerConfig` to use for this connection.
pub type Selector =
    Arc<dyn Fn(&ClientHelloView<'_>) -> Arc<rustls::ServerConfig> + Send + Sync + 'static>;

/// Minimal view over a received `ClientHello`.
pub struct ClientHelloView<'a> {
    pub server_name: Option<&'a str>,
    pub alpn: &'a [&'a [u8]],
    pub raw: &'a [u8],
}

/// A Quinn `ServerConfig` that defers committing to a final
/// `rustls::ServerConfig` until the `ClientHello` is available.
pub struct DeferredServerConfig {
    default_quic: Arc<QuicServerConfig>,
    selector: Selector,
}

impl DeferredServerConfig {
    pub fn new(
        default_rustls: Arc<rustls::ServerConfig>,
        selector: Selector,
    ) -> Result<Self, NoInitialCipherSuite> {
        let default_quic = Arc::new(QuicServerConfig::try_from(default_rustls)?);
        Ok(Self {
            default_quic,
            selector,
        })
    }
}

impl ServerConfig for DeferredServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        self.default_quic.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.default_quic.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        // Eagerly create a session from the default config. It serves two
        // purposes during the buffering phase:
        //   1. `Session::initial_keys` can delegate to it for retry handling.
        //   2. If selection is not needed (selector returns the default),
        //      we already have it ready.
        // Once the ClientHello is parsed and the selector returns a config,
        // we create a fresh session from that config, replay the buffered
        // CRYPTO bytes through it, then swap.
        let default_session = self.default_quic.clone().start_session(version, params);
        Box::new(DeferredSession {
            state: SessionState::Buffering {
                buffer: Vec::new(),
                default_session,
            },
            selector: self.selector.clone(),
            version,
            params: *params,
        })
    }
}

enum SessionState {
    /// Buffering CRYPTO bytes until the full ClientHello is available.
    /// `default_session` is kept so `Session::initial_keys` and similar
    /// pre-CH queries have a real implementation to delegate to.
    Buffering {
        buffer: Vec<u8>,
        default_session: Box<dyn Session>,
    },
    /// The selected rustls-backed session. From this point on, the
    /// `DeferredSession` is a transparent wrapper.
    Active(Box<dyn Session>),
}

pub struct DeferredSession {
    state: SessionState,
    selector: Selector,
    version: u32,
    params: TransportParameters,
}

impl Session for DeferredSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        match &self.state {
            SessionState::Buffering {
                default_session, ..
            } => default_session.initial_keys(dst_cid, side),
            SessionState::Active(s) => s.initial_keys(dst_cid, side),
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        match &self.state {
            SessionState::Active(s) => s.handshake_data(),
            SessionState::Buffering { .. } => None,
        }
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        match &self.state {
            SessionState::Active(s) => s.peer_identity(),
            SessionState::Buffering { .. } => None,
        }
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        match &self.state {
            SessionState::Active(s) => s.early_crypto(),
            SessionState::Buffering { .. } => None,
        }
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match &self.state {
            SessionState::Active(s) => s.early_data_accepted(),
            SessionState::Buffering { .. } => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        match &self.state {
            SessionState::Active(s) => s.is_handshaking(),
            SessionState::Buffering { .. } => true,
        }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        // While buffering, accumulate; once a full ClientHello is in,
        // call the selector, build a fresh session from the selected
        // config, replay the buffered bytes, and transition to Active.
        let next_state = match &mut self.state {
            SessionState::Active(s) => return s.read_handshake(buf),
            SessionState::Buffering { buffer, .. } => {
                buffer.extend_from_slice(buf);
                match parse::try_parse(buffer) {
                    Parse::Incomplete => return Ok(false),
                    Parse::Error(msg) => {
                        return Err(protocol_violation(msg));
                    }
                    Parse::Complete {
                        server_name, alpn, ..
                    } => {
                        let view = ClientHelloView {
                            server_name,
                            alpn: &alpn,
                            raw: buffer.as_slice(),
                        };
                        let selected_rustls = (self.selector)(&view);
                        let selected_quic =
                            QuicServerConfig::try_from(selected_rustls).map_err(|_| {
                                protocol_violation(
                                    "selected ServerConfig lacks a QUIC-compatible TLS 1.3 suite",
                                )
                            })?;
                        let new_session =
                            Arc::new(selected_quic).start_session(self.version, &self.params);
                        Box::new(new_session)
                    }
                }
            }
        };

        // We exited the borrow with `next_state` populated. Now take the
        // buffered bytes out, swap state, and replay them on the new
        // session in one go.
        let buffered = match std::mem::replace(&mut self.state, SessionState::Active(*next_state)) {
            SessionState::Buffering { buffer, .. } => buffer,
            // Unreachable because we returned early above for Active, and
            // `next_state` was only built in the Buffering branch.
            SessionState::Active(_) => unreachable!("state was Buffering above"),
        };

        let SessionState::Active(active) = &mut self.state else {
            unreachable!("just set Active");
        };
        active.read_handshake(&buffered)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match &self.state {
            SessionState::Active(s) => s.transport_parameters(),
            SessionState::Buffering { .. } => Ok(None),
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match &mut self.state {
            SessionState::Active(s) => s.write_handshake(buf),
            SessionState::Buffering { .. } => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        match &mut self.state {
            SessionState::Active(s) => s.next_1rtt_keys(),
            SessionState::Buffering { .. } => None,
        }
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        match &self.state {
            SessionState::Active(s) => s.is_valid_retry(orig_dst_cid, header, payload),
            SessionState::Buffering {
                default_session, ..
            } => default_session.is_valid_retry(orig_dst_cid, header, payload),
        }
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        match &self.state {
            SessionState::Active(s) => s.export_keying_material(output, label, context),
            SessionState::Buffering { .. } => Err(ExportKeyingMaterialError),
        }
    }
}
