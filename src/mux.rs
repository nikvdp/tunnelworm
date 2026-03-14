use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use async_channel::{Receiver, Sender};
use async_std::task;
use futures::{SinkExt, StreamExt, pin_mut};
use magic_wormhole::{
    forwarding,
    transit::{self, TransitRole},
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    persistent::PersistentRole,
    session::ConnectedSession,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelKind {
    PortForward,
    PortControl,
    Echo,
    Pipe,
    Shell,
    FileTransfer,
}

#[derive(Debug, Clone)]
pub struct IncomingChannel {
    pub kind: ChannelKind,
    pub open_payload: Vec<u8>,
    pub channel: MuxChannel,
}

#[derive(Debug, Clone)]
pub struct MuxChannel {
    id: u64,
    outgoing: Sender<WireFrame>,
    incoming: Receiver<ChannelEvent>,
}

pub struct MuxTransport {
    session: MuxSession,
    closed: Receiver<Option<String>>,
}

#[derive(Clone)]
pub struct MuxSession {
    inner: Arc<MuxInner>,
    incoming: Receiver<IncomingChannel>,
}

struct MuxInner {
    outgoing: Sender<WireFrame>,
    channels: Mutex<HashMap<u64, Sender<ChannelEvent>>>,
    next_channel_id: AtomicU64,
}

#[derive(Debug, Clone)]
enum ChannelEvent {
    Data(Vec<u8>),
    Closed,
}

#[derive(Debug, Clone)]
enum WireFrame {
    Open {
        channel_id: u64,
        kind: ChannelKind,
        open_payload: Vec<u8>,
    },
    Data {
        channel_id: u64,
        payload: Vec<u8>,
    },
    Close {
        channel_id: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum TransitMessage {
    Transit { hints: transit::Hints },
    Error { message: String },
}

impl MuxTransport {
    pub async fn connect(
        mut connected: ConnectedSession,
        role: PersistentRole,
    ) -> Result<Self> {
        let our_version: &forwarding::AppVersion = connected
            .wormhole
            .our_version()
            .downcast_ref()
            .expect("tunnelworm only uses the forwarding app version today");
        let peer_version: forwarding::AppVersion =
            serde_json::from_value(connected.peer_version.clone()).map_err(|error| {
                Error::Session(format!("could not parse the peer transit capabilities: {error}"))
            })?;

        let connector = transit::init(
            our_version.transit_abilities,
            Some(peer_version.transit_abilities),
            connected.relay_hints.clone(),
        )
        .await
        .map_err(|error| Error::Session(format!("could not initialize transit: {error}")))?;

        connected
            .wormhole
            .send_json(&TransitMessage::Transit {
                hints: (**connector.our_hints()).clone(),
            })
            .await?;

        let their_hints = match connected.wormhole.receive_json().await?? {
            TransitMessage::Transit { hints } => hints,
            TransitMessage::Error { message } => {
                return Err(Error::Session(format!(
                    "peer failed while setting up the live tunnel transport: {message}"
                )))
            },
        };

        let transit_role = match role {
            PersistentRole::Allocate => TransitRole::Leader,
            PersistentRole::Join => TransitRole::Follower,
        };
        let transit_key = connected
            .wormhole
            .key()
            .derive_subkey_from_purpose::<magic_wormhole::transit::TransitKey>(&format!(
                "{}/transit-key",
                connected.wormhole.appid()
            ));
        let (transit, _info) = connector
            .connect(
                transit_role,
                transit_key,
                peer_version.transit_abilities,
                std::sync::Arc::new(their_hints),
            )
            .await
            .map_err(|error| Error::Session(format!("could not connect live transit: {error}")))?;

        connected.wormhole.close().await?;

        let (sink, stream) = transit.split();
        let (outgoing_tx, outgoing_rx) = async_channel::unbounded::<WireFrame>();
        let (incoming_tx, incoming_rx) = async_channel::unbounded::<IncomingChannel>();
        let (closed_tx, closed_rx) = async_channel::bounded::<Option<String>>(1);
        let inner = Arc::new(MuxInner {
            outgoing: outgoing_tx.clone(),
            channels: Mutex::new(HashMap::new()),
            next_channel_id: AtomicU64::new(initial_channel_id(role)),
        });
        let closed_flag = Arc::new(AtomicBool::new(false));

        {
            let closed_tx = closed_tx.clone();
            let closed_flag = closed_flag.clone();
            task::spawn(async move {
                pin_mut!(sink);
                let result = async {
                    while let Ok(frame) = outgoing_rx.recv().await {
                        sink.send(frame.encode().into_boxed_slice())
                            .await
                            .map_err(|error| Error::Session(format!("live tunnel send failed: {error}")))?;
                    }
                    Ok::<(), Error>(())
                }
                .await;
                notify_closed(&closed_flag, &closed_tx, result.err().map(|error| error.to_string()))
                    .await;
            });
        }

        {
            let inner = inner.clone();
            let closed_tx = closed_tx.clone();
            let closed_flag = closed_flag.clone();
            task::spawn(async move {
                pin_mut!(stream);
                let result = async {
                    while let Some(record) = stream.next().await {
                        let record = record
                            .map_err(|error| Error::Session(format!("live tunnel receive failed: {error}")))?;
                        let frame = WireFrame::decode(&record)?;
                        match frame {
                            WireFrame::Open {
                                channel_id,
                                kind,
                                open_payload,
                            } => {
                                let (channel_tx, channel_rx) = async_channel::unbounded();
                                inner
                                    .channels
                                    .lock()
                                    .expect("channel map poisoned")
                                    .insert(channel_id, channel_tx);
                                let channel = MuxChannel {
                                    id: channel_id,
                                    outgoing: inner.outgoing.clone(),
                                    incoming: channel_rx,
                                };
                                incoming_tx
                                    .send(IncomingChannel {
                                        kind,
                                        open_payload,
                                        channel,
                                    })
                                    .await
                                    .map_err(|_| {
                                        Error::Session(
                                            "live tunnel incoming channel receiver shut down".into(),
                                        )
                                    })?;
                            },
                            WireFrame::Data { channel_id, payload } => {
                                let maybe_tx = inner
                                    .channels
                                    .lock()
                                    .expect("channel map poisoned")
                                    .get(&channel_id)
                                    .cloned();
                                if let Some(tx) = maybe_tx {
                                    let _ = tx.send(ChannelEvent::Data(payload)).await;
                                }
                            },
                            WireFrame::Close { channel_id } => {
                                let maybe_tx = inner
                                    .channels
                                    .lock()
                                    .expect("channel map poisoned")
                                    .remove(&channel_id);
                                if let Some(tx) = maybe_tx {
                                    let _ = tx.send(ChannelEvent::Closed).await;
                                }
                            },
                        }
                    }
                    Ok::<(), Error>(())
                }
                .await;
                notify_closed(
                    &closed_flag,
                    &closed_tx,
                    result.err().map(|error| error.to_string()).or_else(|| {
                        Some("live tunnel transport ended".into())
                    }),
                )
                .await;
            });
        }

        Ok(Self {
            session: MuxSession {
                inner,
                incoming: incoming_rx,
            },
            closed: closed_rx,
        })
    }

    pub fn session(&self) -> MuxSession {
        self.session.clone()
    }

    pub async fn wait_for_close(&self) -> Result<()> {
        match self.closed.recv().await {
            Ok(Some(message)) => Err(Error::Session(message)),
            Ok(None) | Err(_) => Ok(()),
        }
    }
}

impl MuxSession {
    pub async fn open_channel(
        &self,
        kind: ChannelKind,
        open_payload: Vec<u8>,
    ) -> Result<MuxChannel> {
        let channel_id = self.inner.next_channel_id.fetch_add(2, Ordering::SeqCst);
        let (channel_tx, channel_rx) = async_channel::unbounded();
        self.inner
            .channels
            .lock()
            .expect("channel map poisoned")
            .insert(channel_id, channel_tx);
        self.inner
            .outgoing
            .send(WireFrame::Open {
                channel_id,
                kind,
                open_payload,
            })
            .await
            .map_err(|_| Error::Session("live tunnel transport is not running".into()))?;
        Ok(MuxChannel {
            id: channel_id,
            outgoing: self.inner.outgoing.clone(),
            incoming: channel_rx,
        })
    }

    pub async fn next_incoming(&self) -> Result<IncomingChannel> {
        self.incoming
            .recv()
            .await
            .map_err(|_| Error::Session("live tunnel transport is not running".into()))
    }
}

impl MuxChannel {
    pub async fn send(&self, payload: Vec<u8>) -> Result<()> {
        self.outgoing
            .send(WireFrame::Data {
                channel_id: self.id,
                payload,
            })
            .await
            .map_err(|_| Error::Session("live tunnel transport is not running".into()))
    }

    pub async fn recv(&self) -> Result<Option<Vec<u8>>> {
        match self.incoming.recv().await {
            Ok(ChannelEvent::Data(payload)) => Ok(Some(payload)),
            Ok(ChannelEvent::Closed) => Ok(None),
            Err(_) => Ok(None),
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.outgoing
            .send(WireFrame::Close {
                channel_id: self.id,
            })
            .await
            .map_err(|_| Error::Session("live tunnel transport is not running".into()))
    }
}

fn initial_channel_id(role: PersistentRole) -> u64 {
    match role {
        PersistentRole::Allocate => 1,
        PersistentRole::Join => 2,
    }
}

async fn notify_closed(
    flag: &AtomicBool,
    closed_tx: &Sender<Option<String>>,
    message: Option<String>,
) {
    if !flag.swap(true, Ordering::SeqCst) {
        let _ = closed_tx.send(message).await;
    }
}

impl WireFrame {
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Open {
                channel_id,
                kind,
                open_payload,
            } => {
                let mut bytes = Vec::with_capacity(1 + 8 + 1 + 4 + open_payload.len());
                bytes.push(0);
                bytes.extend_from_slice(&channel_id.to_be_bytes());
                bytes.push(kind_code(kind));
                bytes.extend_from_slice(&(open_payload.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&open_payload);
                bytes
            },
            Self::Data { channel_id, payload } => {
                let mut bytes = Vec::with_capacity(1 + 8 + 4 + payload.len());
                bytes.push(1);
                bytes.extend_from_slice(&channel_id.to_be_bytes());
                bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&payload);
                bytes
            },
            Self::Close { channel_id } => {
                let mut bytes = Vec::with_capacity(1 + 8);
                bytes.push(2);
                bytes.extend_from_slice(&channel_id.to_be_bytes());
                bytes
            },
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let tag = *bytes.first().ok_or_else(|| {
            Error::Session("received an empty live tunnel frame".into())
        })?;
        match tag {
            0 => {
                let channel_id = read_u64(bytes, 1)?;
                let kind = decode_kind(*bytes.get(9).ok_or_else(|| {
                    Error::Session("open frame is missing the channel kind".into())
                })?)?;
                let payload_len = read_u32(bytes, 10)? as usize;
                let payload = bytes
                    .get(14..14 + payload_len)
                    .ok_or_else(|| {
                        Error::Session("open frame payload is truncated".into())
                    })?
                    .to_vec();
                Ok(Self::Open {
                    channel_id,
                    kind,
                    open_payload: payload,
                })
            },
            1 => {
                let channel_id = read_u64(bytes, 1)?;
                let payload_len = read_u32(bytes, 9)? as usize;
                let payload = bytes
                    .get(13..13 + payload_len)
                    .ok_or_else(|| {
                        Error::Session("data frame payload is truncated".into())
                    })?
                    .to_vec();
                Ok(Self::Data { channel_id, payload })
            },
            2 => Ok(Self::Close {
                channel_id: read_u64(bytes, 1)?,
            }),
            other => Err(Error::Session(format!(
                "received an unknown live tunnel frame tag {other}"
            ))),
        }
    }
}

fn kind_code(kind: ChannelKind) -> u8 {
    match kind {
        ChannelKind::PortForward => 0,
        ChannelKind::PortControl => 1,
        ChannelKind::Echo => 2,
        ChannelKind::Pipe => 3,
        ChannelKind::Shell => 4,
        ChannelKind::FileTransfer => 5,
    }
}

fn decode_kind(code: u8) -> Result<ChannelKind> {
    match code {
        0 => Ok(ChannelKind::PortForward),
        1 => Ok(ChannelKind::PortControl),
        2 => Ok(ChannelKind::Echo),
        3 => Ok(ChannelKind::Pipe),
        4 => Ok(ChannelKind::Shell),
        5 => Ok(ChannelKind::FileTransfer),
        other => Err(Error::Session(format!(
            "received an unknown live tunnel channel kind {other}"
        ))),
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| Error::Session("frame is truncated".into()))?;
    let mut array = [0u8; 8];
    array.copy_from_slice(slice);
    Ok(u64::from_be_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Session("frame is truncated".into()))?;
    let mut array = [0u8; 4];
    array.copy_from_slice(slice);
    Ok(u32::from_be_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::{ChannelKind, WireFrame};

    #[test]
    fn open_frame_round_trips() {
        let frame = WireFrame::Open {
            channel_id: 7,
            kind: ChannelKind::Pipe,
            open_payload: b"hello".to_vec(),
        };
        let encoded = frame.clone().encode();
        let decoded = WireFrame::decode(&encoded).expect("frame should decode");
        match decoded {
            WireFrame::Open {
                channel_id,
                kind,
                open_payload,
            } => {
                assert_eq!(channel_id, 7);
                assert_eq!(kind, ChannelKind::Pipe);
                assert_eq!(open_payload, b"hello");
            },
            other => panic!("decoded the wrong frame: {other:?}"),
        }
    }

    #[test]
    fn data_frame_round_trips() {
        let frame = WireFrame::Data {
            channel_id: 42,
            payload: vec![1, 2, 3, 4],
        };
        let encoded = frame.clone().encode();
        let decoded = WireFrame::decode(&encoded).expect("frame should decode");
        match decoded {
            WireFrame::Data { channel_id, payload } => {
                assert_eq!(channel_id, 42);
                assert_eq!(payload, vec![1, 2, 3, 4]);
            },
            other => panic!("decoded the wrong frame: {other:?}"),
        }
    }
}
