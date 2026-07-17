//! IpcEncodedSource — consumes an already-encoded bitstream produced by an
//! external helper process (e.g. a hardware encoder running under a
//! different libc/toolchain) over a local Unix domain socket, and bridges
//! it into the liveion RTP / WHEP infrastructure exactly like
//! `NativeEncodedSource` does for the FFI-based `livehal` path.
//!
//! This exists so liveion itself never has to link against vendor
//! hardware-codec libraries directly: the encoder helper is a separate
//! process (potentially built with a different libc/toolchain than
//! liveion), and only compressed bitstream bytes cross the process
//! boundary.
//!
//! Data flow:
//!   encoder helper process --(Unix domain socket, framed messages)-->
//!   IpcEncodedSource --(codec-specific RTP packetize)--> RTP broadcast
//!
//! liveion is the client: it connects out to `socket_path` and reconnects
//! automatically if the encoder helper is not yet listening or the
//! connection drops (mirroring `RtspSource`'s reconnect behavior).
//!
//! ## Wire format
//!
//! Each message is a fixed 25-byte header followed by `data_len` payload
//! bytes:
//!
//! ```text
//! offset  size  field
//! 0       1     codec       (matches source_config::VideoCodec numeric value)
//! 1       4     flags       (u32 LE, bit 0 = keyframe; currently informational)
//! 5       8     pts_us      (u64 LE, presentation timestamp, microseconds)
//! 13      8     dts_us      (u64 LE, decode timestamp, microseconds)
//! 21      4     data_len    (u32 LE)
//! 25      ..    data        (data_len bytes, Annex-B bitstream for H.264/H.265)
//! ```

use super::source_config::IpcSourceSpec;
use super::{
    MediaPacket, StateChangeEvent, StreamSource, StreamSourceState, h264_util::scan_sps_profile,
    source_config::VideoCodec,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use rtc_rtp::codec::av1::Av1Payloader;
use rtc_rtp::codec::h264::H264Payloader;
use rtc_rtp::codec::h265::HevcPayloader;
use rtc_rtp::codec::vp8::Vp8Payloader;
use rtc_rtp::codec::vp9::Vp9Payloader;
use rtc_rtp::packetizer::{Packetizer as _, Payloader, new_packetizer};
use rtc_rtp::sequence::new_random_sequencer;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};

const HEADER_LEN: usize = 25;
/// Sanity cap on a single encoded frame's size, to fail fast on a
/// desynchronized/corrupt stream instead of trying to allocate a bogus
/// amount of memory.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;
const RECONNECT_INTERVAL_MS: u64 = 1000;

struct RemoteEncodedPacket {
    flags: u32,
    pts_us: u64,
    data: Vec<u8>,
}

/// Read one framed packet from the socket. Returns `Ok(None)` on a clean
/// EOF (peer closed the connection).
async fn read_packet(stream: &mut UnixStream) -> Result<Option<RemoteEncodedPacket>> {
    let mut header = [0u8; HEADER_LEN];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading IPC packet header"),
    }

    let flags = u32::from_le_bytes(header[1..5].try_into().unwrap());
    let pts_us = u64::from_le_bytes(header[5..13].try_into().unwrap());
    let data_len = u32::from_le_bytes(header[21..25].try_into().unwrap());
    if data_len > MAX_FRAME_LEN {
        anyhow::bail!(
            "IPC frame length {} exceeds sanity cap {}, treating stream as desynchronized",
            data_len,
            MAX_FRAME_LEN
        );
    }

    let mut data = vec![0u8; data_len as usize];
    stream
        .read_exact(&mut data)
        .await
        .context("reading IPC packet payload")?;

    Ok(Some(RemoteEncodedPacket {
        flags,
        pts_us,
        data,
    }))
}

pub struct IpcEncodedSource {
    spec: IpcSourceSpec,
    codec: VideoCodec,
    state: Arc<RwLock<StreamSourceState>>,
    rtp_tx: broadcast::Sender<MediaPacket>,
    state_tx: broadcast::Sender<StateChangeEvent>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "source")]
    dynamic_profile: Arc<RwLock<Option<String>>>,
}

impl IpcEncodedSource {
    pub fn new(spec: IpcSourceSpec) -> Result<Self> {
        spec.validate()?;
        let codec = super::source_config::video_codec_from_str(&spec.codec)?;
        let (rtp_tx, _) = broadcast::channel(1024);
        let (state_tx, _) = broadcast::channel(16);

        Ok(Self {
            spec,
            codec,
            state: Arc::new(RwLock::new(StreamSourceState::Initializing)),
            rtp_tx,
            state_tx,
            shutdown_tx: None,
            task_handle: None,
            #[cfg(feature = "source")]
            dynamic_profile: Arc::new(RwLock::new(None)),
        })
    }

    async fn emit_state_change(
        state: &Arc<RwLock<StreamSourceState>>,
        state_tx: &broadcast::Sender<StateChangeEvent>,
        new_state: StreamSourceState,
        error: Option<String>,
    ) {
        let mut s = state.write().await;
        let old_state = *s;
        if old_state != new_state {
            *s = new_state;
            let _ = state_tx.send(StateChangeEvent {
                old_state,
                new_state,
                error: error.clone(),
            });
            info!(
                "state: {:?} -> {:?}{}",
                old_state,
                new_state,
                error.map(|e| format!(" ({e})")).unwrap_or_default()
            );
        }
    }

    /// Connect-read-reconnect loop. Runs until `shutdown_rx` fires.
    #[allow(clippy::too_many_arguments)]
    async fn run(
        stream_id: String,
        socket_path: String,
        codec: VideoCodec,
        payload_type: u8,
        clock_rate: u32,
        rtp_tx: broadcast::Sender<MediaPacket>,
        state: Arc<RwLock<StreamSourceState>>,
        state_tx: broadcast::Sender<StateChangeEvent>,
        #[cfg(feature = "source")] dynamic_profile: Arc<RwLock<Option<String>>>,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) {
        // Fallback RTP timestamp delta for the very rare case of a
        // non-monotonic pts_us from the encoder helper (mirrors
        // NativeEncodedSource's handling). 30fps is a reasonable generic
        // default; exact fps doesn't matter much since this only covers
        // brief PTS regressions, not steady-state playback.
        const FALLBACK_DELTA: u32 = 90000 / 30;

        let payloader: Box<dyn Payloader> = match codec {
            VideoCodec::H265 => Box::new(HevcPayloader),
            VideoCodec::Av1 => Box::new(Av1Payloader::default()),
            VideoCodec::Vp8 => Box::new(Vp8Payloader::default()),
            VideoCodec::Vp9 => Box::new(Vp9Payloader::default()),
            VideoCodec::H264 => Box::new(H264Payloader::default()),
        };
        let sequencer = Box::new(new_random_sequencer());
        let ssrc: u32 = rand::random();
        let mut packetizer =
            new_packetizer(1400, payload_type, ssrc, payloader, sequencer, clock_rate);
        let mut last_rtp_ts: Option<u32> = None;
        static DBG_COUNT: AtomicU64 = AtomicU64::new(0);

        let mut reconnect_count = 0u32;

        loop {
            Self::emit_state_change(
                &state,
                &state_tx,
                if reconnect_count > 0 {
                    StreamSourceState::Reconnecting
                } else {
                    StreamSourceState::Initializing
                },
                None,
            )
            .await;

            debug!("[{}] connecting to {}", stream_id, socket_path);
            let mut stream = match UnixStream::connect(&socket_path).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("[{}] connect failed: {}", stream_id, e);
                    Self::emit_state_change(
                        &state,
                        &state_tx,
                        StreamSourceState::Disconnected,
                        Some(format!("connect failed: {e}")),
                    )
                    .await;
                    reconnect_count += 1;

                    if let Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) =
                        shutdown_rx.try_recv()
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(RECONNECT_INTERVAL_MS))
                        .await;
                    continue;
                }
            };

            info!("[{}] connected", stream_id);
            Self::emit_state_change(&state, &state_tx, StreamSourceState::Connected, None).await;
            reconnect_count = 0;

            let disconnect_reason = loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        info!("[{}] shutdown requested", stream_id);
                        return;
                    }
                    result = read_packet(&mut stream) => {
                        match result {
                            Ok(Some(pkt)) => {
                                let n = DBG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                                if n.is_multiple_of(60) {
                                    tracing::trace!(
                                        "[IpcEncodedSource] packet bytes={} count={}",
                                        pkt.data.len(), n
                                    );
                                }

                                let rtp_ts = if pkt.pts_us > 0 {
                                    ((pkt.pts_us as u128 * 9) / 100) as u32
                                } else {
                                    0u32
                                };
                                let delta = match last_rtp_ts {
                                    Some(prev) if rtp_ts > prev => rtp_ts - prev,
                                    Some(_prev) => FALLBACK_DELTA,
                                    None => 0,
                                };
                                last_rtp_ts = Some(rtp_ts);
                                let _ = pkt.flags; // reserved for future use (e.g. keyframe hints)

                                #[cfg(feature = "source")]
                                if codec == VideoCodec::H264 {
                                    let needs_update = {
                                        let guard = dynamic_profile.read().await;
                                        guard.as_ref().is_none()
                                    };
                                    if needs_update
                                        && let Some(profile) = scan_sps_profile(&pkt.data)
                                    {
                                        let mut guard = dynamic_profile.write().await;
                                        if guard.as_ref() != Some(&profile) {
                                            *guard = Some(profile);
                                        }
                                    }
                                }

                                match packetizer.packetize(&pkt.data.into(), delta) {
                                    Ok(packets) => {
                                        for packet in packets {
                                            let _ = rtp_tx.send(MediaPacket::RtpPacket(Arc::new(packet)));
                                        }
                                    }
                                    Err(e) => {
                                        warn!("[{}] RTP packetize error: {}", stream_id, e);
                                    }
                                }
                            }
                            Ok(None) => {
                                break Some("encoder helper closed the connection".to_string());
                            }
                            Err(e) => {
                                error!("[{}] IPC read error: {}", stream_id, e);
                                break Some(e.to_string());
                            }
                        }
                    }
                }
            };

            Self::emit_state_change(
                &state,
                &state_tx,
                StreamSourceState::Disconnected,
                disconnect_reason,
            )
            .await;
            reconnect_count += 1;

            if let Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) =
                shutdown_rx.try_recv()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(RECONNECT_INTERVAL_MS)).await;
        }

        Self::emit_state_change(&state, &state_tx, StreamSourceState::Disconnected, None).await;
        info!("[{}] task exited", stream_id);
    }
}

#[async_trait]
impl StreamSource for IpcEncodedSource {
    fn stream_id(&self) -> &str {
        &self.spec.stream_id
    }

    fn state(&self) -> StreamSourceState {
        *self.state.blocking_read()
    }

    async fn start(&mut self) -> Result<()> {
        if self.task_handle.is_some() {
            anyhow::bail!("Already started");
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let handle = tokio::spawn(Self::run(
            self.spec.stream_id.clone(),
            self.spec.socket_path.clone(),
            self.codec,
            self.spec.output.payload_type,
            self.spec.output.clock_rate,
            self.rtp_tx.clone(),
            self.state.clone(),
            self.state_tx.clone(),
            #[cfg(feature = "source")]
            self.dynamic_profile.clone(),
            shutdown_rx,
        ));
        self.task_handle = Some(handle);

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        }
        Self::emit_state_change(
            &self.state,
            &self.state_tx,
            StreamSourceState::Disconnected,
            None,
        )
        .await;
        Ok(())
    }

    fn subscribe_rtp(&self) -> broadcast::Receiver<MediaPacket> {
        self.rtp_tx.subscribe()
    }

    fn subscribe_state(&self) -> broadcast::Receiver<StateChangeEvent> {
        self.state_tx.subscribe()
    }

    #[cfg(feature = "source")]
    async fn get_video_codec(
        &self,
    ) -> Option<rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters> {
        use rtc::rtp_transceiver::rtp_sender::{RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters};

        let mime_type = format!("video/{}", self.spec.codec.to_uppercase());
        let sdp_fmtp_line = match self.codec {
            VideoCodec::H264 => {
                let profile = self
                    .dynamic_profile
                    .read()
                    .await
                    .clone()
                    .unwrap_or_else(|| self.spec.profile.clone());
                format!(
                    "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id={}",
                    profile
                )
            }
            VideoCodec::H265 => "profile-id=1;tier-flag=0;level-id=93".to_string(),
            _ => String::new(),
        };

        Some(RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type,
                clock_rate: self.spec.output.clock_rate,
                channels: 0,
                sdp_fmtp_line,
                rtcp_feedback: vec![
                    RTCPFeedback {
                        typ: "goog-remb".into(),
                        parameter: "".into(),
                    },
                    RTCPFeedback {
                        typ: "nack".into(),
                        parameter: "".into(),
                    },
                    RTCPFeedback {
                        typ: "nack".into(),
                        parameter: "pli".into(),
                    },
                ],
            },
            payload_type: self.spec.output.payload_type,
        })
    }

    #[cfg(feature = "source")]
    async fn get_audio_codec(
        &self,
    ) -> Option<rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters> {
        None
    }
}

// Silence unused-import warning when the `write_packet` helper below isn't
// referenced by any non-test code path yet (it is intended for the encoder
// helper side, kept here for now since it must stay in lockstep with
// `read_packet`'s framing; will move to a shared `libs/` crate once the
// encoder helper process is scaffolded).
#[allow(dead_code)]
async fn write_packet(
    stream: &mut UnixStream,
    codec: VideoCodec,
    flags: u32,
    pts_us: u64,
    dts_us: u64,
    data: &[u8],
) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    header[0] = codec as u8;
    header[1..5].copy_from_slice(&flags.to_le_bytes());
    header[5..13].copy_from_slice(&pts_us.to_le_bytes());
    header[13..21].copy_from_slice(&dts_us.to_le_bytes());
    header[21..25].copy_from_slice(&(data.len() as u32).to_le_bytes());
    stream.write_all(&header).await?;
    stream.write_all(data).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_packet_framing() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let payload = vec![0xAAu8; 1234];
        let payload_clone = payload.clone();

        let writer = tokio::spawn(async move {
            write_packet(&mut a, VideoCodec::H264, 1, 1_000_000, 999_000, &payload_clone)
                .await
                .unwrap();
        });

        let pkt = read_packet(&mut b).await.unwrap().unwrap();
        writer.await.unwrap();

        assert_eq!(pkt.flags, 1);
        assert_eq!(pkt.pts_us, 1_000_000);
        assert_eq!(pkt.data, payload);
    }

    #[tokio::test]
    async fn clean_eof_yields_none() {
        let (a, mut b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(read_packet(&mut b).await.unwrap().is_none());
    }

    #[test]
    fn ipc_spec_validate() {
        let spec = IpcSourceSpec {
            stream_id: "cam0".into(),
            socket_path: "/run/radarcam/encoder-cam0.sock".into(),
            codec: "h264".into(),
            profile: "42001f".into(),
            output: super::super::source_config::OutputSpec::default(),
        };
        assert!(spec.validate().is_ok());

        let mut bad = spec.clone();
        bad.socket_path = "".into();
        assert!(bad.validate().is_err());

        let mut bad_codec = spec;
        bad_codec.codec = "mp3".into();
        assert!(bad_codec.validate().is_err());
    }
}
