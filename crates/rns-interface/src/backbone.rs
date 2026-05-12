//! High-throughput HDLC-over-TCP backbone. Server accepts many peers
//! (each its own [`InterfaceHandle`]); client auto-reconnects.
//! Per-peer tuning: TCP keepalive + TCP_USER_TIMEOUT + NODELAY + large
//! buffers. Inbound deframer is capped (vs Python's unbounded) to avoid
//! malformed-peer memory blow-up.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::hdlc;
use crate::socket_tuning::{iface_addr_for, set_keepalive_tuned, set_socket_buffers};
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

/// 1 MiB MTU — also the SO_RCVBUF/SNDBUF target (kernel clamps).
pub const HW_MTU: u32 = 1_048_576;

/// Listener-side bitrate guess advertised on the parent handle.
pub const BITRATE_GUESS: u64 = 1_000_000_000;

/// Per-peer guess (100 Mbps) — drives [`crate::traits::optimise_mtu`] → 64 KiB MTU.
pub const CHILD_BITRATE_GUESS: u64 = 100_000_000;

pub const RECONNECT_WAIT: u64 = 5;
pub const INITIAL_CONNECT_TIMEOUT: u64 = 5;

pub const TCP_PROBE_AFTER: u32 = 5;
pub const TCP_PROBE_INTERVAL: u32 = 2;
pub const TCP_PROBES: u32 = 12;
/// Linux TCP_USER_TIMEOUT — drops stuck conns when peer goes silent without RST.
pub const TCP_USER_TIMEOUT: u32 = 24;

const TX_CHANNEL_DEPTH: usize = 1024;

#[derive(Debug, Clone)]
pub struct BackboneServerConfig {
    pub name: String,
    pub listen_ip: String,
    pub listen_port: u16,
    pub prefer_ipv6: bool,
    pub mode: InterfaceMode,
    /// Optional kernel ifname; binds to its current IP (falls back to `listen_ip`).
    pub device: Option<String>,
}

impl BackboneServerConfig {
    pub fn new(name: &str, ip: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            listen_ip: ip.to_string(),
            listen_port: port,
            prefer_ipv6: false,
            mode: InterfaceMode::Full,
            device: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackboneClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub prefer_ipv6: bool,
    pub connect_timeout_secs: u64,
    pub max_reconnect_tries: Option<usize>,
    pub mode: InterfaceMode,
}

impl BackboneClientConfig {
    pub fn new(name: &str, host: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            target_host: host.to_string(),
            target_port: port,
            prefer_ipv6: false,
            connect_timeout_secs: INITIAL_CONNECT_TIMEOUT,
            max_reconnect_tries: None,
            mode: InterfaceMode::Full,
        }
    }
}

fn keepalive_durations() -> (Duration, Duration, u32, Duration) {
    (
        Duration::from_secs(TCP_PROBE_AFTER as u64),
        Duration::from_secs(TCP_PROBE_INTERVAL as u64),
        TCP_PROBES,
        Duration::from_secs(TCP_USER_TIMEOUT as u64),
    )
}

fn tune_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let (idle, intvl, retries, user_timeout) = keepalive_durations();
    set_keepalive_tuned(stream, idle, intvl, retries, user_timeout);
    set_socket_buffers(stream, HW_MTU as usize);
}

fn child_mtu() -> u32 {
    crate::traits::optimise_mtu(CHILD_BITRATE_GUESS)
        .map(|m| m.min(HW_MTU))
        .unwrap_or(rns_wire::constants::MTU as u32)
}

async fn backbone_read_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    interface_id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
) {
    let mut deframer = hdlc::HdlcDeframer::new();
    // Large buffer to amortise syscalls; inbound capped by HdlcDeframer::MAX_FRAME_SIZE.
    let mut buf = vec![0u8; 65536];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                tracing::info!(interface_id, "backbone read: EOF");
                break;
            }
            Ok(n) => {
                rxb.fetch_add(n as u64, Ordering::Relaxed);
                for frame in deframer.feed(&buf[..n]) {
                    if frame.is_empty() {
                        continue;
                    }
                    let msg = TransportMessage::Inbound(InboundPacket {
                        raw: Bytes::from(frame),
                        interface_id,
                        rssi: None,
                        snr: None,
                        q: None,
                    });
                    if transport_tx.send(msg).await.is_err() {
                        tracing::warn!(interface_id, "transport channel closed");
                        online.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(interface_id, error = %e, "backbone read error");
                break;
            }
        }
    }
    online.store(false, Ordering::SeqCst);
}

async fn backbone_write_loop(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Bytes>,
    online: Arc<AtomicBool>,
    txb: Arc<AtomicU64>,
) {
    while let Some(data) = rx.recv().await {
        let framed = hdlc::frame(&data);
        txb.fetch_add(framed.len() as u64, Ordering::Relaxed);
        if let Err(e) = writer.write_all(&framed).await {
            tracing::warn!(error = %e, "backbone write error");
            break;
        }
    }
    online.store(false, Ordering::SeqCst);
}

/// `device` takes precedence over `listen_ip` when its lookup succeeds.
fn resolve_listen_addr(config: &BackboneServerConfig) -> String {
    if let Some(name) = config.device.as_deref() {
        match iface_addr_for(name, config.prefer_ipv6) {
            Some(IpAddr::V4(v4)) => return v4.to_string(),
            Some(IpAddr::V6(v6)) => return format!("[{}]", v6),
            None => {
                tracing::warn!(
                    device = %name,
                    listen_ip = %config.listen_ip,
                    "backbone: device lookup failed, falling back to listen_ip",
                );
            }
        }
    }
    config.listen_ip.clone()
}

/// Resolve `host:port` preferring the configured address family.
async fn resolve_target(
    host: &str,
    port: u16,
    prefer_ipv6: bool,
) -> std::io::Result<std::net::SocketAddr> {
    let mut addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {host}:{port}"),
        ));
    }
    // Prefer the requested family; else first resolved.
    let preferred = if prefer_ipv6 {
        addrs.iter().find(|a| a.is_ipv6()).copied()
    } else {
        addrs.iter().find(|a| a.is_ipv4()).copied()
    };
    Ok(preferred.unwrap_or_else(|| addrs.remove(0)))
}

/// Spawn a backbone server; each accepted connection becomes an `InterfaceHandle`.
pub async fn spawn_backbone_server(
    config: BackboneServerConfig,
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let listen_ip = resolve_listen_addr(&config);
    let bind_addr = if listen_ip.starts_with('[') {
        format!("{}:{}", listen_ip, config.listen_port)
    } else if listen_ip.contains(':') && !listen_ip.contains('.') {
        format!("[{}]:{}", listen_ip, config.listen_port)
    } else {
        format!("{}:{}", listen_ip, config.listen_port)
    };
    let listener = TcpListener::bind(&bind_addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(name = %config.name, addr = %local_addr, "backbone server listening");

    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let name = config.name.clone();
    let mode = config.mode;

    // Parent listener is inbound-only; drain task warns on stray writes.
    let (tx, mut listener_rx) = mpsc::channel::<Bytes>(1);
    let drain_name = name.clone();
    tokio::spawn(async move {
        while listener_rx.recv().await.is_some() {
            tracing::warn!(
                name = %drain_name,
                "backbone listener tx received unexpected outbound data; dropping",
            );
        }
    });

    let read_task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                    let client_name = format!("{}/client_{}", config.name, client_id);
                    tracing::info!(
                        name = %client_name,
                        peer = %peer,
                        "backbone: accepted connection",
                    );

                    tune_stream(&stream);

                    let c_online = Arc::new(AtomicBool::new(true));
                    let c_rxb = Arc::new(AtomicU64::new(0));
                    let c_txb = Arc::new(AtomicU64::new(0));
                    let (c_tx, c_rx) = mpsc::channel::<Bytes>(TX_CHANNEL_DEPTH);
                    let (reader, writer) = stream.into_split();

                    let c_online_w = c_online.clone();
                    let c_txb_w = c_txb.clone();
                    tokio::spawn(backbone_write_loop(writer, c_rx, c_online_w, c_txb_w));

                    let c_online_r = c_online.clone();
                    let c_rxb_r = c_rxb.clone();
                    let transport_tx2 = transport_tx.clone();
                    let dereg_tx = transport_tx.clone();
                    let cname = client_name.clone();
                    let read_handle = tokio::spawn(async move {
                        backbone_read_loop(reader, client_id, transport_tx2, c_online_r, c_rxb_r)
                            .await;
                        tracing::info!(name = %cname, "backbone client disconnected");
                        // Proactive notify so broadcasts don't target dead tx.
                        let _ = dereg_tx
                            .send(TransportMessage::DeregisterInterface { id: client_id })
                            .await;
                    });

                    let handle = InterfaceHandle {
                        id: client_id,
                        parent_id: Some(id),
                        name: client_name,
                        mode,
                        direction: InterfaceDirection {
                            inbound: true,
                            outbound: true,
                            forward: false,
                            repeat: false,
                        },
                        bitrate: CHILD_BITRATE_GUESS,
                        mtu: child_mtu(),
                        online: c_online,
                        rxb: Some(c_rxb),
                        txb: Some(c_txb),
                        tx: c_tx,
                        read_task: read_handle,
                    };
                    if handle_tx.send(handle).await.is_err() {
                        tracing::warn!("backbone handle registry closed");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "backbone accept error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        online2.store(false, Ordering::SeqCst);
    });

    Ok(InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: false,
            forward: false,
            repeat: false,
        },
        bitrate: BITRATE_GUESS,
        mtu: rns_wire::constants::MTU as u32,
        online,
        rxb: Some(Arc::new(AtomicU64::new(0))),
        txb: Some(Arc::new(AtomicU64::new(0))),
        tx,
        read_task,
    })
}

pub async fn spawn_backbone_client(
    config: BackboneClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let online = Arc::new(AtomicBool::new(false));
    let online2 = online.clone();
    let (tx, rx) = mpsc::channel::<Bytes>(TX_CHANNEL_DEPTH);
    let name = config.name.clone();
    let mode = config.mode;
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();

    let read_task = tokio::spawn(async move {
        let max_tries = config.max_reconnect_tries;
        let mut tries: usize = 0;

        loop {
            let target = match tokio::time::timeout(
                Duration::from_secs(config.connect_timeout_secs),
                resolve_target(&config.target_host, config.target_port, config.prefer_ipv6),
            )
            .await
            {
                Ok(Ok(addr)) => addr,
                Ok(Err(e)) => {
                    tracing::warn!(name = %config.name, error = %e, "backbone resolve failed");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
                Err(_) => {
                    tracing::warn!(name = %config.name, "backbone resolve timed out");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
            };

            let stream = match tokio::time::timeout(
                Duration::from_secs(config.connect_timeout_secs),
                TcpStream::connect(target),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::warn!(name = %config.name, error = %e, "backbone connect failed");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
                Err(_) => {
                    tracing::warn!(name = %config.name, "backbone connect timed out");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
            };

            tune_stream(&stream);
            online2.store(true, Ordering::SeqCst);
            tries = 0;

            let c_online = Arc::new(AtomicBool::new(true));
            let (reader, writer) = stream.into_split();

            let (conn_tx, conn_rx) = mpsc::channel::<Bytes>(TX_CHANNEL_DEPTH);
            let c_online_w = c_online.clone();
            let c_txb = task_txb.clone();
            let write_handle =
                tokio::spawn(backbone_write_loop(writer, conn_rx, c_online_w, c_txb));

            let rx_ref = rx.clone();
            let fwd_handle = tokio::spawn(async move {
                let mut guard = rx_ref.lock().await;
                while let Some(data) = guard.recv().await {
                    if conn_tx.send(data).await.is_err() {
                        break;
                    }
                }
            });

            let c_online_r = c_online.clone();
            let c_rxb = task_rxb.clone();
            backbone_read_loop(reader, id, transport_tx.clone(), c_online_r, c_rxb).await;

            online2.store(false, Ordering::SeqCst);
            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            if let Some(max) = max_tries {
                tries += 1;
                if tries >= max {
                    let _ = transport_tx
                        .send(TransportMessage::DeregisterInterface { id })
                        .await;
                    return;
                }
            }
            tracing::info!(
                name = %config.name,
                "backbone: reconnecting in {}s",
                RECONNECT_WAIT,
            );
            tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
        }
    });

    Ok(InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate: CHILD_BITRATE_GUESS,
        mtu: child_mtu(),
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backbone_server_config() {
        let cfg = BackboneServerConfig::new("backbone0", "0.0.0.0", 4243);
        assert_eq!(cfg.listen_port, 4243);
        assert!(!cfg.prefer_ipv6);
        assert!(cfg.device.is_none());
    }

    #[test]
    fn test_backbone_client_config() {
        let cfg = BackboneClientConfig::new("bb-client", "10.0.0.1", 4243);
        assert_eq!(cfg.target_host, "10.0.0.1");
        assert_eq!(cfg.connect_timeout_secs, INITIAL_CONNECT_TIMEOUT);
    }

    #[test]
    fn test_constants() {
        assert_eq!(HW_MTU, 1_048_576);
        assert_eq!(BITRATE_GUESS, 1_000_000_000);
        assert_eq!(CHILD_BITRATE_GUESS, 100_000_000);
        assert_eq!(RECONNECT_WAIT, 5);
    }

    #[test]
    fn test_backbone_server_config_mode() {
        let cfg = BackboneServerConfig::new("bb-srv", "0.0.0.0", 4243);
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert_eq!(cfg.listen_ip, "0.0.0.0");
        assert_eq!(cfg.name, "bb-srv");
    }

    #[test]
    fn test_backbone_client_config_defaults() {
        let cfg = BackboneClientConfig::new("bb-cli", "192.168.1.1", 4243);
        assert_eq!(cfg.target_host, "192.168.1.1");
        assert_eq!(cfg.target_port, 4243);
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert!(cfg.max_reconnect_tries.is_none());
    }

    #[test]
    fn test_backbone_config_ipv6() {
        let cfg = BackboneServerConfig::new("bb-v6", "::", 4243);
        assert!(!cfg.prefer_ipv6);
        let mut cfg = cfg;
        cfg.prefer_ipv6 = true;
        assert!(cfg.prefer_ipv6);
    }

    #[test]
    fn test_child_mtu_uses_100mbps_curve() {
        // optimise_mtu(100 Mbps) is one of the step values; verify the
        // result lands inside the HW_MTU ceiling.
        let mtu = child_mtu();
        assert!(mtu <= HW_MTU);
        assert!(mtu >= rns_wire::constants::MTU as u32 / 2);
    }

    #[tokio::test]
    async fn test_backbone_max_reconnect_dereg() {
        // Connect attempts to a port nobody is listening on; with
        // max_reconnect_tries = Some(1) we get one connect attempt, one
        // failure, then DeregisterInterface and exit.
        let mut cfg = BackboneClientConfig::new("bb-dereg", "127.0.0.1", 1);
        cfg.connect_timeout_secs = 1;
        cfg.max_reconnect_tries = Some(1);

        let (tx, mut rx) = mpsc::channel::<TransportMessage>(8);
        let handle = spawn_backbone_client(cfg, 99, tx).await.unwrap();
        // Wait for the read_task to finish — guarded by a generous timeout
        // to absorb the one RECONNECT_WAIT sleep + connect attempt.
        let dereg = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                match rx.recv().await {
                    Some(TransportMessage::DeregisterInterface { id }) => return Some(id),
                    Some(_) => continue,
                    None => return None,
                }
            }
        })
        .await
        .ok()
        .flatten();
        assert_eq!(dereg, Some(99));
        // Drop the handle (aborts read_task if still alive).
        drop(handle);
    }

    #[tokio::test]
    async fn test_resolve_target_loopback_v4() {
        let addr = resolve_target("127.0.0.1", 1234, false).await.unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 1234);
    }
}
