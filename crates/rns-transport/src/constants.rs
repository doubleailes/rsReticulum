/// Maximum hop count. Announces and forwarded packets exceeding this are
/// dropped at the inbound boundary. Mirrors Python `Transport.PATHFINDER_M`.
pub const PATHFINDER_M: u8 = 128;

/// Number of retransmit retries for announces.
pub const PATHFINDER_R: u8 = 1;

/// Grace period (seconds) before announce retry.
pub const PATHFINDER_G: f64 = 5.0;

/// Random window for announce rebroadcast jitter.
pub const PATHFINDER_RW: f64 = 0.5;

/// Default path expiry (7 days, in seconds).
pub const PATHFINDER_E: u64 = 604_800;

/// Access Point path expiry (24 hours).
pub const AP_PATH_TIME: u64 = 86_400;

/// Roaming path expiry (6 hours).
pub const ROAMING_PATH_TIME: u64 = 21_600;

/// Default destination timeout (7 days). Matches Python
/// `Transport.DESTINATION_TIMEOUT`. Drives both `path_table` and
/// `recent_announces` eviction.
pub const DESTINATION_TIMEOUT: u64 = 604_800;

/// Transport link-table timeout for validated links (15 min).
/// Equals `Link::STALE_TIME (720s) * 1.25`.
pub const LINK_TIMEOUT: f64 = 900.0;

/// Reverse table entry timeout (8 minutes).
pub const REVERSE_TIMEOUT: u64 = 480;

/// Maximum packet receipts tracked.
pub const MAX_RECEIPTS: usize = 1024;

/// Rate timestamps per destination.
pub const MAX_RATE_TIMESTAMPS: usize = 16;

/// Random blobs saved to disk per destination.
pub const PERSIST_RANDOM_BLOBS: usize = 32;

/// Random blobs kept in memory per destination.
pub const MAX_RANDOM_BLOBS: usize = 64;

/// Max local rebroadcasts before stopping.
pub const LOCAL_REBROADCASTS_MAX: u32 = 2;

/// Path request timeout (seconds).
pub const PATH_REQUEST_TIMEOUT: f64 = 15.0;

/// Duplicate inbound path request tag retention (seconds).
pub const PATH_REQUEST_GATE_TIMEOUT: f64 = 120.0;

/// Grace before path response (seconds).
pub const PATH_REQUEST_GRACE: f64 = 0.4;

/// Extra grace for roaming interfaces (seconds).
pub const PATH_REQUEST_RG: f64 = 1.5;

/// Minimum interval between path requests (seconds).
pub const PATH_REQUEST_MI: f64 = 20.0;

/// Maximum packet hashes before rotation. Set to 2M with rotation at
/// `maxsize/2` so effective history matches Python's 1M-no-rotation window.
pub const HASHLIST_MAXSIZE: usize = 2_000_000;

/// Job loop period (250ms).
pub const JOB_INTERVAL_MS: u64 = 250;

/// Job loop period in background mode (2s). Inbound packet processing is
/// unaffected — it runs on the channel branch at full speed.
pub const JOB_INTERVAL_BG_MS: u64 = 2000;

/// Cadence at which `on_tick` flushes routing-state files (path_table,
/// announce_cache, blackhole, tunnel_table) when dirty. Hashlist is excluded
/// (multi-MB on busy hubs); it saves on shutdown + foreground→background.
pub const STATE_SAVE_INTERVAL_SECS: f64 = 10.0;

/// Link table check interval.
pub const LINKS_CHECK_INTERVAL: f64 = 1.0;

/// Receipt timeout check interval.
pub const RECEIPTS_CHECK_INTERVAL: f64 = 1.0;

/// Announce rebroadcast check interval.
pub const ANNOUNCES_CHECK_INTERVAL: f64 = 1.0;

/// Pending path request cleanup interval.
pub const PENDING_PRS_CHECK_INTERVAL: f64 = 30.0;

/// Cache cleanup interval (5 minutes).
pub const CACHE_CLEAN_INTERVAL: f64 = 300.0;

/// Table culling interval.
pub const TABLES_CULL_INTERVAL: f64 = 5.0;

/// Interface job processing interval.
pub const INTERFACE_JOBS_INTERVAL: f64 = 5.0;

/// Management announce interval (2 hours).
pub const MGMT_ANNOUNCE_INTERVAL: f64 = 7200.0;

/// Blackhole expiry check interval.
pub const BLACKHOLE_CHECK_INTERVAL: f64 = 60.0;

/// Announce bandwidth cap as a fraction of interface bitrate (2%).
///
/// The Python reference stores `ANNOUNCE_CAP = 2` and divides by 100 at use
/// sites; we store the fraction directly. UIs may show the percentage.
pub const ANNOUNCE_CAP: f64 = 0.02;

/// Maximum ingress-limited announces to hold per interface.
/// Matches Python `Interface.MAX_HELD_ANNOUNCES = 256`.
pub const MAX_HELD_ANNOUNCES: usize = 256;

/// Held announce release interval (seconds).
/// Matches Python 1.1.6 `Interface.IC_HELD_RELEASE_INTERVAL = 2`.
pub const IC_HELD_RELEASE_INTERVAL: f64 = 2.0;

/// Incoming announce frequency window samples.
/// Matches Python 1.1.6 `Interface.IA_FREQ_SAMPLES = 128`.
pub const IA_FREQ_SAMPLES: usize = 128;

/// Outgoing announce frequency window samples.
/// Matches Python 1.1.6 `Interface.OA_FREQ_SAMPLES = 128`.
pub const OA_FREQ_SAMPLES: usize = 128;

/// Minimum samples required before frequency is considered defined.
/// Matches Python 1.1.6 `Interface.IC_DEQUE_MIN_SAMPLE = 32`.
pub const IC_DEQUE_MIN_SAMPLE: usize = 32;

/// Duration interface is treated as "new" (seconds).
/// Matches Python `Interface.IC_NEW_TIME = 2*60*60`.
pub const IC_NEW_TIME: f64 = 7200.0;

/// Burst threshold for new interfaces (announces/sec).
/// Matches Python 1.1.6 `Interface.IC_BURST_FREQ_NEW = 6`.
pub const IC_BURST_FREQ_NEW: f64 = 6.0;

/// Burst threshold for established interfaces (announces/sec).
/// Matches Python 1.1.6 `Interface.IC_BURST_FREQ = 35`.
pub const IC_BURST_FREQ: f64 = 35.0;

/// Burst detection active duration (seconds).
/// Matches Python `Interface.IC_BURST_HOLD = 1*60`.
pub const IC_BURST_HOLD: f64 = 60.0;

/// Burst penalty delay (seconds).
/// Matches Python 1.1.6 `Interface.IC_BURST_PENALTY = 15`.
pub const IC_BURST_PENALTY: f64 = 15.0;

/// Tunnel timeout (8 hours, in seconds).
/// Matches Python 1.1.6 `Transport.TUNNEL_TIMEOUT = 60*60*8`.
pub const TUNNEL_TIMEOUT: u64 = 28_800;

/// Tunnel path timeout (8 hours, in seconds).
/// Matches Python 1.1.6 `Transport.TUNNEL_PATH_TIMEOUT = 60*60*8`.
pub const TUNNEL_PATH_TIMEOUT: u64 = 28_800;

/// Announce queue processing interval (seconds).
pub const ANNOUNCE_QUEUE_INTERVAL: f64 = 1.0;

/// Local client cache max size.
pub const LOCAL_CLIENT_CACHE_MAXSIZE: usize = 512;

/// Maximum lifetime for queued announces (24 hours, in seconds).
/// Matches Python `Reticulum.QUEUED_ANNOUNCE_LIFE = 60*60*24`.
pub const QUEUED_ANNOUNCE_LIFE: f64 = 86_400.0;

/// Maximum number of queued announces per interface.
/// Matches Python `Reticulum.MAX_QUEUED_ANNOUNCES = 16384`.
pub const MAX_QUEUED_ANNOUNCES: usize = 16_384;

/// Startup grace period (seconds) before cache cleaning runs.
/// Allows interfaces to come online before pruning stale cache entries.
pub const STARTUP_GRACE_PERIOD: f64 = 3.0;

/// Wire transport mode carried in the packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportMode {
    Broadcast = 0x00,
    Transport = 0x01,
    Relay = 0x02,
    Tunnel = 0x03,
}

/// Reachability state recorded for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reachability {
    Unreachable = 0x00,
    Direct = 0x01,
    Transport = 0x02,
}

/// Liveness state for a known path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PathState {
    Unknown = 0x00,
    Unresponsive = 0x01,
    Responsive = 0x02,
}

/// Configured operating mode for an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    Full,
    PointToPoint,
    Gateway,
    AccessPoint,
    Roaming,
    Boundary,
}

/// Which directions an interface carries traffic in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceDirection {
    pub inbound: bool,
    pub outbound: bool,
}

impl InterfaceDirection {
    pub fn bidirectional() -> Self {
        Self {
            inbound: true,
            outbound: true,
        }
    }

    pub fn inbound_only() -> Self {
        Self {
            inbound: true,
            outbound: false,
        }
    }

    pub fn outbound_only() -> Self {
        Self {
            inbound: false,
            outbound: true,
        }
    }
}
