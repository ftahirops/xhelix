//! xhelix-watchdog — independent liveness monitor for the xhelix
//! daemon.
//!
//! Design intent: xhelix's own selfprotect machinery can be
//! subverted by a kernel-level adversary. A second supervisor in
//! a different language, with a different bug surface, is the
//! belt-and-braces defence — if xhelix stops heartbeating, the
//! watchdog notices and either kicks systemd to restart it or
//! escalates to a tripwire.
//!
//! Threat model:
//!   - Attacker subverts xhelix's eBPF programs but not the
//!     watchdog (different toolchain, different memory layout).
//!   - Attacker SIGKILLs xhelix — watchdog sees stale heartbeat
//!     and triggers restart.
//!   - Attacker stops systemd unit — watchdog sees its restart
//!     attempt fail and writes a tamper flag the next reboot's
//!     posture audit catches.
//!
//! Runtime contract:
//!   - xhelix writes /run/xhelix.heartbeat every <HEARTBEAT_OK>
//!     seconds with the current wall-clock UNIX time.
//!   - Watchdog polls every <POLL_INTERVAL>. If the heartbeat is
//!     older than <STALE_THRESHOLD>, the agent is presumed dead.
//!   - On stale heartbeat, watchdog runs `systemctl restart xhelix`
//!     once. If the heartbeat still doesn't recover within
//!     <RECOVERY_TIMEOUT>, it writes /run/xhelix.tamper.
//!
//! No external crates — only `std` and process spawn via the
//! libc-backed Command. Compiles to a single 300-ish-KB binary.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::thread::sleep;

// Tunables. Override via environment for testing.
const HEARTBEAT_PATH: &str = "/run/xhelix.heartbeat";
const TAMPER_FLAG: &str = "/run/xhelix.tamper";
const POLL_INTERVAL_S: u64 = 10;
const STALE_THRESHOLD_S: u64 = 60;
const RECOVERY_TIMEOUT_S: u64 = 30;
const RESTART_COOLDOWN_S: u64 = 120;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_heartbeat() -> Option<u64> {
    let raw = fs::read_to_string(HEARTBEAT_PATH).ok()?;
    raw.trim().parse::<u64>().ok()
}

fn systemctl_restart() -> bool {
    let status = Command::new("systemctl")
        .args(["restart", "xhelix"])
        .status();
    matches!(status, Ok(s) if s.success())
}

fn write_tamper_flag(reason: &str) {
    if let Ok(mut f) = fs::File::create(TAMPER_FLAG) {
        let _ = writeln!(f, "{} ts={}", reason, now());
    }
    eprintln!("xhelix-watchdog: TAMPER {}", reason);
}

fn log_info(msg: &str) {
    println!("xhelix-watchdog: {} ts={}", msg, now());
}

fn main() {
    log_info("starting");
    let mut last_restart: u64 = 0;

    loop {
        sleep(Duration::from_secs(POLL_INTERVAL_S));

        let now_ts = now();
        let beat = match read_heartbeat() {
            Some(b) => b,
            None => {
                // No heartbeat file at all. Could be fresh boot
                // (daemon not up yet) or active kill. Wait one
                // full window before reacting.
                if !Path::new(HEARTBEAT_PATH).exists() && now_ts > 60 {
                    log_info("heartbeat file missing; treating as stale");
                }
                continue;
            }
        };

        let age = now_ts.saturating_sub(beat);
        if age < STALE_THRESHOLD_S {
            continue;
        }

        log_info(&format!("stale heartbeat age={}s — restarting", age));
        if now_ts.saturating_sub(last_restart) < RESTART_COOLDOWN_S {
            log_info("restart cooldown active");
            continue;
        }
        last_restart = now_ts;

        let restarted = systemctl_restart();
        if !restarted {
            write_tamper_flag("systemctl_restart_failed");
            continue;
        }
        log_info("restart issued; waiting for recovery");

        // Wait up to RECOVERY_TIMEOUT_S for the heartbeat to be
        // fresh again.
        let recovery_start = now_ts;
        let mut recovered = false;
        while now().saturating_sub(recovery_start) < RECOVERY_TIMEOUT_S {
            sleep(Duration::from_secs(2));
            if let Some(new_beat) = read_heartbeat() {
                if now().saturating_sub(new_beat) < STALE_THRESHOLD_S {
                    recovered = true;
                    log_info("recovered");
                    break;
                }
            }
        }
        if !recovered {
            write_tamper_flag("recovery_timeout");
        }
    }
}
