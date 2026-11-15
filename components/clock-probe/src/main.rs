//! clock-probe: a test fixture. A plain std `wasm32-wasip2` command that samples every source of
//! nondeterminism a normal guest touches (monotonic clock, wall clock, secure and
//! insecure random, std's `HashMap` seed) twice, with a `std::thread::sleep` in between.
//!
//! Its output is only meaningful under a host that virtualises those sources; under
//! `wasmnet-host` the same seed must give byte-identical stdout.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long the probe sleeps between its two rounds (virtual time under wasmnet-host).
const SLEEP: Duration = Duration::from_millis(1500);

fn main() {
    let start = Instant::now();
    for round in 0..2 {
        if round > 0 {
            std::thread::sleep(SLEEP);
        }
        sample(round, start);
    }
}

fn sample(round: u32, start: Instant) {
    // std surface: Instant (monotonic) and SystemTime (wall).
    let elapsed = start.elapsed();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // std's HashMap keys come from the host's entropy; hash a constant to expose them.
    let hash = RandomState::new().hash_one(0xC0FFEE_u64);

    // Direct WASI 0.2 calls for what std does not expose.
    let mono_raw = wasip2::clocks::monotonic_clock::now();
    let wall_raw = wasip2::clocks::wall_clock::now();
    let secure = wasip2::random::random::get_random_u64();
    let insecure = wasip2::random::insecure::get_insecure_random_u64();
    let (seed_hi, seed_lo) = wasip2::random::insecure_seed::insecure_seed();

    println!("round={round}");
    println!("  monotonic_ns={mono_raw}");
    println!("  instant_elapsed_ns={}", elapsed.as_nanos());
    println!("  wall={}.{:09}", wall_raw.seconds, wall_raw.nanoseconds);
    println!("  systemtime_ns={}", wall.as_nanos());
    println!("  random_u64={secure:#018x}");
    println!("  insecure_u64={insecure:#018x}");
    println!("  insecure_seed={seed_hi:#018x}{seed_lo:016x}");
    println!("  std_hash={hash:#018x}");
}
