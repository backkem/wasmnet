//! async-probe: a WASI 0.3 command (`wasi:cli/run@0.3.0`, an `async func`) built with
//! wit-bindgen's async ABI through the `wasip3` crate.
//!
//! It exists to prove that the pinned wasmtime and wit-bindgen agree on the component-model
//! async ABI, and to probe virtual time from the p3 side: two concurrent `wait-for`s in one
//! task must complete in deadline order at exactly the virtual instants requested.
//! Output goes through a p3 `stream<u8>` on `wasi:cli/stdout@0.3.0`.

// Native builds (a `cargo test --workspace`) compile it without the export, so nothing is used.
#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]

use std::fmt::Write as _;
use std::future::{Future, IntoFuture as _};
use std::pin::pin;
use std::task::Poll;

use wasip3::clocks::{monotonic_clock, system_clock};
use wasip3::random::{insecure, random};

// Exported on Wasm only: a native `cargo test --workspace` links this cdylib example too, and
// rust-lld's version script rejects the `[async-lift]` export name.
#[cfg(target_family = "wasm")]
wasip3::cli::command::export!(AsyncProbe);

struct AsyncProbe;

impl wasip3::exports::cli::run::Guest for AsyncProbe {
    async fn run() -> Result<(), ()> {
        let mut out = String::new();
        let t0 = monotonic_clock::now();
        let wall = system_clock::now();
        let _ = writeln!(
            out,
            "p3 t0={t0} wall={}.{:09}",
            wall.seconds, wall.nanoseconds
        );
        let _ = writeln!(
            out,
            "p3 random_u64={:#018x} insecure_u64={:#018x}",
            random::get_random_u64(),
            insecure::get_insecure_random_u64()
        );

        // Two concurrent waits: the 100ms one must fire first, at exactly t0+100ms.
        let (slow, fast) = join(timed(300_000_000), timed(100_000_000)).await;
        let _ = writeln!(out, "p3 fast_done=+{} slow_done=+{}", fast - t0, slow - t0);

        monotonic_clock::wait_until(t0 + 1_000_000_000).await;
        let _ = writeln!(out, "p3 after_wait_until=+{}", monotonic_clock::now() - t0);

        let (mut tx, rx) = wasip3::wit_stream::new();
        let ((), result) = join(
            async move {
                let rest = tx.write_all(out.into_bytes()).await;
                debug_assert!(rest.is_empty());
            },
            wasip3::cli::stdout::write_via_stream(rx).into_future(),
        )
        .await;
        result.map_err(|_| ())
    }
}

/// Waits `ns` nanoseconds and returns the monotonic time observed afterwards.
async fn timed(ns: u64) -> u64 {
    monotonic_clock::wait_for(ns).await;
    monotonic_clock::now()
}

/// Minimal two-way join so the probe needs no executor crate.
async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (pin!(a), pin!(b));
    let (mut ra, mut rb) = (None, None);
    std::future::poll_fn(move |cx| {
        if ra.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            ra = Some(v);
        }
        if rb.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            rb = Some(v);
        }
        match (ra.take(), rb.take()) {
            (Some(x), Some(y)) => Poll::Ready((x, y)),
            (x, y) => {
                (ra, rb) = (x, y);
                Poll::Pending
            }
        }
    })
    .await
}
