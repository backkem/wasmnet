//! A device's stdin as the world feeds it: the bytes of [`crate::Op::Stdin`] operator events.
//!
//! [`InputQueue`] is runtime-agnostic: an operator event appends bytes at its instant
//! ([`InputQueue::push`]) and wakes whoever waits on the guest's stdin read; a runtime backend
//! serves the guest's `wasi:cli/stdin` from it. A read never blocks the world: with nothing
//! queued it is pending until the next write, and stdin never reaches end of file, like a
//! terminal nobody types on.
//!
//! Determinism: bytes only arrive through operator events, which run at their instant inside
//! the world's one thread, and the wake goes to the device's own event loop. A run that
//! feeds a device's stdin replays byte for byte from the same operator events.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

#[derive(Default)]
struct State {
    bytes: VecDeque<u8>,
    /// Every reader waiting for bytes (a p3 stream task, a p2 pollable).
    waiters: Vec<Waker>,
    /// Bytes ever pushed (diagnostics).
    pushed: u64,
}

/// One device's stdin. Cloning gives another handle to the same queue.
#[derive(Clone, Default)]
pub struct InputQueue {
    state: Arc<Mutex<State>>,
}

impl InputQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Appends `bytes` and wakes every waiting reader.
    pub fn push(&self, bytes: &[u8]) {
        let waiters = {
            let mut s = self.state();
            s.bytes.extend(bytes);
            s.pushed += bytes.len() as u64;
            std::mem::take(&mut s.waiters)
        };
        for w in waiters {
            w.wake();
        }
    }

    /// Takes up to `max` queued bytes now (possibly none).
    pub fn take(&self, max: usize) -> Vec<u8> {
        let mut s = self.state();
        let n = max.min(s.bytes.len());
        s.bytes.drain(..n).collect()
    }

    /// Whether bytes are queued.
    pub fn ready(&self) -> bool {
        !self.state().bytes.is_empty()
    }

    /// Up to `max` bytes, or pending (the waker is woken by the next [`push`](Self::push)).
    pub fn poll_take(&self, cx: &mut Context<'_>, max: usize) -> Poll<Vec<u8>> {
        let mut s = self.state();
        if s.bytes.is_empty() {
            if !s.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                s.waiters.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let n = max.min(s.bytes.len());
        Poll::Ready(s.bytes.drain(..n).collect())
    }

    /// Pending until bytes are queued.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut s = self.state();
        if s.bytes.is_empty() {
            if !s.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                s.waiters.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        Poll::Ready(())
    }

    /// Bytes pushed so far.
    pub fn pushed(&self) -> u64 {
        self.state().pushed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_pending_read_is_woken_by_a_push() {
        let q = InputQueue::new();
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(q.poll_take(&mut cx, 8).is_pending());
        assert!(
            q.poll_take(&mut cx, 8).is_pending(),
            "one waker, registered once"
        );
        q.push(b"ls\n");
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(q.poll_take(&mut cx, 2), Poll::Ready(b"ls".to_vec()));
        assert_eq!(q.take(8), b"\n".to_vec());
        assert!(!q.ready());
        assert_eq!(q.pushed(), 3);
    }
}
