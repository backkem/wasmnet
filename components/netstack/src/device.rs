//! The smoltcp `phy::Device` adapter: two in-memory queues, nothing else (a `QueueDevice`).
//!
//! * `rx`: frames the host delivered (`device.receive` only pushes here and wakes the driver).
//! * `tx`: frames smoltcp produced during a poll. The driver takes them after the poll and hands
//!   them to `wire.transmit` with no stack borrow held (driver rule 3).
//!
//! Frame size: smoltcp's `max_transmission_unit` is the **frame** size for `Medium::Ethernet`
//! (not the IP MTU), so it is the IP MTU + 14. Frames shorter than the 60-byte Ethernet
//! minimum (an ARP frame is 42) are zero-padded on transmit, like a real NIC (smoltcp issue #11
//! in `docs/upstream/smoltcp.md`).

use std::collections::VecDeque;

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// Ethernet II header: dst, src, EtherType.
pub const ETH_HEADER: usize = 14;
/// Minimum Ethernet frame without FCS.
pub const MIN_FRAME: usize = 60;

/// Frame counters (`counters` export).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameCounters {
    pub rx_frames: u64,
    pub rx_bytes: u64,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    /// Transmitted frames that needed padding to [`MIN_FRAME`].
    pub tx_padded: u64,
}

/// The in-memory NIC.
#[derive(Debug)]
pub struct QueueDevice {
    /// IP MTU.
    mtu: usize,
    pub rx: VecDeque<Vec<u8>>,
    pub tx: Vec<Vec<u8>>,
    pub counters: FrameCounters,
}

impl QueueDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx: VecDeque::new(),
            tx: Vec::new(),
            counters: FrameCounters::default(),
        }
    }

    /// Queues a received frame for the next poll.
    pub fn push_rx(&mut self, frame: Vec<u8>) {
        self.counters.rx_frames += 1;
        self.counters.rx_bytes += frame.len() as u64;
        self.rx.push_back(frame);
    }

    /// Queues a copy of a frame this node sent, to be received by the node itself (multicast
    /// loopback). It never was on the wire, so the rx counters do not count it.
    pub fn push_loopback(&mut self, frame: Vec<u8>) {
        self.rx.push_back(frame);
    }

    /// Takes every frame smoltcp produced so far, in order.
    pub fn take_tx(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx)
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(RxToken, TxToken<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((
            RxToken(frame),
            TxToken {
                tx: &mut self.tx,
                counters: &mut self.counters,
            },
        ))
    }

    fn transmit(&mut self, _now: Instant) -> Option<TxToken<'_>> {
        Some(TxToken {
            tx: &mut self.tx,
            counters: &mut self.counters,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.mtu + ETH_HEADER;
        caps
    }
}

pub struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub struct TxToken<'a> {
    tx: &'a mut Vec<Vec<u8>>,
    counters: &'a mut FrameCounters,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0u8; len.max(MIN_FRAME)];
        let r = f(&mut frame[..len]);
        if len < MIN_FRAME {
            self.counters.tx_padded += 1;
        }
        self.counters.tx_frames += 1;
        self.counters.tx_bytes += frame.len() as u64;
        self.tx.push(frame);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{RxToken as _, TxToken as _};

    #[test]
    fn short_frames_are_padded_and_the_mtu_is_the_frame_size() {
        let mut dev = QueueDevice::new(1500);
        assert_eq!(dev.capabilities().max_transmission_unit, 1514);
        let tok = dev.transmit(Instant::ZERO).unwrap();
        tok.consume(42, |buf| buf.fill(0xab));
        let tok = dev.transmit(Instant::ZERO).unwrap();
        tok.consume(100, |buf| buf.fill(0xcd));
        let tx = dev.take_tx();
        assert_eq!(tx[0].len(), 60);
        assert!(tx[0][..42].iter().all(|&b| b == 0xab) && tx[0][42..].iter().all(|&b| b == 0));
        assert_eq!(tx[1].len(), 100);
        assert_eq!(
            dev.counters,
            FrameCounters {
                tx_frames: 2,
                tx_bytes: 160,
                tx_padded: 1,
                ..FrameCounters::default()
            }
        );
    }

    #[test]
    fn rx_is_fifo() {
        let mut dev = QueueDevice::new(1500);
        dev.push_rx(vec![1; 60]);
        dev.push_rx(vec![2; 64]);
        let (rx, _) = dev.receive(Instant::ZERO).unwrap();
        assert_eq!(rx.consume(|b| b[0]), 1);
        let (rx, _) = dev.receive(Instant::ZERO).unwrap();
        assert_eq!(rx.consume(|b| b.len()), 64);
        assert!(dev.receive(Instant::ZERO).is_none());
        assert_eq!((dev.counters.rx_frames, dev.counters.rx_bytes), (2, 124));
    }
}
