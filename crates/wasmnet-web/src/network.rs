//! The network API, shaped like the native host's: create a network with a seed, add devices
//! with flat config, link ports with a latency, run in steps, read the journal, the links'
//! pcap-ng captures and the outcome.
//!
//! The difference from the native host is the run: JavaScript runs the guests' async work on
//! promises, outside the network's actor polls, so a run is a loop of [`Network::step`]s with
//! the JavaScript event loop settling in between (the protocol is in the crate docs), and
//! [`Network::finish`] reads the outcome at the end.

use wasmnet_core::{
    DeviceConfig, DeviceId, DeviceOptions, FrameRecord, Guard, Impairments, JournalEntry, LinkId,
    Nanos, Outcome, PortRef, SimConfig, Stats,
};

use crate::host::JsHost;
use crate::runtime::{JsRuntime, Registry};

/// How a run ended, as [`Network::finish`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// The network ran to its end: quiescent, or stopped at the deadline.
    Finished(Outcome),
    /// A device crashed (or the network refused to go on) at `at`.
    Failed { at: Nanos, message: String },
}

/// A virtual network whose devices JavaScript supplies.
///
/// The simulator borrows its runtime for its whole life, so [`Network::new`] leaks one small
/// allocation (the runtime: the host handle and an empty registry); everything the devices
/// hold is released when the network is dropped.
pub struct Network<H: JsHost + Clone + Unpin + 'static> {
    runtime: &'static JsRuntime<H>,
    /// `Some` until dropped (it must go before the registry is emptied).
    sim: Option<wasmnet_core::Network<'static, JsRuntime<H>>>,
    failure: Option<(Nanos, String)>,
    steps: u64,
}

impl<H: JsHost + Clone + Unpin + 'static> Network<H> {
    /// An empty network with `seed` and the default wall epoch.
    pub fn new(host: H, seed: u64) -> Self {
        let runtime: &'static JsRuntime<H> = Box::leak(Box::new(JsRuntime::new(host)));
        let guard = Guard {
            // A busy guest that never lets the network move would otherwise spin forever; jco
            // needs more polls per instant than wasmtime, as its work arrives in small pieces.
            max_polls_per_instant: 100_000,
            ..Guard::default()
        };
        let sim = wasmnet_core::Network::with_config(runtime, SimConfig::seeded(seed), guard);
        runtime.registry().set_clock(sim.clock().clone());
        Self {
            runtime,
            sim: Some(sim),
            failure: None,
            steps: 0,
        }
    }

    fn sim_ref(&self) -> &wasmnet_core::Network<'static, JsRuntime<H>> {
        self.sim.as_ref().expect("present until dropped")
    }

    fn sim_mut(&mut self) -> &mut wasmnet_core::Network<'static, JsRuntime<H>> {
        self.sim.as_mut().expect("present until dropped")
    }

    /// The simulator underneath, for anything this API does not wrap.
    pub fn sim(&self) -> &wasmnet_core::Network<'static, JsRuntime<H>> {
        self.sim_ref()
    }

    /// The registry the device-side exports serve from.
    pub fn registry(&self) -> &Registry {
        self.runtime.registry()
    }

    /// The JavaScript host.
    pub fn host(&self) -> &H {
        self.runtime.host()
    }

    /// Instantiates `component` as a device called `name`, serving `config` to it. See
    /// [`device_with_options`](Self::device_with_options).
    pub fn device(
        &mut self,
        name: &str,
        component: &str,
        config: DeviceConfig,
    ) -> Result<DeviceId, String> {
        self.device_with_options(name, component, config, DeviceOptions::default())
    }

    /// Instantiates `component` as a device called `name` through [`JsHost::instantiate`], with
    /// `config` and `options` (`journal_stdio` puts its stdout and stderr lines in the journal).
    /// `ports()` is answered right here; the rest of the start-up happens when the network
    /// runs. The device's index ([`DeviceId::index`]) is the `dev` of every host call and
    /// device-side export. A failed instantiation leaves the network as it was, and the next
    /// device gets the same index.
    pub fn device_with_options(
        &mut self,
        name: &str,
        component: &str,
        config: DeviceConfig,
        options: DeviceOptions,
    ) -> Result<DeviceId, String> {
        self.sim_mut()
            .device_with_options(name, component, config, options)
            .map_err(|e| e.to_string())
    }

    /// Wires two ports with a point-to-point link of one-way `latency` (ns). Both ports must be
    /// declared by their device, and each port can be on one link only.
    pub fn link(&mut self, a: PortRef, b: PortRef, latency: Nanos) -> Result<LinkId, String> {
        self.link_impaired(a, b, latency, [Impairments::default(); 2])
    }

    /// [`link`](Self::link) with each direction's impairments (a rate with a bounded transmit
    /// queue, seeded loss and jitter; `docs/design/links.md`), indexed by the sending end:
    /// `[a -> b, b -> a]`.
    pub fn link_impaired(
        &mut self,
        a: PortRef,
        b: PortRef,
        latency: Nanos,
        impairments: [Impairments; 2],
    ) -> Result<LinkId, String> {
        let count = self.sim_ref().devices().len();
        if let Some(end) = [a, b].into_iter().find(|p| p.device.index() >= count) {
            return Err(format!("no device {}", end.device.index()));
        }
        let mut link = self.sim_mut().link(a, b).map_err(|e| e.to_string())?;
        link = link.latency(latency);
        if impairments != [Impairments::default(); 2] {
            link = link
                .impair_from(a, impairments[0])
                .impair_from(b, impairments[1]);
        }
        Ok(link.id())
    }

    /// Runs every event at or before `until`, and every device JavaScript woke, first. `false`
    /// once the network failed (a trap): stop driving it; [`finish`](Self::finish) reports why.
    pub fn step(&mut self, until: Nanos) -> bool {
        if self.failure.is_some() {
            return false;
        }
        self.steps += 1;
        let sim = self.sim_mut();
        match sim.run_until(until) {
            Ok(_) => true,
            Err(e) => {
                let at = sim.now();
                self.failure = Some((at, e.to_string()));
                false
            }
        }
    }

    /// Whether JavaScript woke a device since the last call (then [`step`](Self::step) at
    /// [`now`](Self::now) before time may move).
    pub fn take_dirty(&self) -> bool {
        self.registry().take_dirty()
    }

    /// Current virtual time.
    pub fn now(&self) -> Nanos {
        self.sim_ref().now()
    }

    /// The time of the earliest queued event, if any.
    pub fn next_event_time(&self) -> Option<Nanos> {
        self.sim_ref().next_event_time()
    }

    /// The trap that ended the run, if one did.
    pub fn failure(&self) -> Option<&(Nanos, String)> {
        self.failure.as_ref()
    }

    /// Steps taken so far.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Ends the run (once JavaScript has settled and nothing is due, see the crate docs): runs
    /// to quiescence (`deadline = None`) or to `deadline`, and reports how it ended. Events still
    /// queued run here without JavaScript settling in between, so call it only when
    /// [`next_event_time`](Self::next_event_time) is `None` or past the deadline. The network can
    /// be stepped further afterwards.
    pub fn finish(&mut self, deadline: Option<Nanos>) -> RunOutcome {
        if let Some((at, message)) = &self.failure {
            return RunOutcome::Failed {
                at: *at,
                message: message.clone(),
            };
        }
        let sim = self.sim_mut();
        let result = match deadline {
            None => sim.run_until_quiescent(),
            Some(d) => sim.run_until(d),
        };
        match result {
            Ok(o) => RunOutcome::Finished(o),
            Err(e) => {
                let at = sim.now();
                let message = e.to_string();
                self.failure = Some((at, message.clone()));
                RunOutcome::Failed { at, message }
            }
        }
    }

    /// Every device, in creation order.
    pub fn devices(&self) -> Vec<DeviceId> {
        self.sim_ref().devices()
    }

    /// The device's name.
    pub fn device_name(&self, device: DeviceId) -> &str {
        self.sim_ref().device_name(device)
    }

    /// Every link, in creation order.
    pub fn links(&self) -> Vec<LinkId> {
        self.sim_ref().links()
    }

    /// The link's name, after its two ends (`<device>.<port>-<device>.<port>`).
    pub fn link_name(&self, link: LinkId) -> String {
        self.sim_ref().link_name(link)
    }

    /// The link's pcap-ng capture so far (timestamps in virtual nanoseconds).
    pub fn pcap(&self, link: LinkId) -> Vec<u8> {
        self.sim_ref().pcap(link)
    }

    /// Every transmission on a wired port so far, in transmit order, with its fate.
    pub fn frames(&self) -> Vec<FrameRecord> {
        self.sim_ref().frames()
    }

    /// Every journal record so far.
    pub fn journal(&self) -> Vec<JournalEntry> {
        self.sim_ref().journal()
    }

    /// The journal from entry `from` on: what a live view has not taken yet. The next increment
    /// starts at `from` plus the number of entries returned.
    pub fn journal_from(&self, from: usize) -> Vec<JournalEntry> {
        self.sim_ref().journal_from(from)
    }

    /// Everything the device wrote to stdout so far.
    pub fn stdout(&self, device: DeviceId) -> Vec<u8> {
        self.sim_ref().stdout(device)
    }

    /// Everything the device wrote to stderr so far.
    pub fn stderr(&self, device: DeviceId) -> Vec<u8> {
        self.sim_ref().stderr(device)
    }

    /// Reads the device's counters through [`JsHost::counters`] (`None` if it exports none), at
    /// the current instant, between steps. A trap here fails the network.
    pub fn counters(&mut self, device: DeviceId) -> Result<Option<Vec<(String, u64)>>, String> {
        if let Some((_, message)) = &self.failure {
            return Err(message.clone());
        }
        let sim = self.sim_mut();
        match sim.counters(device) {
            Ok(c) => Ok(c),
            Err(e) => {
                let at = sim.now();
                let message = e.to_string();
                self.failure = Some((at, message.clone()));
                Err(message)
            }
        }
    }

    /// Executor counters.
    pub fn stats(&self) -> Stats {
        self.sim_ref().stats()
    }
}

impl<H: JsHost + Clone + Unpin + 'static> Drop for Network<H> {
    fn drop(&mut self) {
        // The actors go first; then nothing refers to the devices' state any more.
        drop(self.sim.take());
        self.runtime.registry().clear();
    }
}
