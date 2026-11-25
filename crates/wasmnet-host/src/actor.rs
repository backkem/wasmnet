//! Device actors: one future per device that owns the device's `Store` and keeps exactly one
//! `run_concurrent` event loop alive for the device's whole life
//! (`docs/design/async-under-virtual-time.md`).
//!
//! Host→guest calls are never made with `call_async` (that would drive the store only until the
//! call returns and freeze the guest's background tasks). Instead, the actor drains its [`Inbox`]
//! inside the live event loop and starts one `call_concurrent` per command. In-flight calls are
//! polled in start order, so everything stays deterministic.
//!
//! Life of a device: the network calls `ports()` when it creates the device (before the actor
//! exists). The actor calls `start()` first for async devices, then runs commands in inbox
//! order. After a `receive` or `link-state` the actor asks the queue for a `poll(now)`, and after
//! a `poll` it replaces the device's deadline with the answer.
//!
//! Control calls (`counters`) travel the same inbox. The network queues one between runs and lets
//! the executor settle the current instant, so the call runs inside the live event loop like any
//! other, without advancing time.
//!
//! Apps: a composed node also exports each app's `wasi:cli/run` as `app-<name>`.
//! Once `start()` has returned, the actor starts every app's `run` (in export-name order) as a
//! **daemon call**: it stays in flight as long as the app runs, and it never counts as
//! outstanding for deadlock detection (a server never returns, by design). An app that returns
//! is journalled as an `app-exit {app, status}` event at that instant.

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll};

use wasmnet_core::{
    ActorFuture, Command, CostMeter, Fault, Inbox, JournalEnd, Nanos, Status, VirtualClock,
};
use wasmtime::AsContextMut;
use wasmtime::Store;
use wasmtime::component::{Accessor, TypedFunc};

use crate::bindings::exports::wasmnet::link::{counters, device, lifecycle};
use crate::extension::ControlHandler;
use crate::wasi::HostState;

/// A device index in its network.
type DeviceIdx = usize;

/// A guest trap or host error as the sim's [`Fault`]: the message as the executor always
/// formatted it, and the `wasmtime::Trap` (if any) as its detail.
pub(crate) fn fault(error: wasmtime::Error) -> Fault {
    let message = format!("{error:?}");
    match error.downcast_ref::<wasmtime::Trap>().copied() {
        Some(trap) => Fault::with_detail(message, trap),
        None => Fault::new(message),
    }
}

type Call<'a> = Pin<Box<dyn Future<Output = wasmtime::Result<()>> + 'a>>;

/// In-flight export calls, polled in start order.
struct Calls<'a> {
    status: Status,
    calls: Vec<(u64, Call<'a>)>,
}

impl<'a> Calls<'a> {
    fn push(&mut self, what: String, call: Call<'a>) {
        let id = self.status.begin(what, false);
        self.calls.push((id, call));
    }

    /// A call that may never finish (an app's `run`).
    fn push_daemon(&mut self, what: String, call: Call<'a>) {
        let id = self.status.begin(what, true);
        self.calls.push((id, call));
    }

    /// Polls every call once and retires finished ones. Returns how many finished.
    fn poll(&mut self, cx: &mut Context<'_>) -> wasmtime::Result<usize> {
        let mut finished = 0;
        let mut i = 0;
        while i < self.calls.len() {
            match self.calls[i].1.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    let (id, _) = self.calls.remove(i);
                    self.status.end(id);
                    result?;
                    finished += 1;
                }
                Poll::Pending => i += 1,
            }
        }
        Ok(finished)
    }
}

/// Fuel per virtual instant: refilled the first time the actor runs at a new instant. Wasmtime
/// polls the `run_concurrent` closure before every work item, so this runs before any guest code
/// at that instant, and a compute loop traps deterministically with `Trap::OutOfFuel`.
struct Fuel {
    budget: u64,
    /// The store's engine meters fuel (components with a budget of their own run without).
    metered: bool,
    clock: VirtualClock,
    last: Cell<Option<Nanos>>,
    /// The fuel left when last looked at, and where consumption is reported.
    left: Cell<u64>,
    meter: CostMeter,
}

impl Fuel {
    fn refill(&self, acc: &Accessor<HostState>) -> wasmtime::Result<()> {
        // Guest work runs between the closure's polls: count it at the next one, under the
        // instant it ran at (before `last` moves on).
        self.account(acc)?;
        let now = self.clock.now();
        if self.last.get() != Some(now) {
            self.last.set(Some(now));
            if self.metered {
                acc.with(|mut a| a.as_context_mut().set_fuel(self.budget))?;
            }
            self.left.set(self.budget);
        }
        Ok(())
    }

    /// Reports the fuel consumed since the last look (if a host call gave fuel back to the
    /// store, so more is left than at the last look, that counts as nothing consumed). It was
    /// all consumed under the budget of the instant of the last refill (`last`), even when it
    /// is reported at the next instant's first look: only a refill resets the store's fuel.
    fn account(&self, acc: &Accessor<HostState>) -> wasmtime::Result<()> {
        if !self.metered {
            return Ok(());
        }
        let left = acc.with(|mut a| a.as_context_mut().get_fuel())?;
        let used = self.left.get().saturating_sub(left);
        match self.last.get() {
            Some(at) => self.meter.add_fuel_at(at, used),
            // Before the first refill (instantiation and `ports()` ran on their own budget,
            // and the first look sees none of it): nothing.
            None => self.meter.add_fuel(used),
        }
        self.left.set(left);
        Ok(())
    }
}

/// An app's `wasi:cli/run@0.3.x`, exported by a composed node as `app-<name>`.
pub(crate) struct App {
    /// The export name, `app-<name>`.
    pub(crate) export: String,
    pub(crate) run: TypedFunc<(), (Result<(), ()>,)>,
}

/// Everything an actor needs. The store's instance is already created.
pub(crate) struct DeviceActor {
    pub(crate) idx: DeviceIdx,
    pub(crate) store: Store<HostState>,
    pub(crate) device: device::Guest,
    pub(crate) lifecycle: Option<lifecycle::Guest>,
    /// Present when the component exports `wasmnet:link/counters`.
    pub(crate) counters: Option<counters::Guest>,
    /// The handlers of the optional exports the extensions found, in extension order.
    pub(crate) controls: Vec<Box<dyn ControlHandler>>,
    /// The node's apps, in export-name order (empty for a plain device).
    pub(crate) apps: Vec<App>,
    /// Where `app-exit` events go.
    pub(crate) journal: JournalEnd,
    pub(crate) inbox: Inbox,
    pub(crate) status: Status,
    pub(crate) clock: VirtualClock,
    pub(crate) fuel_per_instant: u64,
    /// The store's engine meters fuel.
    pub(crate) metered: bool,
}

impl DeviceActor {
    /// Turns the device into its actor future: one `run_concurrent` that never returns `Ok`.
    pub(crate) fn into_future(self) -> ActorFuture {
        let Self {
            idx,
            mut store,
            device,
            lifecycle,
            counters,
            controls,
            apps,
            journal,
            inbox,
            status,
            clock,
            fuel_per_instant,
            metered,
        } = self;
        let fuel = Fuel {
            budget: fuel_per_instant,
            metered,
            clock: clock.clone(),
            last: Cell::new(None),
            left: Cell::new(0),
            meter: inbox.cost().clone(),
        };
        Box::pin(async move {
            let run = async move {
                store
                    .run_concurrent(async move |acc| -> wasmtime::Result<()> {
                        let (dev, ctr, ctl, clock, journal) = (
                            &device,
                            counters.as_ref(),
                            controls.as_slice(),
                            &clock,
                            &journal,
                        );
                        // `ports()` already ran when the network created the device. An async
                        // device's `start()` must return before any other command.
                        let initialised = Cell::new(lifecycle.is_none());
                        let mut apps_started = false;
                        let mut calls = Calls {
                            status: status.clone(),
                            calls: Vec::new(),
                        };
                        if let Some(lc) = &lifecycle {
                            calls.push(
                                "start".to_owned(),
                                Box::pin(async {
                                    lc.call_start(acc).await?;
                                    initialised.set(true);
                                    Ok(())
                                }),
                            );
                        }
                        poll_fn(|cx| {
                            fuel.refill(acc)?;
                            loop {
                                let mut started = 0;
                                // The apps' `run`s start once `start` has returned, before any
                                // queued command, as daemon calls.
                                if initialised.get() && !apps_started {
                                    apps_started = true;
                                    for app in &apps {
                                        let call = app_call(app, acc, clock, journal);
                                        calls.push_daemon(format!("{}.run", app.export), call);
                                        started += 1;
                                    }
                                }
                                // Commands wait until `start` has returned.
                                while initialised.get()
                                    && let Some(command) = inbox.poll_pop(cx)
                                {
                                    let (what, call) =
                                        command_call(dev, ctr, ctl, acc, clock, idx, command);
                                    calls.push(what, call);
                                    started += 1;
                                }
                                if started == 0 && calls.poll(cx)? == 0 {
                                    break;
                                }
                            }
                            fuel.account(acc)?;
                            status.set_guest_tasks_alive(
                                acc.poll_no_interesting_tasks(cx).is_pending(),
                            );
                            Poll::Pending
                        })
                        .await
                    })
                    .await?
            };
            run.await.map_err(fault)
        })
    }
}

/// An app's `run`, then its `app-exit {app, status}` event (and a log line) at the instant it
/// returned. A trap in the app is a trap of the whole node, like any other.
fn app_call<'a>(
    app: &'a App,
    acc: &'a Accessor<HostState>,
    clock: &'a VirtualClock,
    journal: &'a JournalEnd,
) -> Call<'a> {
    Box::pin(async move {
        let (result,) = app.run.call_concurrent(acc, ()).await?;
        let name = app.export.strip_prefix("app-").unwrap_or(&app.export);
        journal.app_exit(clock.now(), name, result.is_ok());
        Ok(())
    })
}

/// Starts the export call for one command. The call's `now` is the instant it was started at.
fn command_call<'a>(
    dev: &'a device::Guest,
    ctr: Option<&'a counters::Guest>,
    ctl: &'a [Box<dyn ControlHandler>],
    acc: &'a Accessor<HostState>,
    clock: &'a VirtualClock,
    idx: DeviceIdx,
    command: Command,
) -> (String, Call<'a>) {
    let now = clock.now();
    match command {
        Command::Receive { port, frame } => (
            format!("receive(p{port})"),
            Box::pin(async move {
                dev.call_receive(acc, now, port, frame).await?;
                clock.poll_by(idx, now);
                Ok(())
            }),
        ),
        Command::LinkState { port, up } => (
            format!("link-state(p{port}, {up})"),
            Box::pin(async move {
                dev.call_link_state(acc, now, port, up).await?;
                clock.poll_by(idx, now);
                Ok(())
            }),
        ),
        Command::Poll => (
            "poll".to_owned(),
            Box::pin(async move {
                let next = dev.call_poll(acc, now).await?;
                clock.set_poll(idx, next.map(|t| t.max(now)));
                Ok(())
            }),
        ),
        Command::Counters(reply) => (
            "counters".to_owned(),
            Box::pin(async move {
                // The network only sends this to devices that export `counters`.
                let values = match ctr {
                    Some(c) => c.call_counters(acc).await?,
                    None => Vec::new(),
                };
                *reply.lock().unwrap_or_else(PoisonError::into_inner) = Some(values);
                Ok(())
            }),
        ),
        Command::Control(call) => (
            call.name().to_owned(),
            Box::pin(async move {
                let reschedule = call.may_reschedule();
                // The network only sends this to devices that report the call's export: the first
                // handler that takes it serves it (the call answers into its own slot).
                let mut call = Some(call);
                for handler in ctl {
                    let Some(c) = call.take() else { break };
                    match handler.serve(acc, c) {
                        Ok(served) => served.await?,
                        Err(c) => call = Some(c),
                    }
                }
                if let Some(c) = call {
                    c.unsupported();
                }
                // The call may move a stepped device's deadline: let it say so.
                if reschedule {
                    clock.poll_by(idx, now);
                }
                Ok(())
            }),
        ),
        // Typed bytes for stdin. The push wakes a guest read pending on stdin, which then
        // runs in this store's event loop at this instant.
        Command::Stdin(bytes) => (
            "stdin".to_owned(),
            Box::pin(async move {
                acc.with(|mut a| a.get().stdin.push(&bytes));
                Ok(())
            }),
        ),
    }
}
