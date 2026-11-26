//! A device's fuel on wasmtime: its budget per virtual instant, what it consumed (reported to
//! its cost meter), and its fuel spans ([`FuelSpan`]), in which its work costs it nothing.
//!
//! The book lives in the store's [`HostState`], so that both places that look into the store's
//! fuel reach it: the device's actor (before and after every round of guest work) and a served
//! call of a portable interface (`crate::portable::call`), where a span begins or ends in the
//! middle of the device's own call.

use wasmnet_core::{CostMeter, FuelSpan, Nanos};
use wasmtime::{AsContextMut, StoreContextMut};

use crate::wasi::HostState;

/// One store's fuel book.
pub(crate) struct Book {
    /// Fuel per instant.
    budget: u64,
    /// The store's engine meters fuel (components with a budget of their own run without).
    metered: bool,
    /// The instant of the last refill; `None` before the actor first ran.
    last: Option<Nanos>,
    /// The fuel left when last looked at.
    left: u64,
    /// Where consumption is reported.
    meter: CostMeter,
    span: FuelSpan,
    /// While a span is applied: the device's fuel when it began.
    saved: Option<u64>,
}

impl Book {
    pub(crate) fn new(budget: u64, metered: bool, meter: CostMeter, span: FuelSpan) -> Self {
        Self {
            budget,
            metered,
            last: None,
            left: 0,
            meter,
            span,
            saved: None,
        }
    }
}

fn book<'a>(store: &'a mut StoreContextMut<'_, HostState>) -> Option<&'a mut Book> {
    store.data_mut().fuel.as_mut()
}

/// Before guest work, at every poll of the actor: counts what ran since the last look, refills
/// the store the first time the actor runs at a new instant (which ends a span of an earlier
/// instant), and applies a span's beginning or end asked for since.
pub(crate) fn refill(
    mut store: StoreContextMut<'_, HostState>,
    now: Nanos,
) -> wasmtime::Result<()> {
    account(store.as_context_mut())?;
    let Some(b) = book(&mut store) else {
        return Ok(());
    };
    if b.last != Some(now) {
        b.last = Some(now);
        // The fuel a span saved belongs to its own instant.
        b.saved = None;
        b.left = b.budget;
        let (budget, metered) = (b.budget, b.metered);
        if metered {
            store.set_fuel(budget)?;
        }
    }
    apply_span(store)
}

/// Reports the fuel consumed since the last look. It was all consumed under the budget of the
/// instant of the last refill (`last`), even when it is reported at the next instant's first
/// look: only a refill resets the store's fuel. If a host call gave fuel back to the store (more
/// is left than at the last look), that counts as nothing consumed. Inside a span nothing is
/// reported, and the store's allowance is set back to the budget.
pub(crate) fn account(mut store: StoreContextMut<'_, HostState>) -> wasmtime::Result<()> {
    let Some(b) = book(&mut store) else {
        return Ok(());
    };
    if !b.metered {
        return Ok(());
    }
    let left = store.get_fuel()?;
    let Some(b) = book(&mut store) else {
        return Ok(());
    };
    if b.saved.is_some() {
        let budget = b.budget;
        b.left = budget;
        store.set_fuel(budget)?;
        return Ok(());
    }
    let used = b.left.saturating_sub(left);
    match b.last {
        Some(at) => b.meter.add_fuel_at(at, used),
        // Before the first refill (instantiation and `ports()` ran on their own budget, and
        // the first look sees none of it): nothing.
        None => b.meter.add_fuel(used),
    }
    b.left = left;
    Ok(())
}

/// After a served call returned (the device is between two instructions of its own call): a
/// span begun or ended in it applies now, and an open span's allowance is set back.
pub(crate) fn served(mut store: StoreContextMut<'_, HostState>) -> wasmtime::Result<()> {
    let Some(b) = book(&mut store) else {
        return Ok(());
    };
    // Before the actor first ran (instantiation, `ports()`), or no span involved: nothing.
    if b.last.is_none() || (b.saved.is_none() && !b.span.is_open()) {
        return Ok(());
    }
    account(store.as_context_mut())?;
    apply_span(store)
}

/// Opens or closes the store's span to match its handle.
fn apply_span(mut store: StoreContextMut<'_, HostState>) -> wasmtime::Result<()> {
    let Some(b) = book(&mut store) else {
        return Ok(());
    };
    if !b.metered {
        return Ok(());
    }
    match (b.span.is_open(), b.saved) {
        (true, None) => {
            // Everything before it was counted by the look just taken.
            let budget = b.budget;
            let fuel = store.get_fuel()?;
            let b = book(&mut store).expect("checked above");
            b.saved = Some(fuel);
            b.left = budget;
            store.set_fuel(budget)
        }
        (false, Some(saved)) => {
            b.saved = None;
            b.left = saved;
            store.set_fuel(saved)
        }
        _ => Ok(()),
    }
}
