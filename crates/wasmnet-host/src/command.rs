//! The command runner: one `wasi:cli/run` component under a virtual clock.

use wasmtime::Store;
use wasmtime::component::Component;

use crate::wasi::HostState;
use crate::{Error, Host, Result, SimConfig, runtime_error};
use wasmnet_core::{Nanos, OutputCapture, VirtualClock, block_on};

/// What a command component left behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    /// `true` if `run` returned `ok`.
    pub success: bool,
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
    /// Virtual time when the command started.
    pub started_at: Nanos,
    /// Virtual time when it finished.
    pub finished_at: Nanos,
}

/// One deterministic simulation: a seed and the virtual clock all its components share.
pub struct Sim<'h> {
    host: &'h Host,
    config: SimConfig,
    clock: VirtualClock,
}

impl<'h> Sim<'h> {
    pub(crate) fn new(host: &'h Host, config: SimConfig) -> Self {
        Self {
            host,
            clock: VirtualClock::new(config.wall_epoch),
            config,
        }
    }

    /// The simulation's virtual clock.
    pub fn clock(&self) -> &VirtualClock {
        &self.clock
    }

    /// The simulation's configuration.
    pub fn config(&self) -> &SimConfig {
        &self.config
    }

    /// Instantiates `component` as `name` and runs its `wasi:cli/run` export to completion.
    ///
    /// `name` is both `argv[0]` and the key for the component's RNG seeds. Virtual time
    /// advances only while every task in the store is waiting on a virtual timer. A command
    /// that waits with no timer left to fire is an [`Error::Deadlock`] on `wasi:cli/run`.
    /// Commands have no fuel limit.
    pub fn run_command(
        &self,
        name: &str,
        component: &Component,
        args: &[&str],
    ) -> Result<CommandOutput> {
        let exports = self.host.exports(component);
        let exports_run = |v: &str| exports.iter().any(|e| e.starts_with(v));
        let p3 = exports_run("wasi:cli/run@0.3");
        if !p3 && !exports_run("wasi:cli/run@0.2") {
            return Err(Error::NotACommand(name.to_owned()));
        }
        let (stdout, stderr) = (OutputCapture::new(), OutputCapture::new());
        let mut state = HostState::new(
            &self.clock,
            self.config.seed,
            name,
            args,
            stdout.clone(),
            stderr.clone(),
        );
        self.host.init_store(&mut state)?;
        let (linker, metered) = self.host.linker_for(component);
        let mut store = Store::new(component.engine(), state);
        self.host.store_created(&mut store);
        if metered {
            store.set_fuel(u64::MAX).map_err(runtime_error)?;
        }
        let started_at = self.clock.now();

        let run = block_on(&self.clock, async {
            if p3 {
                use wasmtime_wasi::p3::bindings::Command;
                let cmd = Command::instantiate_async(&mut store, component, linker).await?;
                store
                    .run_concurrent(async move |s| cmd.wasi_cli_run().call_run(s).await)
                    .await?
            } else {
                use wasmtime_wasi::p2::bindings::Command;
                let cmd = Command::instantiate_async(&mut store, component, linker).await?;
                cmd.wasi_cli_run().call_run(&mut store).await
            }
        })
        .map_err(|stalled| Error::Deadlock {
            at: stalled.at,
            outstanding: vec![(name.to_owned(), "wasi:cli/run".to_owned())],
        })?;

        let success = match run {
            Ok(result) => result.is_ok(),
            // `wasi:cli/exit` surfaces as a trap carrying the exit code.
            Err(e) => match e.downcast_ref::<wasmtime_wasi::I32Exit>() {
                Some(exit) => exit.0 == 0,
                None => return Err(runtime_error(e)),
            },
        };
        Ok(CommandOutput {
            success,
            stdout: stdout.contents(),
            stderr: stderr.contents(),
            started_at,
            finished_at: self.clock.now(),
        })
    }
}
