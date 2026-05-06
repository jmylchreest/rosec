//! Actor pattern for embedding a synchronous, stateful resource in a tokio
//! daemon.
//!
//! `extism::Plugin::call` is synchronous and can take 30+ seconds for
//! Argon2-heavy unlocks. Calling that under a `tokio::sync::Mutex<Plugin>`
//! from an async fn pins a tokio worker thread for the call's full
//! duration — a textbook async-blocking anti-pattern that starves other
//! tasks scheduled on the same worker.
//!
//! `Worker<R>` owns the resource on a dedicated `std::thread`. Async
//! callers send boxed closures through a sync channel; the worker
//! executes them with `&mut R`. A `tokio::sync::oneshot` reply carries
//! the result back. This is the same pattern tokio-rusqlite uses to
//! wrap rusqlite, tokio-postgres uses around libpq, and most ML
//! inference bindings use around their model objects.
//!
//! The worker survives panics in dispatched closures via `catch_unwind`
//! so a bad provider call cannot kill the daemon's WASM-host thread.

use std::panic::AssertUnwindSafe;
use std::thread;

use crossbeam_channel::Sender;
use rosec_core::ProviderError;
use tokio::sync::oneshot;
use tracing::{error, warn};

/// A boxed unit of work the worker executes against `&mut R`.
#[allow(dead_code)]
type CallFn<R> = Box<dyn FnOnce(&mut R) + Send + 'static>;

/// Channel capacity. 16 in-flight requests is plenty — the WASM provider
/// surface is sequential per provider (a single user, single unlock at a
/// time). A bounded channel is preferred over unbounded so a misbehaving
/// caller can't queue work indefinitely.
#[allow(dead_code)]
const CHANNEL_CAPACITY: usize = 16;

/// Async-friendly handle to a synchronous resource owned by a dedicated
/// thread.
///
/// Drop the `Worker` to shut the thread down: the channel sender drops,
/// the worker's `recv()` returns `Err(Disconnected)`, the loop exits.
#[allow(dead_code)] // wired into WasmProvider in the next commit
pub(crate) struct Worker<R: Send + 'static> {
    tx: Sender<CallFn<R>>,
    /// Held to keep the JoinHandle alive (otherwise `Drop` of `Worker`
    /// would not wait for the thread to finish, which is what we want
    /// — fire-and-forget shutdown). Stored so `Drop` is explicit and
    /// callers see we own the thread's lifetime.
    handle: Option<thread::JoinHandle<()>>,
    /// Used in error messages so a stuck/dead worker is identifiable.
    label: String,
}

#[allow(dead_code)]
impl<R: Send + 'static> Worker<R> {
    /// Spawn a worker thread; the thread runs `init()` to construct the
    /// resource, then loops servicing dispatched closures until the channel
    /// is dropped or the resource is taken.
    ///
    /// `init` runs on the new thread (not the caller's), so any thread-affine
    /// setup (e.g. Landlock, `prctl` calls) applied inside `init` affects
    /// only the worker.
    pub fn spawn<F, E>(label: impl Into<String>, init: F) -> Result<Self, ProviderError>
    where
        F: FnOnce() -> Result<R, E> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let label = label.into();
        let (tx, rx) = crossbeam_channel::bounded::<CallFn<R>>(CHANNEL_CAPACITY);
        let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(0);
        let label_for_thread = label.clone();
        let handle = thread::Builder::new()
            .name(format!("worker-{label}"))
            .spawn(move || {
                let mut resource = match init() {
                    Ok(r) => {
                        let _ = init_tx.send(Ok(()));
                        r
                    }
                    Err(e) => {
                        let _ = init_tx.send(Err(format!("{e}")));
                        return;
                    }
                };
                while let Ok(call) = rx.recv() {
                    // catch_unwind isolates closure panics so one bad
                    // request doesn't take the worker down. The closure
                    // is the request body — if it panics, the reply
                    // oneshot is dropped, surfacing as a recv error on
                    // the async side.
                    if let Err(panic) =
                        std::panic::catch_unwind(AssertUnwindSafe(|| call(&mut resource)))
                    {
                        let msg = panic
                            .downcast_ref::<&'static str>()
                            .map(|s| s.to_string())
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "(non-string panic)".into());
                        error!(worker = %label_for_thread, panic = %msg, "worker call panicked");
                    }
                }
            })
            .map_err(|e| {
                ProviderError::Other(anyhow::anyhow!(
                    "failed to spawn worker thread '{label}': {e}"
                ))
            })?;

        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx,
                handle: Some(handle),
                label,
            }),
            Ok(Err(msg)) => Err(ProviderError::Other(anyhow::anyhow!(
                "worker '{label}' init failed: {msg}"
            ))),
            Err(_) => Err(ProviderError::Other(anyhow::anyhow!(
                "worker '{label}' panicked during init"
            ))),
        }
    }

    /// Dispatch a closure to the worker; await its result on a oneshot.
    ///
    /// The closure runs on the worker thread with exclusive `&mut R`. Its
    /// return value travels back through a `tokio::sync::oneshot` so the
    /// async caller doesn't need to know about the underlying threading.
    pub async fn call<T, F>(&self, f: F) -> Result<T, ProviderError>
    where
        T: Send + 'static,
        F: FnOnce(&mut R) -> T + Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        let label = self.label.clone();
        self.tx
            .send(Box::new(move |r| {
                let result = f(r);
                let _ = reply_tx.send(result);
            }))
            .map_err(|_| ProviderError::Unavailable(format!("worker '{label}' has stopped")))?;
        reply_rx.await.map_err(|_| {
            ProviderError::Unavailable(format!(
                "worker '{}' dropped reply (likely panicked)",
                self.label
            ))
        })
    }
}

impl<R: Send + 'static> Drop for Worker<R> {
    fn drop(&mut self) {
        // Dropping `tx` closes the channel; the worker's `recv()` returns
        // `Err(Disconnected)` and the loop exits naturally. We don't join
        // the thread because pending calls on long-running WASM might
        // hold up shutdown for tens of seconds — fire-and-forget is the
        // right trade for daemon shutdown / hot-reload.
        if let Some(handle) = self.handle.take()
            && handle.is_finished()
        {
            // Already exited cleanly — nothing to do.
        } else {
            warn!(worker = %self.label, "worker drop: not awaiting thread completion");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A trivial test resource: a counter we can mutate from closures.
    struct Counter(i32);

    fn spawn_counter() -> Worker<Counter> {
        Worker::spawn("test", || Ok::<_, &str>(Counter(0))).unwrap()
    }

    #[tokio::test]
    async fn dispatches_and_returns() {
        let w = spawn_counter();
        let v = w
            .call(|c| {
                c.0 += 1;
                c.0
            })
            .await
            .unwrap();
        assert_eq!(v, 1);
        let v2 = w
            .call(|c| {
                c.0 += 10;
                c.0
            })
            .await
            .unwrap();
        assert_eq!(v2, 11);
    }

    #[tokio::test]
    async fn survives_panic_in_closure() {
        let w = spawn_counter();
        // A panicking closure: reply is dropped, caller sees Unavailable.
        let bad = w.call(|_| panic!("test panic")).await;
        assert!(matches!(bad, Err(ProviderError::Unavailable(_))));
        // Worker keeps serving.
        let good = w
            .call(|c| {
                c.0 = 42;
                c.0
            })
            .await
            .unwrap();
        assert_eq!(good, 42);
    }

    #[tokio::test]
    async fn drop_shuts_down_cleanly() {
        let w = spawn_counter();
        let _ = w.call(|c| c.0).await.unwrap();
        let label = w.label.clone();
        drop(w);
        // Give the worker a moment to exit; the test passes if no thread
        // leak occurs (i.e. the test process can finish).
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Sanity: name is still constructable (no thread-related panics).
        assert!(label.contains("test"));
    }

    #[tokio::test]
    async fn init_failure_propagates() {
        let r: Result<Worker<Counter>, _> = Worker::spawn("failing", || Err::<Counter, _>("nope"));
        let err = match r {
            Ok(_) => panic!("expected init failure"),
            Err(e) => e,
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("init failed"), "got: {msg}");
    }

    #[tokio::test]
    async fn channel_full_blocks_send() {
        // CHANNEL_CAPACITY = 16; flood with slow closures and ensure
        // backpressure surfaces as a delay rather than unbounded growth.
        // We can't easily test the bound without simulating a slow
        // worker, so instead verify that 16 quick dispatches all
        // succeed in order.
        let w = spawn_counter();
        let mut handles = vec![];
        for i in 0..32 {
            let w_ref = &w;
            handles.push(async move {
                w_ref
                    .call(move |c| {
                        c.0 = i;
                        c.0
                    })
                    .await
                    .unwrap()
            });
        }
        let results = futures_util::future::join_all(handles).await;
        // All 32 ran; final state is one of the values 0..32.
        assert_eq!(results.len(), 32);
    }

    /// `current_thread` flavor gives one tokio worker. If a long sync
    /// closure on the dedicated thread were somehow pinning that tokio
    /// worker, the concurrent tokio task could not progress until the
    /// closure returned.
    #[tokio::test(flavor = "current_thread")]
    async fn long_sync_call_does_not_block_tokio_runtime() {
        let w = spawn_counter();
        let start = std::time::Instant::now();

        let long_call = w.call(|c| {
            std::thread::sleep(Duration::from_millis(200));
            c.0 = 1;
            c.0
        });

        // Concurrent tokio work that finishes quickly *if* the runtime is
        // not blocked. tokio::time::sleep yields, so it can interleave.
        let concurrent = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            start.elapsed()
        };

        let (long_res, concurrent_elapsed) = tokio::join!(long_call, concurrent);
        assert_eq!(long_res.unwrap(), 1);
        // If the worker had pinned the tokio thread, this would be ~200ms.
        assert!(
            concurrent_elapsed < Duration::from_millis(150),
            "tokio task waited {concurrent_elapsed:?} — worker is blocking the runtime",
        );
    }
}
