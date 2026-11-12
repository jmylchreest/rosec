use rosec_events::run_consumer;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

#[tokio::test]
async fn worker_retries_and_observes_changes_during_a_rebuild() {
    let (tx, rx) = tokio::sync::watch::channel(0);
    let attempts = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let task = {
        let attempts = attempts.clone();
        let started = started.clone();
        let release = release.clone();
        tokio::spawn(run_consumer(rx, move || {
            let attempts = attempts.clone();
            let started = started.clone();
            let release = release.clone();
            async move {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    return Some(false);
                }
                if attempt == 1 {
                    started.notify_one();
                    release.notified().await;
                }
                Some(true)
            }
        }))
    };
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    tx.send_replace(1);
    tx.send_replace(2);
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while attempts.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(tx);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}
