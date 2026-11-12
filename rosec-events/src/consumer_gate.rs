//! Serializes snapshot publication with revocation, without holding a lock over I/O.
use rosec_core::Provider;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

#[derive(Default)]
pub struct ConsumerGate(Mutex<State>);
#[derive(Default)]
struct State {
    epoch: u64,
    sources: HashMap<String, (Weak<dyn Provider>, bool)>,
}
impl ConsumerGate {
    /// Registration is explicit so a queued rebuild cannot reintroduce a removed instance.
    pub fn register(&self, provider: &Arc<dyn Provider>) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let source = Arc::downgrade(provider);
        if s.sources
            .get(provider.id())
            .is_some_and(|(old, _)| old.ptr_eq(&source))
        {
            return;
        }
        s.epoch += 1;
        s.sources.insert(provider.id().to_owned(), (source, true));
    }
    pub fn activate(&self, provider: &Arc<dyn Provider>) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((source, enabled)) = s.sources.get_mut(provider.id())
            && source.ptr_eq(&Arc::downgrade(provider))
        {
            *enabled = true;
            s.epoch += 1;
        }
    }
    pub fn begin(&self, providers: &[Arc<dyn Provider>]) -> (Option<u64>, Vec<Arc<dyn Provider>>) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if providers.iter().any(|p| {
            !s.sources
                .get(p.id())
                .is_some_and(|(source, _)| source.ptr_eq(&Arc::downgrade(p)))
        }) {
            // A queued request carrying retired instances must not clear a newer view.
            return (None, Vec::new());
        }
        s.epoch += 1;
        let providers = providers
            .iter()
            .filter(|p| {
                s.sources
                    .get(p.id())
                    .is_some_and(|(source, enabled)| *enabled && source.ptr_eq(&Arc::downgrade(p)))
            })
            .map(Arc::clone)
            .collect();
        (Some(s.epoch), providers)
    }
    pub fn publish(&self, epoch: Option<u64>, install: impl FnOnce()) -> bool {
        let s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if Some(s.epoch) != epoch {
            return false;
        }
        install();
        true
    }
    /// Delayed lifecycle callbacks may only revoke their own registered instance.
    pub fn revoke_source(&self, provider: &Arc<dyn Provider>, evict: impl FnOnce()) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some((source, enabled)) = s.sources.get_mut(provider.id()) else {
            return;
        };
        if !source.ptr_eq(&Arc::downgrade(provider)) {
            return;
        }
        *enabled = false;
        s.epoch += 1;
        evict();
    }
    pub fn revoke(&self, provider: Option<&str>, evict: impl FnOnce()) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.epoch += 1;
        for (id, (_, enabled)) in &mut s.sources {
            if provider.is_none_or(|p| p == id) {
                *enabled = false;
            }
        }
        evict();
    }
}
