//! Resolve the requested virtual collection/item projection without parsing IDs
//! out of object paths. Provider locks remain global and provider-wide.
use crate::state::{ServiceState, map_provider_error};

pub(crate) struct UnlockPlan {
    pub unlocked: Vec<String>,
    pub pending: Vec<UnlockTarget>,
    pub next_provider: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UnlockTarget {
    pub path: String,
    pub providers: Vec<String>,
    collection: bool,
}

pub(crate) fn targets<'a>(
    state: &ServiceState,
    paths: impl IntoIterator<Item = &'a str>,
) -> Vec<UnlockTarget> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let layout = state.collections();
    for path in paths {
        if !seen.insert(path) {
            continue;
        }
        let view = layout.at(path);
        let providers = if let Some(view) = view {
            state
                .providers_ordered()
                .iter()
                .filter(|p| view.includes(p.id()))
                .map(|p| p.id().to_owned())
                .collect()
        } else if let Ok((provider, _)) = state.provider_and_id_for_path(path) {
            vec![provider.id().to_owned()]
        } else {
            continue;
        };
        targets.push(UnlockTarget {
            path: path.to_owned(),
            providers,
            collection: view.is_some(),
        });
    }
    targets
}

pub(crate) async fn resolve(
    state: &ServiceState,
    targets: &[UnlockTarget],
) -> zbus::fdo::Result<UnlockPlan> {
    let mut statuses = std::collections::HashMap::new();
    for provider in state.providers_ordered() {
        if targets
            .iter()
            .any(|target| target.providers.iter().any(|id| id == provider.id()))
        {
            statuses.insert(
                provider.id().to_owned(),
                provider.status().await.map_err(map_provider_error)?.locked,
            );
        }
    }
    let mut plan = UnlockPlan {
        unlocked: Vec::new(),
        pending: Vec::new(),
        next_provider: None,
    };
    let mut collection_candidate = None;
    for target in targets {
        let ids = &target.providers;
        if ids.iter().any(|id| statuses.get(id) == Some(&false)) {
            plan.unlocked.push(target.path.clone());
        } else {
            let candidate = ids
                .iter()
                .find(|id| statuses.get(*id) == Some(&true))
                .cloned();
            if target.collection {
                collection_candidate = collection_candidate.or(candidate);
            } else {
                plan.next_provider = plan.next_provider.or(candidate);
            }
            plan.pending.push(target.clone());
        }
    }
    plan.next_provider = plan.next_provider.or(collection_candidate);
    Ok(plan)
}
