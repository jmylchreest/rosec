//! Resolve the requested virtual collection/item projection without parsing IDs
//! out of object paths. Provider locks remain global and provider-wide.
use crate::state::{ServiceState, map_provider_error};

pub(crate) struct UnlockPlan {
    pub unlocked: Vec<String>,
    pub pending: Vec<String>,
    pub next_provider: Option<String>,
}

pub(crate) fn targets<'a>(
    state: &ServiceState,
    paths: impl IntoIterator<Item = &'a str>,
) -> Vec<(String, Vec<String>)> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        if !seen.insert(path) {
            continue;
        }
        let providers = if let Some(view) = state.collections.at(path) {
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
        targets.push((path.to_owned(), providers));
    }
    targets
}

pub(crate) async fn resolve(
    state: &ServiceState,
    paths: &[String],
) -> zbus::fdo::Result<UnlockPlan> {
    let targets = targets(state, paths.iter().map(String::as_str));
    let mut statuses = std::collections::HashMap::new();
    for provider in state.providers_ordered() {
        if targets
            .iter()
            .any(|(_, ids)| ids.iter().any(|id| id == provider.id()))
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
    for (path, ids) in targets {
        if ids.iter().any(|id| statuses.get(id) == Some(&false)) {
            plan.unlocked.push(path);
        } else {
            let candidate = ids.into_iter().find(|id| statuses.get(id) == Some(&true));
            if state.collections.at(&path).is_some() {
                collection_candidate = collection_candidate.or(candidate);
            } else {
                plan.next_provider = plan.next_provider.or(candidate);
            }
            plan.pending.push(path);
        }
    }
    plan.next_provider = plan.next_provider.or(collection_candidate);
    Ok(plan)
}
