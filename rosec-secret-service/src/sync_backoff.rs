//! Retry state held under the per-provider sync mutex, shared by scheduled
//! checks, notification nudges, and manual syncs.

use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Default)]
pub(crate) struct SyncBackoff {
    unlocked_at: Option<SystemTime>,
    failures: u32,
    retry_at: Option<Instant>,
    auth_failed: bool,
}

impl SyncBackoff {
    /// A fresh unlock starts a new session, including after an auth failure.
    pub fn observe_unlock(&mut self, unlocked_at: Option<SystemTime>) {
        if unlocked_at.is_some() && self.unlocked_at != unlocked_at {
            self.succeeded();
            self.unlocked_at = unlocked_at;
        }
    }

    pub fn ready(&self, now: Instant) -> bool {
        !self.auth_failed && self.retry_at.is_none_or(|retry_at| now >= retry_at)
    }

    pub fn has_failures(&self) -> bool {
        self.failures != 0
    }

    pub fn succeeded(&mut self) {
        self.failures = 0;
        self.retry_at = None;
        self.auth_failed = false;
    }

    pub fn failed(&mut self, now: Instant, auth_failed: bool) -> Duration {
        self.failures = self.failures.saturating_add(1);
        // 30, 60, 120, 240, then 300 seconds between completed attempts.
        let delay = Duration::from_secs((30 << (self.failures - 1).min(4)).min(300));
        self.retry_at = Some(now + delay);
        // Keep the terminal gate even if locking fails or a manual retry
        // subsequently encounters a temporary error. Only success/unlock resets it.
        self.auth_failed |= auth_failed;
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_back_off_from_completion_and_remain_capped() {
        let mut retry = SyncBackoff::default();
        let mut now = Instant::now();
        assert!(retry.ready(now));
        for seconds in [30, 60, 120, 240, 300, 300, 300] {
            let delay = retry.failed(now, false);
            assert_eq!(delay, Duration::from_secs(seconds));
            assert!(!retry.ready(now + delay - Duration::from_nanos(1)));
            now += delay;
            assert!(retry.ready(now));
        }
        retry.succeeded();
        assert!(retry.ready(now));
        assert!(!retry.has_failures());
        assert_eq!(retry.failed(now, false), Duration::from_secs(30));
    }

    #[test]
    fn authentication_failure_stops_retries_until_a_new_session() {
        let mut retry = SyncBackoff::default();
        let now = Instant::now();
        let unlocked = Some(SystemTime::now());
        retry.observe_unlock(unlocked);
        retry.failed(now, true);
        retry.failed(now, false);
        retry.observe_unlock(unlocked);
        assert!(!retry.ready(now + Duration::from_secs(86_400)));

        retry.observe_unlock(unlocked.map(|at| at + Duration::from_secs(1)));
        assert!(retry.ready(now));
        assert!(!retry.has_failures());
    }
}
