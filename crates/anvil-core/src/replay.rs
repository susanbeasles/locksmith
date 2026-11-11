use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub use crate::error::ReplayError;

/// Default monotonic clock skew window (`+-30_000` milliseconds = `+-30s`).
pub const DEFAULT_SKEW_WINDOW_MS: u64 = 30_000;

/// Configuration for [`ReplayFilter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayFilterConfig {
    /// Allowed bidirectional timestamp skew around `now_ms`.
    pub skew_window_ms: u64,
    /// Hard upper bound on concurrently tracked unexpired nonces.
    pub max_entries: usize,
}

#[derive(Debug)]
struct ReplayState {
    burned: HashMap<[u8; 32], u64>,
    order: VecDeque<([u8; 32], u64)>,
}

impl ReplayState {
    fn is_expired(recorded_ts: u64, now_ms: u64, skew_window_ms: u64) -> bool {
        now_ms.saturating_sub(recorded_ts) > skew_window_ms
    }

    fn purge_expired_front(&mut self, now_ms: u64, skew_window_ms: u64) {
        while let Some(&(front_nonce, front_ts)) = self.order.front() {
            if Self::is_expired(front_ts, now_ms, skew_window_ms) {
                self.order.pop_front();
                self.burned.remove(&front_nonce);
            } else {
                break;
            }
        }
    }

    fn purge_expired_full(&mut self, now_ms: u64, skew_window_ms: u64) {
        self.burned
            .retain(|_, &mut ts| !Self::is_expired(ts, now_ms, skew_window_ms));
        self.order
            .retain(|&(_, ts)| !Self::is_expired(ts, now_ms, skew_window_ms));
    }
}

/// Bounded-memory concurrency-safe single-use nonce tracker.
#[derive(Debug)]
pub struct ReplayFilter {
    config: ReplayFilterConfig,
    state: Mutex<ReplayState>,
}

impl ReplayFilter {
    /// Creates a new [`ReplayFilter`] with explicit skew and capacity bounds.
    pub fn new(config: ReplayFilterConfig) -> Result<Self, ReplayError> {
        if config.skew_window_ms == 0 || config.max_entries == 0 {
            return Err(ReplayError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            state: Mutex::new(ReplayState {
                burned: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// Creates a [`ReplayFilter`] with `DEFAULT_SKEW_WINDOW_MS` (`+-30s`).
    pub fn with_defaults(max_entries: usize) -> Result<Self, ReplayError> {
        Self::new(ReplayFilterConfig {
            skew_window_ms: DEFAULT_SKEW_WINDOW_MS,
            max_entries,
        })
    }

    /// Validates `timestamp_ms` against `now_ms +- skew_window_ms` and atomically burns `nonce`.
    pub fn check_and_burn(
        &self,
        nonce: [u8; 32],
        timestamp_ms: u64,
        now_ms: u64,
    ) -> Result<(), ReplayError> {
        if now_ms > timestamp_ms && now_ms - timestamp_ms > self.config.skew_window_ms {
            return Err(ReplayError::TimestampExpired {
                timestamp_ms,
                now_ms,
                skew_window_ms: self.config.skew_window_ms,
            });
        }
        if timestamp_ms > now_ms && timestamp_ms - now_ms > self.config.skew_window_ms {
            return Err(ReplayError::TimestampInFuture {
                timestamp_ms,
                now_ms,
                skew_window_ms: self.config.skew_window_ms,
            });
        }

        let mut guard = self.state.lock().map_err(|_| ReplayError::StateCorrupted)?;
        guard.purge_expired_front(now_ms, self.config.skew_window_ms);

        if let Some(&recorded_ts) = guard.burned.get(&nonce) {
            if !ReplayState::is_expired(recorded_ts, now_ms, self.config.skew_window_ms) {
                return Err(ReplayError::NonceAlreadyBurned);
            }
            guard.burned.remove(&nonce);
        }

        if guard.burned.len() >= self.config.max_entries {
            guard.purge_expired_full(now_ms, self.config.skew_window_ms);
            if guard.burned.len() >= self.config.max_entries {
                return Err(ReplayError::CapacityExceeded {
                    max_entries: self.config.max_entries,
                });
            }
        }

        guard.burned.insert(nonce, timestamp_ms);
        guard.order.push_back((nonce, timestamp_ms));
        Ok(())
    }

    /// Validates and burns `nonce` against the host `SystemTime`.
    pub fn check_and_burn_system_time(
        &self,
        nonce: [u8; 32],
        timestamp_ms: u64,
    ) -> Result<(), ReplayError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReplayError::StateCorrupted)?;
        let now_ms =
            u64::try_from(duration.as_millis()).map_err(|_| ReplayError::StateCorrupted)?;
        self.check_and_burn(nonce, timestamp_ms, now_ms)
    }

    /// Returns the number of currently retained nonces in the filter.
    pub fn active_count(&self) -> Result<usize, ReplayError> {
        let guard = self.state.lock().map_err(|_| ReplayError::StateCorrupted)?;
        Ok(guard.burned.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn enforces_skew_window_and_single_use_burn() {
        let filter = ReplayFilter::with_defaults(128).unwrap();
        let now = 1_700_000_000_000u64;
        let nonce = [0x42; 32];

        assert!(filter.check_and_burn(nonce, now - 10_000, now).is_ok());
        assert_eq!(
            filter.check_and_burn(nonce, now - 10_000, now).unwrap_err(),
            ReplayError::NonceAlreadyBurned
        );

        let expired_nonce = [0x43; 32];
        assert!(matches!(
            filter
                .check_and_burn(expired_nonce, now - 30_001, now)
                .unwrap_err(),
            ReplayError::TimestampExpired { .. }
        ));

        let future_nonce = [0x44; 32];
        assert!(matches!(
            filter
                .check_and_burn(future_nonce, now + 30_001, now)
                .unwrap_err(),
            ReplayError::TimestampInFuture { .. }
        ));
    }

    #[test]
    fn purges_expired_entries_and_fails_closed_at_live_capacity() {
        let filter = ReplayFilter::new(ReplayFilterConfig {
            skew_window_ms: 30_000,
            max_entries: 2,
        })
        .unwrap();
        let t0 = 1_000_000u64;
        assert!(filter.check_and_burn([1; 32], t0, t0).is_ok());
        assert!(filter.check_and_burn([2; 32], t0, t0).is_ok());
        assert_eq!(
            filter.check_and_burn([3; 32], t0, t0).unwrap_err(),
            ReplayError::CapacityExceeded { max_entries: 2 }
        );

        // Advance past 2 * skew_window_ms so t0 entries cannot possibly be replayed cleanly
        let t_later = t0 + 60_001;
        assert!(filter.check_and_burn([3; 32], t_later, t_later).is_ok());
        assert_eq!(filter.active_count().unwrap(), 1);
    }
}
