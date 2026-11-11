use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClockDomain {
    MonotonicSystem,
    ExplicitCaller,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BurnedRecord {
    expires_at_ms: u64,
    domain: ClockDomain,
}

#[derive(Debug)]
struct ReplayState {
    /// Maps active `nonce -> BurnedRecord`.
    burned: HashMap<[u8; 32], BurnedRecord>,
    /// FIFO queue of `(nonce, expires_at_ms)` burned under `monotonic_now_ms()`.
    system_order: VecDeque<([u8; 32], u64)>,
    /// FIFO queue of `(nonce, expires_at_ms)` burned under explicit `check_and_burn` callers.
    explicit_order: VecDeque<([u8; 32], u64)>,
    /// Monotonic high-water mark strictly scoped to explicit `check_and_burn` callers.
    explicit_high_water_ms: u64,
}

impl ReplayState {
    const fn is_expired_at(expires_at_ms: u64, domain_now_ms: u64) -> bool {
        expires_at_ms < domain_now_ms
    }

    const fn is_record_expired(
        record: BurnedRecord,
        system_now_ms: u64,
        explicit_now_ms: u64,
    ) -> bool {
        match record.domain {
            ClockDomain::MonotonicSystem => {
                Self::is_expired_at(record.expires_at_ms, system_now_ms)
            }
            ClockDomain::ExplicitCaller => {
                Self::is_expired_at(record.expires_at_ms, explicit_now_ms)
            }
        }
    }

    fn purge_expired_front(&mut self, system_now_ms: u64, explicit_now_ms: u64) {
        while let Some(&(front_nonce, front_expires_at)) = self.system_order.front() {
            if Self::is_expired_at(front_expires_at, system_now_ms) {
                self.system_order.pop_front();
                if self.burned.get(&front_nonce)
                    == Some(&BurnedRecord {
                        expires_at_ms: front_expires_at,
                        domain: ClockDomain::MonotonicSystem,
                    })
                {
                    self.burned.remove(&front_nonce);
                }
            } else {
                break;
            }
        }

        while let Some(&(front_nonce, front_expires_at)) = self.explicit_order.front() {
            if Self::is_expired_at(front_expires_at, explicit_now_ms) {
                self.explicit_order.pop_front();
                if self.burned.get(&front_nonce)
                    == Some(&BurnedRecord {
                        expires_at_ms: front_expires_at,
                        domain: ClockDomain::ExplicitCaller,
                    })
                {
                    self.burned.remove(&front_nonce);
                }
            } else {
                break;
            }
        }
    }

    fn purge_expired_full(&mut self, system_now_ms: u64, explicit_now_ms: u64) {
        self.burned
            .retain(|_, &mut rec| !Self::is_record_expired(rec, system_now_ms, explicit_now_ms));
        self.system_order.retain(|&(nonce, expires_at)| {
            self.burned.get(&nonce)
                == Some(&BurnedRecord {
                    expires_at_ms: expires_at,
                    domain: ClockDomain::MonotonicSystem,
                })
        });
        self.explicit_order.retain(|&(nonce, expires_at)| {
            self.burned.get(&nonce)
                == Some(&BurnedRecord {
                    expires_at_ms: expires_at,
                    domain: ClockDomain::ExplicitCaller,
                })
        });
    }

    fn total_queued(&self) -> usize {
        self.system_order
            .len()
            .saturating_add(self.explicit_order.len())
    }
}

/// Bounded-memory concurrency-safe single-use nonce tracker.
#[derive(Debug)]
pub struct ReplayFilter {
    config: ReplayFilterConfig,
    anchor_instant: Instant,
    anchor_epoch_ms: u64,
    /// Monotonic high-water mark updated **exclusively** by [`Self::monotonic_now_ms`].
    last_now_ms: AtomicU64,
    state: Mutex<ReplayState>,
}

impl ReplayFilter {
    /// Creates a new [`ReplayFilter`] with explicit skew and capacity bounds.
    pub fn new(config: ReplayFilterConfig) -> Result<Self, ReplayError> {
        if config.skew_window_ms == 0 || config.max_entries == 0 {
            return Err(ReplayError::InvalidConfiguration);
        }
        let anchor_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);

        Ok(Self {
            config,
            anchor_instant: Instant::now(),
            anchor_epoch_ms,
            last_now_ms: AtomicU64::new(anchor_epoch_ms),
            state: Mutex::new(ReplayState {
                burned: HashMap::new(),
                system_order: VecDeque::new(),
                explicit_order: VecDeque::new(),
                explicit_high_water_ms: 0,
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

    /// Returns a monotonically non-decreasing epoch millisecond reading anchored
    /// to [`std::time::Instant`], immune to OS `SystemTime` NTP backward steps and
    /// isolated from caller-supplied timestamps in [`Self::check_and_burn`].
    #[must_use]
    pub fn monotonic_now_ms(&self) -> u64 {
        let elapsed_ms =
            u64::try_from(self.anchor_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
        let candidate = self.anchor_epoch_ms.saturating_add(elapsed_ms);
        let prev = self.last_now_ms.fetch_max(candidate, Ordering::SeqCst);
        candidate.max(prev)
    }

    fn check_and_burn_in_domain(
        &self,
        nonce: [u8; 32],
        timestamp_ms: u64,
        caller_now_ms: Option<u64>,
    ) -> Result<(), ReplayError> {
        let mut guard = self.state.lock().map_err(|_| ReplayError::StateCorrupted)?;
        let system_now_ms = self.monotonic_now_ms();
        let (domain, effective_now_ms, explicit_now_ms) = match caller_now_ms {
            None => (
                ClockDomain::MonotonicSystem,
                system_now_ms,
                guard.explicit_high_water_ms,
            ),
            Some(raw_now_ms) => {
                let clamped = raw_now_ms.max(guard.explicit_high_water_ms);
                guard.explicit_high_water_ms = clamped;
                (ClockDomain::ExplicitCaller, clamped, clamped)
            }
        };

        if effective_now_ms > timestamp_ms
            && effective_now_ms - timestamp_ms > self.config.skew_window_ms
        {
            return Err(ReplayError::TimestampExpired {
                timestamp_ms,
                now_ms: effective_now_ms,
                skew_window_ms: self.config.skew_window_ms,
            });
        }
        if timestamp_ms > effective_now_ms
            && timestamp_ms - effective_now_ms > self.config.skew_window_ms
        {
            return Err(ReplayError::TimestampInFuture {
                timestamp_ms,
                now_ms: effective_now_ms,
                skew_window_ms: self.config.skew_window_ms,
            });
        }

        guard.purge_expired_front(system_now_ms, explicit_now_ms);

        if let Some(&record) = guard.burned.get(&nonce) {
            if !ReplayState::is_record_expired(record, system_now_ms, explicit_now_ms) {
                return Err(ReplayError::NonceAlreadyBurned);
            }
            guard.burned.remove(&nonce);
        }

        if guard.burned.len() >= self.config.max_entries
            || guard.total_queued() >= self.config.max_entries
        {
            guard.purge_expired_full(system_now_ms, explicit_now_ms);
            if guard.burned.len() >= self.config.max_entries
                || guard.total_queued() >= self.config.max_entries
            {
                return Err(ReplayError::CapacityExceeded {
                    max_entries: self.config.max_entries,
                });
            }
        }

        let retention_ms = self.config.skew_window_ms.saturating_mul(2);
        let expires_at_ms = effective_now_ms.saturating_add(retention_ms);
        guard.burned.insert(
            nonce,
            BurnedRecord {
                expires_at_ms,
                domain,
            },
        );
        match domain {
            ClockDomain::MonotonicSystem => guard.system_order.push_back((nonce, expires_at_ms)),
            ClockDomain::ExplicitCaller => guard.explicit_order.push_back((nonce, expires_at_ms)),
        }
        Ok(())
    }

    /// Validates `timestamp_ms` against explicit `now_ms +- skew_window_ms` and
    /// atomically burns `nonce` across the full `2 * skew_window_ms` validity span
    /// without mutating [`Self::monotonic_now_ms`] state.
    pub fn check_and_burn(
        &self,
        nonce: [u8; 32],
        timestamp_ms: u64,
        now_ms: u64,
    ) -> Result<(), ReplayError> {
        self.check_and_burn_in_domain(nonce, timestamp_ms, Some(now_ms))
    }

    /// Alias for [`Self::check_and_burn`] accepting an explicit caller clock reading.
    pub fn check_and_burn_at(
        &self,
        nonce: [u8; 32],
        timestamp_ms: u64,
        now_ms: u64,
    ) -> Result<(), ReplayError> {
        self.check_and_burn_in_domain(nonce, timestamp_ms, Some(now_ms))
    }

    /// Validates and burns `nonce` against the monotonic clock anchored at filter startup.
    pub fn check_and_burn_system_time(
        &self,
        nonce: [u8; 32],
        timestamp_ms: u64,
    ) -> Result<(), ReplayError> {
        self.check_and_burn_in_domain(nonce, timestamp_ms, None)
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
