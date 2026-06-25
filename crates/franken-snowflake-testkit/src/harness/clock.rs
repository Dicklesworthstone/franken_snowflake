//! Injected, deterministic time for backoff and TTL.
//!
//! Tests must not sleep and must not read the wall clock for control flow, or
//! their timings and orderings stop being reproducible. This module supplies:
//!
//! - [`Clock`] — a trait abstracting "what time is it", with a real
//!   [`SystemClock`] and a [`ManualClock`] that only advances when told to.
//! - [`DeterministicRng`] — a small seeded SplitMix64 generator, so jitter is a
//!   pure function of its seed.
//! - [`Deadline`] — a clock-relative TTL check.
//! - [`backoff_schedule`] — a reproducible exponential-backoff-with-jitter
//!   sequence: same `(policy, seed)` always yields the same `Vec<Duration>`.
//!
//! Nothing here sleeps or touches the network; it is pure arithmetic plus an
//! optional real-clock read.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Abstract monotonic time source. [`Clock::now`] is non-decreasing within a
/// single clock instance.
pub trait Clock {
    /// Time elapsed since this clock's epoch.
    fn now(&self) -> Duration;
}

/// A real, monotonic clock anchored at construction (`Instant`-backed).
#[derive(Clone, Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Anchor a system clock at the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A clock that advances only on explicit [`ManualClock::advance`] /
/// [`ManualClock::set`]. Thread-safe via an atomic nanosecond counter, so it can
/// be shared by reference across a scoped concurrency test.
#[derive(Debug)]
pub struct ManualClock {
    nanos: AtomicU64,
}

impl ManualClock {
    /// A manual clock starting at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nanos: AtomicU64::new(0),
        }
    }

    /// A manual clock starting at `start`.
    #[must_use]
    pub fn at(start: Duration) -> Self {
        Self {
            nanos: AtomicU64::new(saturating_nanos(start)),
        }
    }

    /// Advance the clock by `delta`.
    pub fn advance(&self, delta: Duration) {
        let delta_nanos = saturating_nanos(delta);
        self.nanos
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(delta_nanos))
            })
            .expect("saturating manual clock advance always returns Some");
    }

    /// Set the clock to `instant` (since epoch).
    pub fn set(&self, instant: Duration) {
        self.nanos
            .store(saturating_nanos(instant), Ordering::SeqCst);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
}

/// Truncate a `Duration` to `u64` nanoseconds (saturating; > ~584 years clamps).
fn saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// A deterministic [SplitMix64](https://prng.di.unimi.it/splitmix64.c)
/// generator: seedable, allocation-free, and identical across platforms.
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Seed the generator. The same seed always produces the same sequence.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The next value in `[0.0, 1.0)`, using the top 53 bits.
    pub fn next_unit_f64(&mut self) -> f64 {
        // 53 bits of mantissa precision; division is exact for this numerator.
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }
}

/// A clock-relative deadline for TTL checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    at: Duration,
}

impl Deadline {
    /// A deadline `ttl` after the clock's current time.
    #[must_use]
    pub fn after<C: Clock>(clock: &C, ttl: Duration) -> Self {
        Self {
            at: clock.now().saturating_add(ttl),
        }
    }

    /// A deadline at an absolute clock time.
    #[must_use]
    pub fn at(at: Duration) -> Self {
        Self { at }
    }

    /// Whether the clock has reached or passed the deadline.
    #[must_use]
    pub fn is_expired<C: Clock>(&self, clock: &C) -> bool {
        clock.now() >= self.at
    }

    /// Time remaining until the deadline (zero once expired).
    #[must_use]
    pub fn remaining<C: Clock>(&self, clock: &C) -> Duration {
        self.at.saturating_sub(clock.now())
    }
}

/// An exponential-backoff policy. With `jitter == 0.0` the schedule is fully
/// determined by the policy; with `jitter > 0.0` it is determined by the policy
/// **and** the seed passed to [`backoff_schedule`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BackoffPolicy {
    /// Delay before the first retry.
    pub base: Duration,
    /// Multiplier applied per attempt (`base * factor^attempt`).
    pub factor: f64,
    /// Upper bound on any single delay (applied before jitter).
    pub max: Duration,
    /// Symmetric jitter fraction in `[0.0, 1.0]`: a delay is scaled by
    /// `1 - jitter` … `1 + jitter`.
    pub jitter: f64,
    /// Number of delays to produce.
    pub attempts: u32,
}

impl BackoffPolicy {
    /// A jitter-free exponential policy (`factor = 2.0`).
    #[must_use]
    pub const fn exponential(base: Duration, max: Duration, attempts: u32) -> Self {
        Self {
            base,
            factor: 2.0,
            max,
            jitter: 0.0,
            attempts,
        }
    }

    /// This policy with the given symmetric jitter fraction.
    #[must_use]
    pub const fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter;
        self
    }
}

/// Produce a reproducible backoff schedule. Given the same `policy` and `seed`,
/// the returned delays are byte-for-byte identical on every run and platform.
#[must_use]
pub fn backoff_schedule(policy: &BackoffPolicy, seed: u64) -> Vec<Duration> {
    let mut rng = DeterministicRng::new(seed);
    let base_nanos = policy.base.as_nanos() as f64;
    let max_nanos = policy.max.as_nanos() as f64;
    let mut schedule = Vec::with_capacity(policy.attempts as usize);
    for attempt in 0..policy.attempts {
        let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
        let raw = base_nanos * policy.factor.powi(exponent);
        let capped = raw.min(max_nanos);
        let delay = if policy.jitter > 0.0 {
            let unit = rng.next_unit_f64();
            let low = 1.0 - policy.jitter;
            let span = 2.0 * policy.jitter;
            capped * (low + span * unit)
        } else {
            capped
        };
        // Float→int `as` saturates: negatives clamp to 0, overflow to u64::MAX.
        schedule.push(Duration::from_nanos(delay.max(0.0) as u64));
    }
    schedule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_only_when_told() {
        let clock = ManualClock::new();
        assert_eq!(clock.now(), Duration::ZERO);
        let deadline = Deadline::after(&clock, Duration::from_secs(5));
        assert!(!deadline.is_expired(&clock));
        clock.advance(Duration::from_secs(5));
        assert!(deadline.is_expired(&clock));
        assert_eq!(deadline.remaining(&clock), Duration::ZERO);
    }

    #[test]
    fn backoff_schedule_is_reproducible_for_a_seed() {
        let policy =
            BackoffPolicy::exponential(Duration::from_millis(100), Duration::from_secs(10), 5)
                .with_jitter(0.25);
        let first = backoff_schedule(&policy, 0xC0FF_EE00);
        let second = backoff_schedule(&policy, 0xC0FF_EE00);
        let different_seed = backoff_schedule(&policy, 0xDEAD_BEEF);
        assert_eq!(first, second);
        assert_eq!(first.len(), 5);
        // A different seed perturbs the jittered schedule.
        assert_ne!(first, different_seed);
    }

    #[test]
    fn jitter_free_backoff_is_pure_exponential_and_capped() {
        let policy =
            BackoffPolicy::exponential(Duration::from_millis(100), Duration::from_millis(500), 4);
        let schedule = backoff_schedule(&policy, 1);
        assert_eq!(
            schedule,
            vec![
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(500), // capped (would be 800)
            ]
        );
    }

    #[test]
    fn deterministic_rng_is_seed_reproducible() {
        let draw = |seed: u64| {
            let mut rng = DeterministicRng::new(seed);
            [rng.next_u64(), rng.next_u64(), rng.next_u64()]
        };
        assert_eq!(draw(42), draw(42));
        assert_ne!(draw(42), draw(43));
    }

    #[test]
    fn rng_unit_values_stay_in_half_open_unit_interval() {
        let mut rng = DeterministicRng::new(7);
        for _ in 0..1_000 {
            let value = rng.next_unit_f64();
            assert!((0.0..1.0).contains(&value));
        }
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::new();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }

    #[test]
    fn manual_clock_at_and_set_position_absolute_time() {
        let clock = ManualClock::at(Duration::from_secs(100));
        assert_eq!(clock.now(), Duration::from_secs(100));
        clock.set(Duration::from_secs(5));
        assert_eq!(clock.now(), Duration::from_secs(5));
        let deadline = Deadline::at(Duration::from_secs(10));
        assert!(!deadline.is_expired(&clock));
        assert_eq!(deadline.remaining(&clock), Duration::from_secs(5));
    }

    #[test]
    fn manual_clock_advance_saturates_instead_of_wrapping() {
        let clock = ManualClock::at(Duration::from_nanos(u64::MAX - 2));
        clock.advance(Duration::from_nanos(10));
        assert_eq!(clock.now(), Duration::from_nanos(u64::MAX));

        let deadline = Deadline::at(Duration::from_nanos(u64::MAX - 1));
        assert!(deadline.is_expired(&clock));
        assert_eq!(deadline.remaining(&clock), Duration::ZERO);
    }

    #[test]
    fn jittered_backoff_stays_within_symmetric_bounds() {
        let policy =
            BackoffPolicy::exponential(Duration::from_millis(100), Duration::from_secs(60), 6)
                .with_jitter(0.25);
        for (attempt, delay) in backoff_schedule(&policy, 99).into_iter().enumerate() {
            let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
            let capped = (100.0 * 2.0_f64.powi(exponent)).min(60_000.0);
            let low = Duration::from_secs_f64((capped * 0.75) / 1000.0);
            let high = Duration::from_secs_f64((capped * 1.25) / 1000.0);
            assert!(delay >= low, "attempt {attempt}: {delay:?} < {low:?}");
            assert!(delay <= high, "attempt {attempt}: {delay:?} > {high:?}");
        }
    }

    #[test]
    fn manual_clock_is_deterministic_and_monotonic_under_identical_advances() {
        let run = || {
            let clock = ManualClock::new();
            let mut samples = Vec::new();
            for step in [10_u64, 5, 0, 100] {
                clock.advance(Duration::from_millis(step));
                samples.push(clock.now());
            }
            samples
        };
        // Determinism: identical advance sequences yield identical timelines.
        assert_eq!(run(), run());
        // Monotonicity: time never goes backwards (a zero advance holds steady).
        for pair in run().windows(2) {
            assert!(pair[1] >= pair[0]);
        }
    }
}
