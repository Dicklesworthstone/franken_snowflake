//! Capability rows for the connector's execution layers, enforced at compile time.
//!
//! Read-only is a **type-level** property, applied at the right layer (capability
//! row order is `[SPAWN, TIME, RANDOM, IO, REMOTE]`):
//!
//! - the pure planning/validation/SQL-compile path runs under [`PlannerCaps`] —
//!   `cap::None`, **zero capabilities including no IO** (Asupersync `cx_readonly()`);
//! - the transport layer runs under [`TransportCaps`] — `IO` (+ `TIME`/`SPAWN`)
//!   but **never** `REMOTE`;
//! - only the write-intent ladder widens further, to [`WriteCaps`].
//!
//! Narrowing is monotone and widening is a compile error (`SubsetOf`), so the
//! `const _` proofs below fail to compile if any layer is mis-scoped.

use asupersync::cx::cap::{CapSet, SubsetOf};
use asupersync::Cx;

/// Pure planner layer: zero capabilities (no IO). Equivalent to Asupersync
/// `cx_readonly()` = `Cx<cap::None>`.
pub type PlannerCaps = CapSet<false, false, false, false, false>;

/// Transport layer: `SPAWN` + `TIME` + `IO`, but never `RANDOM` or `REMOTE`.
pub type TransportCaps = CapSet<true, true, false, true, false>;

/// Write-intent ladder: the only layer permitted to widen further (adds `REMOTE`).
pub type WriteCaps = CapSet<true, true, false, true, true>;

/// Execution context for the read-only planner layer.
pub type PlannerCx = Cx<PlannerCaps>;
/// Execution context for the transport layer.
pub type TransportCx = Cx<TransportCaps>;
/// Execution context for the write-intent ladder.
pub type WriteCx = Cx<WriteCaps>;

// ---------------------------------------------------------------------------
// Compile-time layering proofs. Each `const _: fn()` coerces a generic fn item
// to a function pointer, which forces the `SubsetOf` bound to be checked now.
// If a layer were mis-scoped (e.g. the planner gained IO, or the transport
// gained REMOTE), the corresponding line would fail to compile.
// ---------------------------------------------------------------------------

fn assert_subset<Sub: SubsetOf<Super>, Super>() {}

/// Authority only ever widens UP the ladder: planner ⊆ transport ⊆ write.
const _: fn() = assert_subset::<PlannerCaps, TransportCaps>;
const _: fn() = assert_subset::<TransportCaps, WriteCaps>;

/// The transport layer can never hold `REMOTE` (⊆ the all-but-`REMOTE` row).
const _: fn() = assert_subset::<TransportCaps, CapSet<true, true, true, true, false>>;

/// The planner layer can never hold `IO` (⊆ the all-but-`IO` row).
const _: fn() = assert_subset::<PlannerCaps, CapSet<true, true, true, false, true>>;
