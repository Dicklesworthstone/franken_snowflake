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

use asupersync::Cx;
use asupersync::cx::cap::{CapSet, SubsetOf};

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

/// Narrow any capability context `Cx<Caps>` to the zero-capability [`PlannerCx`]
/// (`CapSet<false, false, false, false, false>`).
#[inline]
#[must_use]
pub fn narrow_to_planner<Caps>(cx: &Cx<Caps>) -> PlannerCx
where
    PlannerCaps: SubsetOf<Caps>,
{
    cx.restrict::<PlannerCaps>()
}

/// Narrow a full or write-capable context to [`TransportCx`] (`SPAWN + TIME + IO`,
/// stripping `RANDOM` and `REMOTE` at the type level).
#[inline]
#[must_use]
pub fn narrow_to_transport<Caps>(cx: &Cx<Caps>) -> TransportCx
where
    TransportCaps: SubsetOf<Caps>,
{
    cx.restrict::<TransportCaps>()
}

/// Narrow a full context to [`WriteCx`] only when presented with a valid
/// [`crate::write_intent::WriteAuthorization`] minted by
/// [`crate::write_intent::evaluate_write_intent`].
#[inline]
#[must_use]
pub fn narrow_to_write<Caps>(
    cx: &Cx<Caps>,
    _grant: &crate::write_intent::WriteAuthorization,
) -> WriteCx
where
    WriteCaps: SubsetOf<Caps>,
{
    cx.restrict::<WriteCaps>()
}

/// Obtain a zero-capability [`PlannerCx`] narrowed from the ambient runtime
/// context when one is installed, or a standalone read-only context otherwise.
#[inline]
#[must_use]
pub fn current_planner_cx() -> PlannerCx {
    Cx::current().map_or_else(PlannerCx::detached_cancel_context, |cx| {
        narrow_to_planner(&cx)
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_contexts_narrow_monotonically() {
        let detached = PlannerCx::detached_cancel_context();
        let planner_from_detached: PlannerCx = narrow_to_planner(&detached);
        let planner_from_current: PlannerCx = current_planner_cx();
        assert_eq!(
            planner_from_detached.is_cancel_requested(),
            planner_from_current.is_cancel_requested()
        );
        let _narrow_transport_fn: fn(&Cx) -> TransportCx =
            narrow_to_transport::<asupersync::cx::cap::All>;
        let _narrow_planner_fn: fn(&TransportCx) -> PlannerCx = narrow_to_planner::<TransportCaps>;
    }
}
