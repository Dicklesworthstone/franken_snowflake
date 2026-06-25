//! Query budgets, modeled on Asupersync's `Budget` (deadline + poll quota + cost
//! quota + priority) with min-plus `meet()` propagation to partition fetchers.
//!
//! The **cost quota is advisory**: the enforceable ceiling is server-side
//! `STATEMENT_TIMEOUT_IN_SECONDS` + result row caps. A cost-quota breach surfaces
//! as `Outcome::Cancelled(CancelReason::cost_budget())`
//! (`CancelKind::CostBudget`). See `docs/asupersync_leverage.md` and
//! `docs/security_model.md`.

pub use asupersync::Budget;

use asupersync::Time;

/// Build a query-level budget.
///
/// `cost_quota` is advisory telemetry (see the module docs); `deadline` is an
/// absolute [`Time`]; `priority` is the scheduling priority (0 = lowest,
/// 255 = highest).
#[must_use]
pub fn query_budget(
    deadline: Option<Time>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8,
) -> Budget {
    let mut budget = Budget::new().with_poll_quota(poll_quota).with_priority(priority);
    if let Some(deadline) = deadline {
        budget = budget.with_deadline(deadline);
    }
    if let Some(cost) = cost_quota {
        budget = budget.with_cost_quota(cost);
    }
    budget
}

/// The budget for a single partition fetcher: the `parent` budget tightened by a
/// `child` bound via the min-plus `meet()`.
///
/// Because `meet()` is monotone-narrowing, a child can only ever be *tighter*
/// than its parent — a partition fetcher never gains headroom the query did not
/// grant it.
#[must_use]
pub fn partition_child_budget(parent: Budget, child: Budget) -> Budget {
    parent.meet(child)
}
