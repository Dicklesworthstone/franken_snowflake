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
    let mut budget = Budget::new()
        .with_poll_quota(poll_quota)
        .with_priority(priority);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_budget_construction() {
        let budget = query_budget(None, 50, Some(10_000), 128);
        assert_eq!(budget.poll_quota, 50);
        assert_eq!(budget.priority, 128);
        assert_eq!(budget.cost_quota, Some(10_000));
        assert!(budget.deadline.is_none());

        let now = Time::from_nanos(1_000_000_000);
        let timed_budget = query_budget(Some(now), 10, None, 200);
        assert_eq!(timed_budget.poll_quota, 10);
        assert_eq!(timed_budget.priority, 200);
        assert_eq!(timed_budget.deadline, Some(now));
        assert!(timed_budget.cost_quota.is_none());
    }

    #[test]
    fn partition_child_budget_monotone_narrowing() {
        let parent = query_budget(None, 100, Some(50_000), 100);
        let tighter_child = query_budget(None, 20, Some(10_000), 150);

        let effective = partition_child_budget(parent, tighter_child);
        // meet() selects the minimum quota
        assert_eq!(effective.poll_quota, 20);
        assert_eq!(effective.cost_quota, Some(10_000));
    }
}
