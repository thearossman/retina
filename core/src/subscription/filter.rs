use crate::{conntrack::StateTransition, L4Pdu};
use super::data::Tracked;

// TODOs:
// - Like callback, ultimately want the filter to be a wrapper
//   s.t. it can take in multiple tracked datatypes.
// - Maybe add a timer wrapper

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterResult {
    Continue,
    Drop,
    Accept,
}

/// Streaming filter. See notes for streaming callback.
pub trait StreamingFilter<T>
where T: Tracked {
    /// Initialize internal data, if applicable. Invoked on first packet.
    fn new() -> Self;
    /// Invoked at specified intervals with tracked data until either
    /// `Accept` or `Drop` is returned OR all filter predicates that are
    /// preconditions have failed to match. See notes for streaming callback.
    fn filter(&mut self, tracked: &T, pdu: Option<&L4Pdu>) -> FilterResult;
}

#[doc(hidden)]
/// If a streaming filter is specified as "expensive", it is wrapped in this
/// so that we can track when it's still needed by active subscriptions.
/// When it is cleared, it will no longer be invoked.
pub struct FilterWrapper<T, F>
where
    T: Tracked,
    F: StreamingFilter<T>,
{
    /// Starts as `Some`; changed to `None` if:
    /// - Filter itself fails to match, or
    /// - Term + nonterm == 0
    /// When this is None, the filter is no longer active and thus
    /// no longer invoked.
    pub filter: Option<F>,
    /// Required to make the compiler happy so that we can specify `T`.
    tracked: std::marker::PhantomData<T>,
    /// This filter has definitively matched (returned FilterResult).
    pub matched: bool,
    /// Bitmask that must be at least NUM_STATE_TRANSITIONS.
    /// The next phase(s) at which this filter may be cleared.
    /// This is used for filters that are part of longer patterns and
    /// indicates the next phase at which a new predicate in the pattern
    /// can be applied (i.e., we may have more information).
    /// If the other predicates in these patterns match, then we know
    /// that this streaming filter no longer needs to maintain state
    /// or be invoked.
    /// - If this is empty, then the filter can be dropped.
    /// - If this contains StateTransition::L4Terminated, all predicates
    ///   in a broader pattern have matched and the filter will not be
    ///   cleared until it has definitively matched (or not matched).
    refresh_at: u32,
}

impl <T, F> FilterWrapper<T, F>
where
    T: Tracked,
    F: StreamingFilter<T>,
{
    /// Create a new filter wrapper.
    /// `preconditions` should be `false` if this filter predicate
    /// is in any patterns in which it is alone (i.e., not part of
    /// a broader pattern).
    pub fn new(preconditions: bool) -> Self {
        let refresh_at = if preconditions {
            0
        } else {
            1 << StateTransition::L4Terminated.raw()
        };
        FilterWrapper {
            filter: Some(F::new()),
            tracked: std::marker::PhantomData,
            matched: false,
            refresh_at,
        }
    }

    /// Returns true if the filter should be invoked.
    pub fn is_active(&self) -> bool {
        self.filter.is_some()
    }

    /// Accessor methods for wrapped filter.
    pub fn filter(&mut self, tracked: &T, pdu: Option<&L4Pdu>) -> FilterResult {
        if let Some(filter) = &mut self.filter {
            return filter.filter(tracked, pdu);
        }
        FilterResult::Drop
    }

    /// Indicate the start of a phase transition.
    pub fn start_tx(&mut self, tx: &StateTransition) {
        self.refresh_at |= 1 << tx.raw();
    }

    /// Indicate the end of a phase transition. This will clear out the filter
    /// if no patterns are still "active".
    pub fn end_tx(&mut self) {
        if self.refresh_at == 0 {
            self.filter = None;
        }
    }

    /// Indicate that all predicates in any end-to-end pattern containing
    /// `self` have matched.
    pub fn terminal_match(&mut self) {
        self.refresh_at |= 1 << StateTransition::L4Terminated.raw();
    }

    /// Indicate the next phase transition at which a given filter pattern
    /// will have more information to check. `self` must be guaranteed to
    /// exist until at least `tx` unless `self` fails to match.
    pub fn nonterminal_match(&mut self, tx: &StateTransition) {
        self.refresh_at |= 1 << tx.raw();
    }
}