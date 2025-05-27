use crate::L4Pdu;
use super::data::Tracked;

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
    /// Filter pattern preconditions have matched terminally
    /// None if there are no preconditions
    pub term: Option<u32>,
    /// Filter pattern preconditions that have matched non-terminally
    pub nonterm: Option<u32>,
}

impl <T, F> FilterWrapper<T, F>
where
    T: Tracked,
    F: StreamingFilter<T>,
{
    /// Create a new filter wrapper.
    /// `preconditions` should be `true` if this filter predicate
    /// is _only_ part of longer patterns (i.e., if some external predicates
    /// fail to match, this filter should no longer be invoked).
    pub fn new(preconditions: bool) -> Self {
        let matches = if preconditions { Some(0) } else { None };
        FilterWrapper {
            filter: Some(F::new()),
            tracked: std::marker::PhantomData,
            term: matches,
            nonterm: matches,
        }
    }

    /// Returns true if the filter should be invoked.
    pub fn is_active(&self) -> bool {
        self.filter.is_some()
    }
}