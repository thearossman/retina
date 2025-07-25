use super::{FilterResult, Trackable};
use crate::{conntrack::conn::conn_state::StateTxData, L4Pdu};

// TODOs:
// - Like callback, ultimately want the filter to be a wrapper
//   s.t. it can take in multiple Trackable datatypes.
// - Maybe add a timer wrapper

/// NOTE unclear whether this will actually get used....

/// Streaming filter. See notes for streaming callback.
pub trait StreamingFilter<T>
where
    T: Trackable,
{
    /// Initialize internal data, if applicable. Invoked on first packet.
    fn new() -> Self;
    /// Invoked at specified intervals with Trackable data until either
    /// `Accept` or `Drop` is returned OR all filter predicates that are
    /// preconditions have failed to match. See notes for streaming callback.
    fn update(&mut self, tracked: &T, pdu: Option<&L4Pdu>) -> FilterResult;
    /// Invoked at specified state transition
    fn state_tx(&mut self, tracked: &T, tx: &StateTxData) -> FilterResult;
}

#[doc(hidden)]
/// If a streaming filter is specified as "expensive", it is wrapped in this
/// so that we can track when it's still needed by active subscriptions.
/// When it is cleared, it will no longer be invoked.
pub struct FilterWrapper<T, F>
where
    T: Trackable,
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
}

impl<T, F> FilterWrapper<T, F>
where
    T: Trackable,
    F: StreamingFilter<T>,
{
    /// Create a new filter wrapper.
    pub fn new() -> Self {
        FilterWrapper {
            filter: Some(F::new()),
            tracked: std::marker::PhantomData,
            matched: false,
        }
    }

    /// Returns true if the filter should be invoked.
    pub fn is_active(&self) -> bool {
        self.filter.is_some()
    }

    /// Accessor methods for wrapped filter.
    pub fn filter(&mut self, tracked: &T, pdu: Option<&L4Pdu>) -> FilterResult {
        if let Some(filter) = &mut self.filter {
            return filter.update(tracked, pdu);
        }
        FilterResult::Drop
    }

}
