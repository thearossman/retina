/// The framework expects that any stateful callback implements this trait.
/// The user must also define the actual callback function(s), annotated with
/// the appropriate #[callback_group(...)] macros.
pub trait StreamingCallback {
    /// Initializes internal data, if applicable.
    /// Called on first packet in connection.
    fn new() -> Self;
    /// Clears internal data, if applicable.
    fn clear(&mut self);
}

#[derive(Debug)]
pub enum CallbackState {
    Active,
    Matching,
    Unsubscribed,
}

#[doc(hidden)]
/// Wrapper for a stateful callback that is invoked in a streaming state
/// (e.g., L4InPayload) or has multiple functions.
#[derive(Debug)]
pub struct StreamCallbackWrapper<C>
where
    C: StreamingCallback + std::fmt::Debug,
{
    state: CallbackState,
    pub callback: C,
}

impl<C> StreamCallbackWrapper<C>
where
    C: StreamingCallback + std::fmt::Debug,
{
    pub fn new() -> Self {
        Self {
            state: CallbackState::Matching,
            callback: C::new(),
        }
    }

    /// Returns true if the callback should be invoked.
    pub fn is_active(&self) -> bool {
        matches!(self.state, CallbackState::Active)
    }

    /// Invoked when a filter pattern for callback has matched.
    pub fn try_set_active(&mut self) {
        if !matches!(self.state, CallbackState::Unsubscribed) {
            self.state = CallbackState::Active;
        }
    }

    /// Invoked when the callback has unsubscribed.
    pub fn set_inactive(&mut self) {
        if matches!(self.state, CallbackState::Active) {
            self.callback.clear();
        }
        self.state = CallbackState::Unsubscribed;
    }
}

#[doc(hidden)]
/// Wrapper around a boolean value to help ensure that a
/// callback is invoked once per connection or session if that
/// is its expected behavior. The framework uses this wrapper when
/// a subscription specifies a streaming filter and a non-streaming
/// callback.
#[derive(Debug)]
pub struct StaticCallbackWrapper {
    pub invoked: bool,
}
impl StaticCallbackWrapper {
    pub fn new() -> Self {
        Self { invoked: false }
    }
    pub fn should_invoke(&self) -> bool {
        !self.invoked
    }
    pub fn set_invoked(&mut self) {
        self.invoked = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example usage
    #[derive(Debug)]
    struct MyCallback {
        invoked: usize,
    }
    impl StreamingCallback for MyCallback {
        fn new() -> Self {
            Self { invoked: 0 }
        }
        fn clear(&mut self) {
            self.invoked = 0;
        }
    }
    impl MyCallback {
        // #[callback_group] macros would go here
        #[allow(dead_code)]
        fn invoke(&mut self) {
            self.invoked += 1;
        }
    }
    #[test]
    fn test_cb_basic() {
        let mut wrapper: StreamCallbackWrapper<MyCallback> = StreamCallbackWrapper::new();
        wrapper.try_set_active();
        assert!(wrapper.is_active());
        wrapper.callback.invoke();
        wrapper.set_inactive();
        assert!(!wrapper.is_active());
    }
}
