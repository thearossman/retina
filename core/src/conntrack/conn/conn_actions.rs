use super::conn_state::{StateTransition, NUM_STATE_TRANSITIONS};
use bitmask_enum::bitmask;

/// Possible actions to be taken on a connection
#[bitmask(u8)]
#[bitmask_config(vec_debug)]
pub enum Actions {
    /// Invoke Tracked datatype "Update" API at this Layer to pass new frames
    /// to users' subscribed datatype(s).
    Update,
    /// Indicates that some Layer-specific stateful parsing is required.
    /// For L4, this is TCP reassembly. For L6/L7, this indicates a
    /// stateful application-layer protocol parser should be invoked.
    Parse,
    /// Indicates that some child layer(s) require actions.
    PassThrough,
}

/// Basic representation of Actions
/// TODO change to single bitmask in the future
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedActions {
    // Currently-active actions (as bitmask)
    pub active: Actions,
    // Bitmask of actions that should be refreshed at each stage
    pub refresh_at: [Actions; NUM_STATE_TRANSITIONS],
}

impl TrackedActions {
    /// Initialize empty
    pub fn new() -> Self {
        Self {
            active: Actions { bits: 0 },
            refresh_at: [Actions { bits: 0 }; NUM_STATE_TRANSITIONS],
        }
    }

    /// Set up actions for executing a state transition
    /// Clear out actions that will need to be re-checked
    /// Also clear `PassThrough`, which will be reset after the
    /// state TX if child layer(s) have actions set.
    #[inline]
    pub fn start_state_tx(&mut self, state: StateTransition) {
        self.active &= self.refresh_at[state as usize].not();
        self.active &= (Actions::PassThrough).not();
    }

    /// All actions are empty; nothing to do for future packets in connection.
    #[inline]
    pub fn drop(&self) -> bool {
        self.active.is_none()
    }

    #[inline]
    pub fn needs_reassembly(&self) -> bool {
        self.active
            .intersects(Actions::Parse | Actions::PassThrough)
    }

    #[inline]
    pub fn has_next_layer(&self) -> bool {
        self.active.intersects(Actions::PassThrough)
    }

    #[inline]
    pub fn set_next_layer(&mut self) {
        self.active |= Actions::PassThrough;
    }

    #[inline]
    pub fn needs_parse(&self) -> bool {
        self.active.intersects(Actions::Parse)
    }

    #[inline]
    pub fn needs_update(&self) -> bool {
        self.active.intersects(Actions::Update)
    }

    /// When a filter has definitively matched AND it will be required
    /// for the rest of the connection (i.e., connection-level subscription),
    /// remove it from all future state transition "refresh" slots.
    pub fn set_terminal_action(&mut self, action: &Actions) {
        for i in 0..NUM_STATE_TRANSITIONS {
            self.refresh_at[i] &= action.not();
        }
    }
}
