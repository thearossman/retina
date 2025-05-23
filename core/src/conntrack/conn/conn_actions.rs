use bitmask_enum::bitmask;
use super::conn_state::{StateTransition, NUM_STATE_TRANSITIONS};

/// Possible actions to be taken on a connection
#[bitmask(u8)]
#[bitmask_config(vec_debug)]
pub enum Actions {
    /// Invoke "Update" API
    Update,
    /// Invoke TCP reassembly module
    Reassemble,
    /// For L6/L7: probe for protocol or parse session
    Parse,
}

/// Basic representation of Actions
/// TODO change to single bitmask in the future
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedActions {
    // Currently-active actions (as bitmask)
    pub active: Actions,
    // Bitmask of actions that should be refreshed at each stage
    pub refresh_at: [Actions; NUM_STATE_TRANSITIONS]
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
    /// Clear out actions that will need to be re-checked for
    pub fn start_state_tx(&mut self, state: StateTransition) {
        self.active &= self.refresh_at[state as usize].not();
    }

    /// Indicate state transition is done
    /// Retain in 'refresh_at' only actions that may still be active
    pub fn state_tx_done(&mut self, state: StateTransition) {
        self.refresh_at[state as usize] &= self.active;
    }

    /// All actions are empty; nothing to do for future packets in connection.
    pub fn drop(&self) -> bool {
        self.active.is_none()
    }

    pub fn reassemble(&self) -> bool {
        self.active.intersects(Actions::Reassemble | Actions::Parse)
    }

    pub fn parse(&self) -> bool {
        self.active.contains(Actions::Parse)
    }

    pub fn update(&self) -> bool {
        self.active.contains(Actions::Update)
    }

}