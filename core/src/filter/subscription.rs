use crate::conntrack::conn::conn_layers::{SupportedLayer, NUM_LAYERS};
use crate::conntrack::conn::conn_state::StateTxOrd;
use crate::conntrack::{Actions, DataLevel, LayerState, StateTransition, TrackedActions};


/// Compile-time struct for representing a datatype
#[derive(Debug, Clone)]
pub struct DatatypeSpec {
    /// The Level at which the datatype is complete (or streamed)
    pub level: DataLevel,
    /// Updates: streaming updates and state transitions requested.
    /// This should include the `level` above.
    pub updates: Vec<DataLevel>,
}

/// Data required to build PTrees, indicating how to populate actions.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct CompiledActions {
    /// Optional conditional: these actions are only applied if layer is in
    /// one of the listed states.
    if_matches: Option<(SupportedLayer, Vec<LayerState>)>,
    /// Tracked Actions at the transport layer
    transport: TrackedActions,
    /// Tracked Actions at encapsulated layers
    /// Note: SupportedLayers enum must include L4 (transport) for concisely representing
    /// StateTransitions as Predicates in PTrees. The (runtime) conntrack structure
    /// separates the transport protocol from its list of encapsulated protocols.
    layers: [TrackedActions; NUM_LAYERS],
}

impl CompiledActions {
    pub(crate) fn new() -> Self {
        CompiledActions {
            if_matches: None,
            transport: TrackedActions::new(),
            layers: [TrackedActions::new(); NUM_LAYERS],
        }
    }

    // --PSEUDOCODE-- for what the actual code will look like
    // \TODO - this means that Predicate::LayerState won't be required
    // pub(crate) fn to_tokens(&self) -> proc_macro2::TokenStream {
    //     let l7_idx = SupportedLayer::L7 as usize - 1;
    //     // Insert check for state if applicable.
    //     // TODO - maybe these should be extracted into PTree nodes instead
    //     let mut conditional = quote! {};
    //     if let Some((layer, states)) = &self.if_matches {
    //         let linfo = match layer {
    //             SupportedLayer::L4 => quote! { conn_info.linfo },
    //             SupportedLayer::L7 => quote! { conn_info.layers[#l7_idx] },
    //         };
    //         conditional = quote! {
    //             if conn_info.layers[#l7_idx] == #state
    //         };
    //         for idx in 1..states.len() {
    //             let state = states[idx].to_tokens();
    //             conditional = quote! {#conditional || #linfo.state == #state };
    //         }
    //     }
    //     // Body: code to update working list of actions
    //     let mut body = quote! {};
    //     if !self.transport.drop() {
    //         let actions = self.transport.to_tokens();
    //         body = quote! {
    //             conn_info.linfo.actions.update(#actions);
    //         };
    //     }
    //     if !self.layers[l7_idx].drop() {
    //         let actions = self.layers[l7_idx].to_tokens();
    //         body = quote! {
    //             #body
    //             conn_info.layers[#l7_idx].actions.update(#actions);
    //         };
    //     }
//
    //     quote! {
    //         #conditional {
    //             #body
    //         }
    //     }
    // }
}

impl DatatypeSpec {
    /// For a given filter layer (state transition), return the actions that the
    /// datatype requires.
    ///
    /// Example: A TLS handshake requires a "headers parsed" state TX. We must generate
    /// the actions that will allow that state transition to execute. In general, the
    /// framework must (1) 'pass through' at the transport layer (to L7) and (2) parse
    /// at L7, and it must continue doing this _until_ the L7 headers are parsed or
    /// we fail to identify the protocol fails to identify.
    /// In other words: if the filter layer is guaranteed to execute before the end
    /// of the L7 headers, then we can proceed with these actions. If the layer is
    /// guaranteed to execute after the end of the L7 headers, we should do nothing.
    /// If the layers are not comparable (may happen in any order), then the actions
    /// taken depend on the L7 state.
    pub(crate) fn to_actions(&self, filter_layer: StateTransition) -> Vec<CompiledActions> {
        let mut actions = vec![];
        let l7_idx = SupportedLayer::L7 as usize - 1;
        assert!(self.updates.contains(&self.level));
        for level in &self.updates {
            let cmp = filter_layer.compare(level);
            let mut a = CompiledActions::new();
            match level {
                DataLevel::L4FirstPacket => {
                    // Nothing required.
                    // Datatype can be delivered or cached on first packet filter.
                    continue
                },
                DataLevel::L4EndHshk => {
                    match cmp {
                        StateTxOrd::Less | StateTxOrd::Unknown => {
                            // Detecting the handshake requires invoking reassembly
                            a.transport.active |= Actions::Parse;
                            // ...until the handshake has been parsed
                            a.transport.refresh_at[level.as_usize()] |= Actions::Parse;
                            // Only if pre-handshake
                            if matches!(cmp, StateTxOrd::Unknown) {
                                a.if_matches = Some((SupportedLayer::L4, vec![LayerState::Headers]));
                            }
                            DatatypeSpec::push_action(&mut actions, a);
                        },
                        _ => continue,
                    }
                },
                DataLevel::L4InPayload(reassembled) => {
                    // Actions get "refreshed" either never (if specified)
                    // or during subsequent updates (to allow datatype to unsubscribe).
                    let refresh_at = if self.level == DataLevel::L4Terminated { self.level } else { *level };
                    // "In" suggests an update is required
                    a.transport.active |= Actions::Update;
                    a.transport.refresh_at[refresh_at.as_usize()] |= Actions::Update;
                    if *reassembled {
                        // Require reassembly if requested
                        a.transport.active |= Actions::Parse;
                        a.transport.refresh_at[refresh_at.as_usize()] |= Actions::Parse;
                    }
                    DatatypeSpec::push_action(&mut actions, a);
                },
                DataLevel::L7OnDisc => {
                    match cmp {
                        StateTxOrd::Equal | StateTxOrd::Greater => continue,
                        StateTxOrd::Less | StateTxOrd::Unknown => {
                            // Must pass to subsequent layer.
                            // Note this will implicitly reassemble.
                            a.transport.active |= Actions::PassThrough;
                            a.transport.refresh_at[level.as_usize()] |= Actions::PassThrough;
                            // "Parse" at L7 in order to identify protocol, until protocol identified
                            // (or all protocols ruled out).
                            a.layers[l7_idx].active |= Actions::Parse;
                            a.layers[l7_idx].refresh_at[level.as_usize()] |= Actions::Parse;
                            if matches!(cmp, StateTxOrd::Unknown) {
                                a.if_matches = Some((SupportedLayer::L7, vec![LayerState::Discovery]));
                            }
                            DatatypeSpec::push_action(&mut actions, a);
                        }
                    }
                },
                DataLevel::L7InHdrs => {
                    // Resets might happen if "in headers" data unsubscribes or headers end.
                    let refresh_at = vec![DataLevel::L7InHdrs, DataLevel::L7EndHdrs];
                    match cmp {
                        StateTxOrd::Greater => continue,
                        StateTxOrd::Equal | StateTxOrd::Less | StateTxOrd::Unknown => {
                            // Must pass to L7 and parse
                            // - If before protocol discovery: to get to start of L7 headers
                            // - If at or in headers: to update and (eventually) identify end of headers
                            a.transport.active |= Actions::PassThrough;
                            for refr in &refresh_at {
                                a.transport.refresh_at[refr.as_usize()] |= Actions::PassThrough;
                            }
                            // Update at start of and in headers.
                            if matches!(filter_layer, StateTransition::L7OnDisc | StateTransition::L7InHdrs) {
                                a.layers[l7_idx].active |= Actions::Parse | Actions::Update;
                            }
                            for refr in &refresh_at {
                                a.layers[l7_idx].refresh_at[refr.as_usize()] |= Actions::Parse | Actions::Update;
                            }
                            if matches!(cmp, StateTxOrd::Unknown) {
                                a.if_matches = Some((SupportedLayer::L7, vec![LayerState::Headers]));
                            }
                            DatatypeSpec::push_action(&mut actions, a);
                        }
                    }
                },
                DataLevel::L7EndHdrs => {
                    match cmp {
                        StateTxOrd::Equal | StateTxOrd::Greater => continue,
                        StateTxOrd::Less | StateTxOrd::Unknown => {
                            a.transport.active |= Actions::PassThrough;
                            a.transport.refresh_at[level.as_usize()] |= Actions::PassThrough;
                            a.layers[l7_idx].active |= Actions::Parse;
                            a.layers[l7_idx].refresh_at[level.as_usize()] |= Actions::Parse;
                            if matches!(cmp, StateTxOrd::Unknown) {
                                a.if_matches = Some((SupportedLayer::L7, vec![LayerState::Discovery, LayerState::Headers]));
                            }
                            DatatypeSpec::push_action(&mut actions, a);
                        }
                    }
                },
                DataLevel::L7InPayload => {
                    if cmp == StateTxOrd::Greater { continue; }

                    // Start on updates at end of headers, continue in payload.
                    // Once in payload, no more parsing to do.
                    let mut in_payload = CompiledActions::new();
                    in_payload.transport.active |= Actions::PassThrough;
                    in_payload.transport.refresh_at[level.as_usize()] |= Actions::PassThrough;
                    in_payload.layers[l7_idx].active |= Actions::Update;
                    in_payload.layers[l7_idx].refresh_at[level.as_usize()] |= Actions::Update;

                    // Require parsing until end of L7 headers.
                    let mut pre_payload = CompiledActions::new();
                    pre_payload.transport.active |= Actions::PassThrough;
                    pre_payload.transport.refresh_at[StateTransition::L7EndHdrs.as_usize()] |= Actions::PassThrough;
                    pre_payload.layers[l7_idx].active |= Actions::Parse;
                    pre_payload.layers[l7_idx].refresh_at[StateTransition::L7EndHdrs.as_usize()] |= Actions::Parse;

                    // Beginning of or in payload: update
                    if cmp == StateTxOrd::Equal || filter_layer == StateTransition::L7EndHdrs {
                        DatatypeSpec::push_action(&mut actions, in_payload);
                    }
                    // Pre-payload (L7OnDisc, InHdrs)
                    else if cmp == StateTxOrd::Less {
                        DatatypeSpec::push_action(&mut actions, pre_payload);
                    }
                    // Different layer: depends on L7 state
                    else if cmp == StateTxOrd::Unknown {
                        pre_payload.if_matches = Some((SupportedLayer::L7, vec![LayerState::Discovery, LayerState::Headers]));
                        DatatypeSpec::push_action(&mut actions, pre_payload);
                        in_payload.if_matches = Some((SupportedLayer::L7, vec![LayerState::Payload]));
                        DatatypeSpec::push_action(&mut actions, in_payload);
                    }
                },
                DataLevel::L7EndPayload => {
                    // L7 payload parsing not yet implemented. Use L4Terminated instead.
                    unimplemented!();
                },
                DataLevel::L4Terminated => {
                    let mut a = CompiledActions::new();
                    a.transport.active |= Actions::Track;
                    a.transport.refresh_at[level.as_usize()];
                    DatatypeSpec::push_action(&mut actions, a);
                },
                DataLevel::None => panic!("Data level cannot be None"),
            }
        }
        actions
    }

    /// Add `new` to `actions` by either:
    /// - Appending it, or
    /// - Updating an existing action that has the same preconditions
    fn push_action(actions: &mut Vec<CompiledActions>, new: CompiledActions) {
        let curr = actions.iter_mut().find(|a| (**a).if_matches == new.if_matches);
        match curr {
            Some(curr) => {
                curr.transport.extend(&new.transport);
                curr.layers[0].extend(&new.layers[0]);
            },
            None => actions.push(new),
        }
    }


}


#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    lazy_static::lazy_static!(
        // L7 headers, e.g., TLS handshake, HTTP headers, DNS txn
        static ref l7_header: DatatypeSpec = DatatypeSpec {
            level: DataLevel::L7EndHdrs,
            updates: vec![DataLevel::L7EndHdrs],
        };
        // L7 headers with a customized fingerprint that requires
        // analyzing payload metadata.
        static ref l7_fingerprint: DatatypeSpec = DatatypeSpec {
            level: DataLevel::L4InPayload(false),
            updates: vec![DataLevel::L4InPayload(false), DataLevel::L7EndHdrs],
        };
        // Basic connection metadata, delivered at end of connection
        static ref conn_data: DatatypeSpec = DatatypeSpec {
            level: DataLevel::L4Terminated,
            updates: vec![DataLevel::L4InPayload(false), DataLevel::L4Terminated],
        };
        // Basic connection metadata, delivered in streaming fashion.
        // Also requests update when handshake completes.
        static ref conn_streamdata: DatatypeSpec = DatatypeSpec {
            level: DataLevel::L4InPayload(false),
            updates: vec![DataLevel::L4InPayload(false), DataLevel::L4EndHshk],
        };
    );

    // Actions for session header (e.g., TLS handshake)
    #[test]
    fn core_data_actions_l7() {
        // Initial state: should parse until end of headers
        let actions = l7_header.to_actions(StateTransition::L4FirstPacket);
        assert!(actions.len() == 1);
        assert!(actions[0].if_matches == None);
        assert!(actions[0].transport.has_next_layer() && actions[0].layers[0].needs_parse());
        for tx in StateTransition::iter() {
            if matches!(tx, StateTransition::L7EndHdrs) {
                assert!(actions[0].transport.refresh_at[tx.as_usize()] != 0,
                        "{:?} has value: {:?}", tx, actions[0].transport.refresh_at[tx.as_usize()]);
            } else if tx != StateTransition::None {
                assert!(actions[0].transport.refresh_at[tx.as_usize()] == 0,
                        "{:?} has value: {:?}", tx, actions[0].transport.refresh_at[tx.as_usize()]);
            }
        }
        // Everything should be dropped after headers
        let actions = l7_header.to_actions(StateTransition::L7EndHdrs);
        assert!(actions.len() == 0);
    }

    // Actions for datatype that requires both L4 and L7 data
    #[test]
    fn core_data_actions_l7_l4() {
        // Initial state: pre-payload
        let actions = l7_fingerprint.to_actions(StateTransition::L4FirstPacket);
        assert!(actions.len() == 1);
        assert!(actions[0].transport.has_next_layer() && actions[0].transport.needs_update());
        for tx in StateTransition::iter() {
            // At end of headers, expect DataLevel::L7EndHdrs done.
            if tx == StateTransition::L7EndHdrs {
                assert!(actions[0].transport.refresh_at[tx.as_usize()] == Actions::PassThrough,
                        "{:?} has value: {:?}", tx, actions[0].transport.refresh_at[tx.as_usize()]);
            }
            // Allow `update` to unsubscribe.
            else if matches!(tx, StateTransition::L4InPayload(_)) {
                assert!(actions[0].transport.refresh_at[tx.as_usize()] == Actions::Update,
                        "{:?} has value: {:?}", tx, actions[0].transport.refresh_at[tx.as_usize()]);
            }
            else if tx != StateTransition::None {
                assert!(actions[0].transport.refresh_at[tx.as_usize()] == 0,
                        "{:?} has value: {:?}", tx, actions[0].transport.refresh_at[tx.as_usize()]);
            }
        }

        // Ambiguous: may be pre- or post-payload
        let actions = l7_fingerprint.to_actions(StateTransition::L4InPayload(false));
        // Two added "nodes" for LayerState checks
        assert!(actions.len() == 2);
        assert!(actions[0].if_matches.is_some() || actions[1].if_matches.is_some());
    }
}