use retina_core::conntrack::StateTransition;
use retina_core::filter::Filter;
use retina_core::filter::{pkt_ptree::PacketPTree, ptree::PTree};

use crate::subscription::SubscriptionDecoder;

pub(crate) fn packet_filter_tree(
    filter_layer: &StateTransition,
    sub: &SubscriptionDecoder,
) -> PacketPTree {
    assert!(matches!(filter_layer, StateTransition::Packet));
    let mut ptree = PacketPTree::new_empty();
    for spec in &sub.subscriptions {
        let patterns = spec.patterns.as_ref().unwrap();
        ptree.build_tree(patterns, &spec.callbacks);
    }
    ptree
}

pub(crate) fn filter_tree(filter_layer: StateTransition, sub: &SubscriptionDecoder) -> PTree {
    assert!(!matches!(filter_layer, StateTransition::Packet));
    let mut ptree = PTree::new_empty(filter_layer);
    for spec in &sub.subscriptions {
        let patterns = spec.patterns.as_ref().unwrap();
        ptree.add_subscription(patterns, &spec.callbacks, &spec.as_str);
    }
    ptree.collapse();
    ptree
}

// TODO get rid of PTrees that aren't actually needed?
// Though, at runtime, we ensure only req PTrees are invoked;
