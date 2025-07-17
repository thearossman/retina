use core::fmt;
use std::collections::HashSet;

use crate::conntrack::{DataLevel, StateTransition};

use super::{ast::Predicate, pattern::FlatPattern, subscription::{CallbackSpec, DatatypeSpec, NodeActions, SubscriptionLevel}};

// A node representing a predicate in the tree
#[derive(Debug, Clone)]
pub struct PNode {
    // Predicate represented by this PNode
    pub pred: Predicate,

    // Child PNodes
    pub children: Vec<PNode>,

    // Predicate is mutually exclusive with the
    // predicate in the node preceding it in child list
    pub if_else: bool,

    // `Actions` struct for this node.
    pub actions: NodeActions,

    // Subscriptions that can be invoked (or CB timer started)
    // at this node. That is, all for which `can_deliver`
    // on its `SubscriptionLevel`` returned true.
    pub deliver: HashSet<CallbackSpec>,

    // Identifier
    pub id: usize,
}

impl PNode {
    fn new(pred: Predicate, level: DataLevel,
           id: usize,) -> Self {
        PNode {
            pred,
            children: vec![],
            if_else: false,
            actions: NodeActions::new(level),
            deliver: HashSet::new(),
            id
        }
    }

    /// -- Utilities for comparing predicates when inserting nodes -- //

    // Utility to check whether a descendant exists
    // Helper for `get_descendant`, which must be invoked in an `if` block
    // due to borrow checker
    fn has_descendant(&self, pred: &Predicate) -> bool {
        for n in &self.children {
            if &n.pred == pred {
                return true;
            }
            if pred.is_child(&n.pred) && n.has_descendant(pred) {
                return true;
            }
        }
        false
    }

    // See above
    fn get_descendant(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        for n in &mut self.children {
            // found exact match
            if &n.pred == pred {
                return Some(n);
            }
            // node is a parent - keep descending
            if pred.is_child(&n.pred) {
                if let Some(c) = n.get_descendant(pred) {
                    return Some(c);
                }
            }
        }
        None
    }

    // Returns true if `self` has `pred` as a direct child
    fn has_child(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| &n.pred == pred)
    }

    // See above
    fn get_child(&mut self, pred: &Predicate) -> &mut PNode {
        self.children.iter_mut().find(|n| &n.pred == pred).unwrap()
    }

    // True if `self` has children that should be (more specific)
    // children of `pred`
    fn has_children_of(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| n.pred.is_child(pred))
    }

    // Returns all of the PNodes that should be children of `pred`,
    // while retaining in `self.children` the nodes that are
    // not children of `pred`
    fn get_children_of(&mut self, pred: &Predicate) -> Vec<PNode> {
        let new;
        let children = std::mem::take(&mut self.children);

        (new, self.children) = children.into_iter().partition(|p| p.pred.is_child(pred));

        new
    }

    // Returns a reference to a PNode that is a child of `self`
    // that can act as "parent" of `pred`.
    fn get_parent_candidate(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        self.children.iter_mut().find(|n| pred.is_child(&n.pred))
    }

    // Returns true if (1) both `self` and `peer` have equal node-to-leaf paths
    // and (2) actions/CB are the same.
    // This is useful for marking nodes as mutually exclusive even
    // if there predicates are not mutually exclusive.
    fn outcome_eq(&self, peer: &PNode) -> bool {
        if self.actions != peer.actions || self.deliver != peer.deliver {
            return false;
        }
        (self.children.is_empty() && peer.children.is_empty()) || self.all_paths_eq(peer)
    }

    // True if there is a PNode that can act as parent of `pred`.
    fn has_parent(&self, pred: &Predicate) -> bool {
        for n in &self.children {
            if pred.is_child(&n.pred) {
                return true;
            }
        }
        false
    }

    // Returns a node that can act as a parent to `pred`, or None.
    // The most "narrow" parent condition will be returned if multiple exist.
    fn get_parent(&mut self, pred: &Predicate, tree_size: usize) -> Option<&mut PNode> {
        // This is messy, but directly iterating through children or
        // recursing will raise flags with the borrow checker.
        let mut node = self;
        for _ in 0..tree_size {
            // Checked for `Some` on last iteration
            let next = node.get_parent_candidate(pred)?;
            if next.get_parent_candidate(pred).is_none() {
                // `next` is the last possible parent at this stage
                return Some(next);
            } else {
                // There are more potential parents
                node = next;
            }
        }
        None
    }

    // Returns `true` if a condition cannot be removed from the filter due to
    // its role extracting data needed for a subsequent condition.
    // For example, getting `ipv4` is necessary for checking `ipv4.src_addr`.
    fn extracts_protocol(&self, filter_layer: DataLevel) -> bool {
        // Filters that parse raw packets are special case
        // Need upper layers to extract inner from mbuf
        // E.g.: need ipv4 header to parse tcp
        if matches!(
            filter_layer,
            DataLevel::L4FirstPacket
        ) && self.pred.is_unary()
            && self.children.iter().any(|n| n.pred.is_unary())
        {
            return true;
        }
        self.pred.is_unary()
            && self
                .children
                .iter()
                .any(|n| self.pred.get_protocol() == n.pred.get_protocol() && n.pred.is_binary())
    }

    // Populates `paths` with all root-to-leaf paths originating
    // at node `self`.
    fn get_paths(&self, curr_path: &mut Vec<String>, paths: &mut Vec<String>) {
        if self.children.is_empty() && !curr_path.is_empty() {
            paths.push(curr_path.join(","));
        } else {
            for c in &self.children {
                curr_path.push(format!("{}", c));
                c.get_paths(curr_path, paths);
            }
        }
        curr_path.pop();
    }

    // Returns true if all root-to-leaf paths originating at `self`
    // are the same as all root-to-leaf paths originating at `other`.
    // This is applied to determine if two nodes have the same outcome
    // (subsequent conditions, actions, delivery) if predicate is `true`.
    fn all_paths_eq(&self, other: &PNode) -> bool {
        if self.children.is_empty() && other.children.is_empty() {
            return true;
        }
        let mut paths = vec![];
        let mut curr = vec![];
        self.get_paths(&mut curr, &mut paths);
        let mut peer_paths = vec![];
        curr = vec![];
        other.get_paths(&mut curr, &mut peer_paths);
        peer_paths == paths
    }
}

impl fmt::Display for PNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pred)?;
        if !self.actions.actions.is_empty() {
            // TODO implement Display for Actions!
            write!(f, " -- A: {:?}", self.actions.actions)?;
        }
        if !self.deliver.is_empty() {
            write!(f, " D: ")?;
            write!(f, "( ")?;
            for d in &self.deliver {
                write!(f, "{}, ", d.as_str)?;
            }
            write!(f, ")")?;
        }
        if self.if_else {
            write!(f, " x")?;
        }
        Ok(())
    }
}

// A n-ary tree representing a Filter.
// Paths from root to leaf represent a pattern for data to match.
// Filter returns action(s) or delivers data.
#[derive(Debug, Clone)]
pub struct PTree {
    // Root node
    pub root: PNode,

    // Number of nodes in tree
    pub size: usize,

    // Which filter this PTree represents
    pub filter_layer: StateTransition,

    // Has `collapse` been applied?
    // Use to ensure no filters are applied after `collapse`
    collapsed: bool,
}

impl PTree {
    pub fn new_empty(filter_layer: StateTransition) -> Self {
        let pred = Predicate::Unary {
            protocol: protocol!("ethernet"),
        };
        Self {
            root: PNode::new(pred, filter_layer, 0),
            size: 0,
            filter_layer,
            collapsed: false,
        }
    }

    pub fn add_subscription(
        &mut self,
        // Filter patterns
        patterns: &[FlatPattern],
        // Individual callbacks; each has datatypes
        callbacks: &Vec<CallbackSpec>,
    ) {
        if self.collapsed {
            panic!("Cannot add filter to tree after collapsing");
        }
        assert!(patterns.len() > 0 ||
                patterns.iter().all(|p| p.predicates.is_empty()),
                "Empty filter pattern must have default predicate.");
        for pattern in patterns {
            // Extract required datatypes in filter pattern
            let mut datatypes: Vec<_> = pattern.predicates
                                               .iter()
                                               .map(|p| DatatypeSpec::from_pred(p))
                                               .collect();
            // Add datatypes required by callback
            for callback in callbacks {
                datatypes.extend(callback.datatypes.iter().cloned());
                if let Some(stream) = callback.stream {
                    // Requires streaming `updates` or the level cannot be
                    // inferred from the datatype alone
                    datatypes.push(
                        DatatypeSpec {
                            updates: vec![stream],
                            name: callback.as_str.clone()
                        }
                    );
                }
            }
            // Construct node actions
            let mut node_actions = NodeActions::new(self.filter_layer);
            // Actions required for all datatypes (including filters)
            for spec in &datatypes {
                node_actions.add_datatype(spec);
            }
            // Update `refresh_at` based on where next filter predicate(s)
            // may be applied.
            for next_pred in pattern.next_pred(self.filter_layer) {
                node_actions.push_filter_pred(&next_pred);
            }
            // Allow callback to `unsubscribe`
            for callback in callbacks {
                if let Some(cb_level) = &callback.stream {
                    node_actions.push_cb(*cb_level);
                }
            }
            for callback in callbacks {
                self.add_pattern(pattern, &node_actions, callback);
            }
        }
    }

    fn add_pattern(
        &mut self,
        full_pattern: &FlatPattern,
        actions: &NodeActions,
        callback: &CallbackSpec
    ) {
        let level = SubscriptionLevel::new(
            &callback.datatypes,
            full_pattern,
            callback.stream
        );
        if level.can_skip(&self.filter_layer) {
            return;
        }

        let pattern: Vec<_> = full_pattern.predicates
                                          .iter()
                                          .filter(|p| !p.is_next_layer(self.filter_layer))
                                          .cloned()
                                          .collect();
        assert!(pattern.len() <= full_pattern.predicates.len());
        if pattern.len() < full_pattern.predicates.len() {
            assert!(!level.can_deliver(&self.filter_layer));
        }

        let mut node = &mut self.root;
        for predicate in pattern.iter() {
            // Case 1: Predicate is already present
            if node.has_descendant(predicate) {
                node = node.get_descendant(predicate).unwrap();
                continue;
            }
            // Case 2: Predicate should be added as child of existing node
            if node.has_parent(predicate) {
                node = node.get_parent(predicate, self.size).unwrap();
            }
            // Case 3: Children of curr node should be children of new node
            let children = match node.has_children_of(predicate) {
                true => node.get_children_of(predicate),
                false => {
                    vec![]
                }
            };
            // Create new node
            if !node.has_child(predicate) {
                node.children.push(PNode::new(predicate.clone(), self.filter_layer,
                                   self.size));
                self.size += 1;
            }
            // Move on, pushing any new children if applicable
            node = node.get_child(predicate);
            node.children.extend(children);
        }
        if level.can_deliver(&self.filter_layer) {
            node.deliver.insert(callback.clone());
        }
        node.actions.merge(actions);
    }

    // modified from https://vallentin.dev/2019/05/14/pretty-print-tree
    fn pprint(&self) -> String {
        fn pprint(s: &mut String, node: &PNode, prefix: String, last: bool) {
            let prefix_current = if last { "`- " } else { "|- " };

            let s_next = format!("{}{}{}: {}\n", prefix, prefix_current, node.id, node);
            s.push_str(&s_next);

            let prefix_child = if last { "   " } else { "|  " };
            let prefix = prefix + prefix_child;

            if !node.children.is_empty() {
                let last_child = node.children.len() - 1;

                for (i, child) in node.children.iter().enumerate() {
                    pprint(s, child, prefix.to_string(), i == last_child);
                }
            }
        }

        let mut s = String::new();
        pprint(&mut s, &self.root, "".to_string(), true);
        s
    }
}

impl fmt::Display for PTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tree {:?}\n,{}", &self.filter_layer, self.pprint())?;
        Ok(())
    }
}
