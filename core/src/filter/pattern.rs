use super::ast::*;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use hashlink::LinkedHashMap;
use petgraph::algo;
use petgraph::graph::NodeIndex;

use crate::conntrack::conn::conn_state::StateTxOrd;
use crate::{conntrack::StateTransition, filter::FilterError};
use crate::port::Port;

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlatPattern {
    pub predicates: Vec<Predicate>,
}

impl FlatPattern {
    // Returns true if pattern is empty
    pub(super) fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    // Returns true if self is a fully qualified FlatPattern
    pub(super) fn is_fully_qualified(&self) -> bool {
        let (layers, labels) = (&*LAYERS, &*NODE_BIMAP);

        let mut ret = true;
        let mut prev_header = unwrap_or_ret_false!(labels.get_by_right(&protocol!("ethernet")));

        for predicate in self.predicates.iter() {
            match predicate {
                Predicate::Unary { protocol } => {
                    let cur_header = unwrap_or_ret_false!(labels.get_by_right(protocol));
                    ret = ret && layers.contains_edge(*cur_header, *prev_header);
                    prev_header = cur_header;
                }
                Predicate::Binary { protocol, .. } => {
                    let cur_header = unwrap_or_ret_false!(labels.get_by_right(protocol));
                    ret = ret && (*cur_header == *prev_header)
                }
                _ => continue,
            }
        }
        ret
    }

    // Returns a vector of fully qualified patterns from self
    pub(super) fn to_fully_qualified(&self) -> Result<Vec<LayeredPattern>> {
        if self.is_empty() {
            return Ok(Vec::new());
        }

        let (layers, labels) = (&*LAYERS, &*NODE_BIMAP);

        let mut node_paths: HashSet<Vec<NodeIndex>> = HashSet::new();
        let headers = self
            .predicates
            .iter()
            .filter(|c| c.get_protocol() != ProtocolName::none())
            .map(|c| c.get_protocol())
            .collect::<HashSet<_>>();
        for header in headers.iter() {
            match labels.get_by_right(header) {
                Some(node) => {
                    let ethernet = labels
                        .get_by_right(&protocol!("ethernet"))
                        .expect("Ethernet not defined.");
                    let node_path: HashSet<Vec<NodeIndex>> =
                        algo::all_simple_paths(&layers, *node, *ethernet, 0, None).collect();
                    node_paths.extend(node_path.iter().map(|p| p.to_vec()));
                }
                None => panic!("Predicate header invalid: {}", header),
            }
        }

        // all possible fully qualified paths from predicated headers
        let mut fq_paths = HashSet::new();
        for node_path in node_paths {
            let mut fq_path = node_path
                .iter()
                .map(|n| labels.get_by_left(n).unwrap().to_owned())
                .collect::<Vec<_>>();
            fq_path.remove(fq_path.len() - 1); // remove ethernet
            fq_path.reverse();
            fq_paths.insert(fq_path);
        }

        // build fully qualified patterns (could have multiple per non-fully-qualified pattern)
        let mut fq_patterns = vec![];
        for fq_path in fq_paths {
            let fq_headers: HashSet<&ProtocolName> = fq_path.iter().clone().collect();
            if headers.is_subset(&fq_headers) {
                let mut fq_pattern = LayeredPattern::new();
                for protocol in fq_path.iter() {
                    let proto_predicates = self
                        .predicates
                        .iter()
                        .filter(|c| c.get_protocol() == protocol && c.is_binary())
                        .map(|c| c.to_owned())
                        .collect::<HashSet<_>>();

                    let mut proto_predicates = proto_predicates.into_iter().collect::<Vec<_>>();
                    proto_predicates.sort();

                    assert!(fq_pattern.add_protocol(protocol.to_owned(), proto_predicates));
                }
                fq_patterns.push(fq_pattern);
            }
        }

        // Get all custom filters that don't belong to a protocol, validate
        // that they are valid custom filters, and insert each at the end of
        // each end-to-end pattern.
        let custom_preds = self
            .predicates
            .iter()
            .filter(|c| c.is_custom())
            .map(|c| c.to_owned())
            .collect::<HashSet<_>>();
        if !custom_preds.is_empty() {
            // Add custom filter predicate to end of all patterns
            for pattern in fq_patterns.iter_mut() {
                pattern.extend_patterns(&custom_preds);
            }
            // ...or as standalone pattern
            if fq_patterns.is_empty() {
                fq_patterns.push(LayeredPattern::new());
                fq_patterns
                    .last_mut()
                    .unwrap()
                    .extend_patterns(&custom_preds);
            }
        }

        if fq_patterns.is_empty() {
            // This happens when the headers provided do not have a directed path to ethernet node
            // and no custom filters are provided.
            bail!(FilterError::InvalidPatternLayers(self.to_owned()));
        }
        Ok(fq_patterns)
    }

    // Validate and populate DataLevels for the custom predicates
    // When building a filter from a string, only the name of the custom filter is available.
    // To populate needed data, we need to correlate these names with the information parsed
    // at compile-time from the defined custom filters.
    pub(super) fn handle_custom_predicates(&mut self, valid_preds: &Vec<Predicate>) -> Result<()> {
        for p_empty in &mut self.predicates {
            if p_empty.is_custom() {
                let p = valid_preds.iter()
                                       .find(|p| p.get_name() == p_empty.get_name())
                                       .ok_or(FilterError::InvalidCustomFilter(p_empty.get_name().clone()))?;
                *p_empty = p.clone();
            }
        }
        Ok(())
    }

    // Returns FlatPattern of only predicates that can be filtered in hardware
    pub(super) fn retain_hardware_predicates(&self, port: &Port) -> FlatPattern {
        FlatPattern {
            predicates: self
                .predicates
                .clone()
                .into_iter()
                .filter(|p| p.is_hardware_filterable(port))
                .collect::<Vec<_>>(),
        }
    }

    // Returns the predicates in FlatPattern that come after (or may come after)
    // the given StateTransition.
    pub(super) fn next_pred(&self, curr: StateTransition) -> Vec<StateTransition> {
        self.predicates
            .iter()
            .flat_map(|p| p.levels())
            .filter(|l|
                matches!(l.compare(&curr), StateTxOrd::Unknown | StateTxOrd::Greater)
            )
            .collect::<HashSet<_>>() // dedup
            .into_iter()
            .cloned()
            .collect()
    }
}

impl fmt::Display for FlatPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "[")?;
        let mut first = true;
        for predicate in self.predicates.iter() {
            if !first {
                write!(f, ", {}", predicate)?;
            } else {
                write!(f, "{}", predicate)?;
            }
            first = false;
        }
        write!(f, "]")?;
        Ok(())
    }
}

// Represents a fully qualified pattern, ordered by header layer
#[derive(Debug, Clone)]
pub struct LayeredPattern(LinkedHashMap<ProtocolName, Vec<Predicate>>);

impl LayeredPattern {
    pub(super) fn new() -> Self {
        LayeredPattern(LinkedHashMap::new())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // Add `predicates` to the _end_ of the pattern.
    fn extend_patterns(&mut self, predicates: &HashSet<Predicate>) {
        if self.0.is_empty() {
            self.0.insert(
                ProtocolName::none().clone(),
                predicates.iter().map(|p| p.to_owned()).collect(),
            );
            return;
        }
        self.0.insert(
            ProtocolName::none().clone(),
            predicates.iter().cloned().collect(),
        );
    }

    // Adds predicates on protocol header. Returns true on success
    fn add_protocol(&mut self, proto_name: ProtocolName, field_predicates: Vec<Predicate>) -> bool {
        let (layers, labels) = (&*LAYERS, &*NODE_BIMAP);

        // check that there is an edge to previous protocol header
        // check that field_predicates are all binary
        // check that field_predicates are all predicates on protocol
        // ignore custom filters
        let mut ret = true;
        let node = unwrap_or_ret_false!(labels.get_by_right(&proto_name));
        if let Some((outer_proto, _)) = self.0.back() {
            let prev = unwrap_or_ret_false!(labels.get_by_right(outer_proto));
            ret = ret && layers.contains_edge(*node, *prev);
            for pred in field_predicates.iter() {
                ret = ret
                    && match pred {
                        Predicate::Unary { .. } => false,
                        Predicate::Binary { protocol, .. } => protocol == &proto_name,
                        Predicate::Custom { .. }
                        | Predicate::Callback { .. }
                        | Predicate::LayerState { .. } => false,
                    }
            }
        } else {
            // IPv4 or IPv6
            let root = unwrap_or_ret_false!(labels.get_by_right(&protocol!("ethernet")));
            ret = ret && layers.contains_edge(*node, *root);
        }

        if ret {
            self.0.insert(proto_name, field_predicates);
            ret
        } else {
            false
        }
    }

    // flattens LayeredPattern to fully qualified FlatPattern
    pub(super) fn to_flat_pattern(&self) -> FlatPattern {
        let mut predicates = vec![];
        for (protocol, field_preds) in self.0.iter() {
            predicates.push(Predicate::Unary {
                protocol: protocol.to_owned(),
            });
            predicates.extend(field_preds.to_owned());
        }
        FlatPattern { predicates }
    }

    pub(super) fn get_header_predicates(&self) -> &LinkedHashMap<ProtocolName, Vec<Predicate>> {
        &self.0
    }
}

impl Default for LayeredPattern {
    fn default() -> Self {
        Self::new()
    }
}

impl Ord for LayeredPattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_flat_pattern().cmp(&other.to_flat_pattern())
    }
}

impl PartialOrd for LayeredPattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for LayeredPattern {
    fn eq(&self, other: &Self) -> bool {
        self.to_flat_pattern() == other.to_flat_pattern()
    }
}

impl Eq for LayeredPattern {}

impl fmt::Display for LayeredPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_flat_pattern())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        conntrack::DataLevel,
        filter::{ast::Predicate, parser::FilterParser, ptree_flat::FlatPTree},
    };

    lazy_static! {
        static ref CUSTOM_FILTERS: Vec<Predicate> = vec![Predicate::Custom {
            name: filterfunc!("my_filter"),
            levels: vec![DataLevel::L4InPayload(false)],
        }];
    }

    #[test]
    fn test_custom_single() {
        // Single custom filter.
        let filter_raw = "my_filter";
        let raw_patterns = FilterParser::parse_filter(filter_raw).unwrap();
        // Vector of patterns. Expect one pattern and for this pattern to have one predicate.
        assert!(
            raw_patterns.len() == 1
                && raw_patterns.first().unwrap().len() == 1
                && raw_patterns.first().unwrap().first().unwrap().is_custom()
        );
        let flat_patterns = raw_patterns
            .into_iter()
            .map(|p| {
                let mut patt = FlatPattern { predicates: p };
                patt.handle_custom_predicates(&CUSTOM_FILTERS).unwrap();
                patt
            })
            .collect::<Vec<_>>();
        let fq_patterns = flat_patterns[0]
            .to_fully_qualified()
            .unwrap();
        assert!(
            fq_patterns.len() == 1
                && fq_patterns[0]
                    .0
                    .get(ProtocolName::none())
                    .expect("Expecting `none` protocol entry")
                    .get(0)
                    .expect("Expecting `none` protocol with 1 predicate")
                    .get_name()
                    == &filterfunc!("my_filter")
        );
    }

    #[test]
    fn test_custom_pattern() {
        let filter_raw = "tcp.port = 80 and tls and my_filter";
        let raw_patterns = FilterParser::parse_filter(filter_raw).unwrap();
        let flat_patterns = raw_patterns
            .into_iter()
            .map(|p| {
                let mut patt = FlatPattern { predicates: p };
                patt.handle_custom_predicates(&CUSTOM_FILTERS).unwrap();
                patt
            })
            .collect::<Vec<_>>();
        let fq_patterns = flat_patterns[0]
            .to_fully_qualified()
            .unwrap();
        assert!(fq_patterns.len() == 2); // branches for ipv4/ipv6
        assert!(
            fq_patterns[0]
                .0 // my_filter in end of each branch
                .get(ProtocolName::none())
                .expect("Expecting `none` protocol entry")
                .len()
                == 1
        );
        assert!(
            fq_patterns[0].0.back().unwrap().0 == ProtocolName::none(),
            "`none` should be at back of patterns."
        );

        let flat_patterns: Vec<_> = fq_patterns.iter().map(|p| p.to_flat_pattern()).collect();
        let mut ptree = FlatPTree::new(&flat_patterns);
        ptree.prune_branches();
        // ipv4 -> tcp -> port -> tls -> none -> my_filter
        // + same for ipv4
        // "none" = empty node to indicate start of custom filters
        assert!(ptree.size == 13);
    }

    #[test]
    fn test_custom_invalid() {
        let filter_raw = "tcp.port = 80 and tls and my_filter and invalid_filter";
        let raw_patterns = FilterParser::parse_filter(filter_raw).unwrap();
        let mut flat_patterns = raw_patterns
            .into_iter()
            .map(|p| FlatPattern { predicates: p })
            .collect::<Vec<_>>();
        flat_patterns[0].handle_custom_predicates(&CUSTOM_FILTERS)
                        .expect_err("Should have failed on invalid_filter");
        // println!("Error thrown: {:?}", err);
    }
}
