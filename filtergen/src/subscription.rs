use crate::parse::*;
use lazy_static::lazy_static;
use retina_core::conntrack::DataLevel;
use retina_core::filter::ast::{FuncIdent, Predicate};
use retina_core::filter::subscription::{CallbackSpec, DataLevelSpec};
use retina_core::filter::{Filter, pattern::FlatPattern};
use std::collections::{HashMap, HashSet};

lazy_static! {
    pub(crate) static ref BUILTIN_TYPES: Vec<ParsedInput> = vec![
        ParsedInput::Datatype(DatatypeSpec {
            name: "L4Pdu".into(),
            level: Some(DataLevel::Packet),
        }),
        ParsedInput::Datatype(DatatypeSpec {
            name: "FilterStr".into(),
            level: None,
        })
    ];
}

#[derive(Debug)]
pub(crate) struct SubscriptionSpec {
    pub(crate) callbacks: Vec<CallbackSpec>,
    pub(crate) filter: String,
    pub(crate) as_str: String,
    pub(crate) patterns: Option<Vec<FlatPattern>>,
}

impl SubscriptionSpec {
    fn add_patterns(&mut self, custom_preds: &Vec<Predicate>) {
        if self.patterns.is_none() {
            let filter = Filter::new(&self.filter, &custom_preds)
                .expect(&format!("Invalid filter: {}", self.filter));
            self.patterns = Some(filter.get_patterns_flat());
        }
    }
}

/// Responsible for transforming the raw data in `parse.rs` into the formats
/// Retina requires.
pub(crate) struct SubscriptionDecoder {
    /// Filter group (or function name) --> Parsed Input(s)
    pub(crate) filters_raw: HashMap<String, Vec<ParsedInput>>,
    /// Map datatype group (or name) -> Parsed Input(s)
    pub(crate) datatypes_raw: HashMap<String, Vec<ParsedInput>>,
    /// Map cb group (or name) -> Parsed Input(s)
    pub(crate) cbs_raw: HashMap<String, Vec<ParsedInput>>,

    /// Valid custom predicates passed into Filter::new()
    pub(crate) custom_preds: Vec<Predicate>,
    /// Datatype name -> Datatype Spec with all updates
    /// Used to derive levels for callbacks and custom filters
    pub(crate) datatypes: HashMap<String, DataLevelSpec>,
    /// Full subscriptions
    pub(crate) subscriptions: Vec<SubscriptionSpec>,

    /// Required `updates`: Level of required update -->
    /// datatype update, filter method, or streaming callback.
    pub(crate) updates: HashMap<DataLevel, Vec<ParsedInput>>,
    /// Tracked datatypes (stored as fields in Tracked struct)
    pub(crate) tracked: HashSet<String>,
}

impl SubscriptionDecoder {
    pub(crate) fn new(inputs: &Vec<ParsedInput>) -> Self {
        let mut ret = Self {
            filters_raw: HashMap::new(),
            datatypes_raw: HashMap::new(),
            cbs_raw: HashMap::new(),
            custom_preds: Vec::new(),
            datatypes: HashMap::new(),
            subscriptions: Vec::new(),
            updates: HashMap::new(),
            tracked: HashSet::new(),
        };
        ret.parse_raw(inputs);
        ret.decode_datatypes();
        ret.decode_filters();
        ret.decode_subscriptions();
        ret.decode_updates();
        for spec in &mut ret.subscriptions {
            spec.add_patterns(&ret.custom_preds);
        }
        ret
    }

    /// Map inputs by name
    fn parse_raw(&mut self, inputs: &Vec<ParsedInput>) {
        BUILTIN_TYPES.iter().for_each(|dt| {
            self.datatypes_raw
                .insert(dt.name().clone(), vec![dt.clone()]);
        });
        for inp in inputs {
            let name = inp.name().clone();
            match inp {
                ParsedInput::Datatype(_) => {
                    let v = self.datatypes_raw.entry(name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::DatatypeFn(dt) => {
                    let group_name = dt.group_name.clone();
                    let v = self.datatypes_raw.entry(group_name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::Filter(_) => {
                    self.filters_raw.insert(name.clone(), vec![inp.clone()]);
                }
                ParsedInput::FilterGroup(_) => {
                    let v = self.filters_raw.entry(name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::FilterGroupFn(f) => {
                    let group_name = f.group_name.clone();
                    let v = self.filters_raw.entry(group_name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::Callback(_) => {
                    assert!(
                        !self.cbs_raw.contains_key(&name),
                        "Callback {} defined twice",
                        name
                    );
                    self.cbs_raw.insert(name.clone(), vec![inp.clone()]);
                }
                ParsedInput::CallbackGroup(_) => {
                    let v = self.cbs_raw.entry(name).or_insert(vec![]);
                    v.push(inp.clone());
                }
                ParsedInput::CallbackGroupFn(cb) => {
                    let group_name = cb.group_name.clone();
                    let v = self.cbs_raw.entry(group_name).or_insert(vec![]);
                    v.push(inp.clone());
                }
            }
        }
    }

    fn decode_datatypes(&mut self) {
        for (dt, inp) in &self.datatypes_raw {
            let spec = DataLevelSpec {
                name: dt.clone(),
                updates: inp.iter().cloned().flat_map(|l| l.levels()).collect(),
            };
            self.datatypes.insert(dt.clone(), spec);
        }
    }

    fn decode_filters(&mut self) {
        for (name, v) in self.filters_raw.iter() {
            // Validate grouped input
            if v.iter().any(|inp| inp.is_group()) {
                assert!(v.len() > 1, "Missing group for {:?}", v);
                assert!(
                    v.iter().map(|s| s.group()).all(|x| x == v[0].group()),
                    "Mismatched groups in: {:?}",
                    v
                );
            } else {
                assert!(v.len() == 1, "Missing filter group for: {:?}", v);
            }

            // TODO this breaks if filter is trying to
            // request multiple datatypes like a callback
            let mut levels = vec![];
            for inp in v {
                let mut lvls = vec![];
                // Levels of the datatypes in the function(s)
                match inp {
                    ParsedInput::Filter(f) => {
                        lvls.extend(self.datatypes_to_levels(&f.func));
                    }
                    ParsedInput::FilterGroupFn(f) => {
                        lvls.extend(self.datatypes_to_levels(&f.func));
                    }
                    _ => continue,
                }
                // Explicitly annotated levels
                lvls.extend(inp.levels());
                lvls.sort();
                lvls.dedup();
                if !lvls.is_empty() {
                    levels.push(lvls);
                }
            }
            self.custom_preds.push(Predicate::Custom {
                name: FuncIdent(name.clone()),
                levels,
                matched: true,
            });
        }
    }

    fn decode_subscriptions(&mut self) {
        for (cb_name, v) in &self.cbs_raw {
            let inp_group = v
                .iter()
                .find(|i| matches!(i, ParsedInput::Callback(_) | ParsedInput::CallbackGroup(_)))
                .expect(&format!("{} missing callback definition", cb_name));
            let filter = match inp_group {
                ParsedInput::Callback(cb) => cb.filter.clone(),
                ParsedInput::CallbackGroup(cb) => cb.filter.clone(),
                _ => unreachable!(),
            };
            let mut callbacks = vec![];

            for inp in v {
                match inp {
                    ParsedInput::Callback(cb) => {
                        assert!(v.len() == 1);
                        assert!(
                            cb.level.len() <= 1, // TODO fix this??
                            "Cannot specify >1 explicit level per callback"
                        );
                        let expl_level = cb.level.last().cloned();
                        let cb_spec = self.spec_to_cbs(
                            &cb.func,
                            cb.func.name.clone(),
                            cb.func.name.clone(),
                            expl_level,
                        );
                        callbacks.push(cb_spec);
                    }
                    ParsedInput::CallbackGroupFn(cb) => {
                        // TODO fix this to allow multiple levels
                        let expl_level = cb.level.last().cloned();
                        let sub_id = cb.group_name.clone();
                        let as_str = format!("{}::{}", sub_id, cb.func.name);
                        let cb_spec = self.spec_to_cbs(&cb.func, as_str, sub_id, expl_level);
                        callbacks.push(cb_spec);
                    }
                    ParsedInput::CallbackGroup(_) => continue,
                    _ => panic!("Unknown ParsedInput in callback list"),
                }
            }
            self.subscriptions.push(SubscriptionSpec {
                callbacks,
                filter,
                as_str: cb_name.clone(),
                patterns: None,
            });
        }
    }

    fn spec_to_cbs(
        &self,
        spec: &FnSpec,
        as_str: String,
        subscription_id: String,
        expl_level: Option<DataLevel>,
    ) -> CallbackSpec {
        let must_deliver = spec.datatypes.iter().any(|dt| dt == "FilterStr");
        let datatypes = spec
            .datatypes
            .iter()
            .map(|dt_name| {
                self.datatypes
                    .get(dt_name)
                    .expect(&format!("Can't find datatype {}", dt_name))
                    .clone()
            })
            .collect::<Vec<_>>();
        CallbackSpec {
            expl_level,
            datatypes,
            must_deliver,
            as_str,
            subscription_id,
            tracked_data: vec![],
        }
    }

    // TODO figure out what should go here -- need to fix filters
    // Pull the top-level datatype declaration to infer a function level
    fn datatypes_to_levels(&self, spec: &FnSpec) -> Vec<DataLevel> {
        let mut lvls = vec![];
        for dt_name in &spec.datatypes {
            let dt_info = self
                .datatypes_raw
                .get(dt_name)
                .expect(&format!("Cannot find datatype {}", dt_name));
            let mut level = dt_info
                .iter()
                .find(|grp| matches!(grp, ParsedInput::Datatype(_)))
                .expect(&format!("Cannot find datatype declaration {}", dt_name))
                .levels();
            assert!(
                level.len() == 1,
                "{} declaration has {} levels (requires 1)",
                dt_name,
                level.len()
            );
            lvls.push(level.pop().unwrap());
        }
        lvls.sort();
        lvls.dedup();
        lvls
    }

    fn decode_updates(&mut self) {
        let mut updates = HashMap::new();
        for (name, v) in &self.filters_raw {
            Self::push_update(&mut updates, v);
            if Self::is_tracked_type(v) {
                self.tracked.insert(name.clone());
            }
        }
        for (name, v) in &self.datatypes_raw {
            Self::push_update(&mut updates, v);
            if Self::is_tracked_type(v) {
                self.tracked.insert(name.clone());
            }
        }
        for (name, v) in &self.cbs_raw {
            Self::push_update(&mut updates, v);
            if Self::is_tracked_type(v) {
                self.tracked.insert(name.clone());
            }
        }
        self.updates = updates;
    }

    fn push_update(updates: &mut HashMap<DataLevel, Vec<ParsedInput>>, inps: &Vec<ParsedInput>) {
        for inp in inps {
            let lvls = inp
                .levels()
                .into_iter()
                .filter(|l| l.is_streaming())
                .collect::<Vec<_>>();
            for l in lvls {
                updates.entry(l).or_insert(vec![]).push(inp.clone());
            }
        }
    }

    // TODO CB also needs to be tracked (differently - just make sure it hasn't already been invoked)
    // if it is a static CB with a streaming filter
    fn is_tracked_type(inps: &Vec<ParsedInput>) -> bool {
        // More than one update function, or
        inps.iter()
            .filter(|i| matches!(i, ParsedInput::DatatypeFn(_)))
            .count() > 1 ||
        // Streaming update requested
        inps.iter()
            .any(|inp|
                inp.levels().iter().any(|l| l.is_streaming())
            )
    }
}

#[cfg(test)]
mod tests {
    use retina_core::conntrack::DataLevel;
    use retina_core::filter::{ptree::*, Filter};

    use super::*;

    #[test]
    fn test_filter_parse_basic() {
        /*
         * struct MyGroup {
         *  field: ...
         * }
         *
         * impl MyGroup {
         *  fn new() -> Self;
         *
         *  #[filter_group("MyGroup,L4InPayload")]
         *  fn update(&mut self, pdu: &L4Pdu) -> FilterResult;
         *
         *  #[filter_group("MyGroup")]
         *  fn tls(&mut self, tls: &TlsHandshake) -> FilterResult;
         * }
         */
        let inputs = vec![
            ParsedInput::FilterGroup(FilterGroupSpec {
                level: None,
                name: "MyGroup".into(),
            }),
            ParsedInput::FilterGroupFn(FilterGroupFnSpec {
                level: vec![DataLevel::L4InPayload(false)],
                group_name: "MyGroup".into(),
                func: FnSpec {
                    name: "update".into(),
                    returns: FnReturn::FilterResult,
                    datatypes: vec!["L4Pdu".into()],
                },
            }),
            ParsedInput::FilterGroupFn(FilterGroupFnSpec {
                level: vec![],
                group_name: "MyGroup".into(),
                func: FnSpec {
                    name: "on_tls".into(),
                    returns: FnReturn::FilterResult,
                    datatypes: vec!["TlsHandshake".into()],
                },
            }),
            ParsedInput::Datatype(DatatypeSpec {
                level: Some(DataLevel::Packet),
                name: "L4Pdu".into(),
            }),
            ParsedInput::Datatype(DatatypeSpec {
                level: Some(DataLevel::L7EndHdrs),
                name: "TlsHandshake".into(),
            }),
            ParsedInput::Datatype(DatatypeSpec {
                level: None,
                name: "ConnRecord".into(),
            }),
            ParsedInput::DatatypeFn(DatatypeFnSpec {
                group_name: "ConnRecord".into(),
                func: FnSpec {
                    name: "update".into(),
                    datatypes: vec!["L4Pdu".into()],
                    returns: FnReturn::None,
                },
                level: vec![DataLevel::L4InPayload(false)],
            }),
            ParsedInput::Callback(CallbackFnSpec {
                filter: "ipv4 and tls and MyGroup".into(),
                level: vec![DataLevel::L4Terminated],
                func: FnSpec {
                    name: "my_cb".into(),
                    datatypes: vec!["ConnRecord".into(), "TlsHandshake".into()],
                    returns: FnReturn::None,
                },
            }),
        ];
        let decoder = SubscriptionDecoder::new(&inputs);
        assert!(decoder.custom_preds.len() == 1);
        assert!({
            let pred = decoder.custom_preds.first().unwrap();
            let levels = pred.levels();
            levels.len() == 2
                && levels.contains(&DataLevel::L4InPayload(false))
                && levels.contains(&DataLevel::L7EndHdrs)
        });
        assert!({
            let sub = decoder.subscriptions.first().unwrap();
            let datatypes = &sub.callbacks.first().unwrap().datatypes;
            datatypes.len() == 2
                && datatypes
                    .iter()
                    .any(|dt| dt.updates == vec![DataLevel::L4InPayload(false)])
                && datatypes
                    .iter()
                    .any(|dt| dt.updates == vec![DataLevel::L7EndHdrs])
        });

        assert!(decoder.updates.len() == 1);
        let entr = decoder.updates.get(&DataLevel::L4InPayload(false)).unwrap();
        assert!(
            entr.len() == 2,
            "Actual len: {} (value: {:?}",
            entr.len(),
            entr
        );

        // Build up some basic trees
        let mut ptree = PTree::new_empty(DataLevel::L7OnDisc);
        for s in &decoder.subscriptions {
            let filter = Filter::new(&s.filter, &decoder.custom_preds).unwrap();
            let patterns = filter.get_patterns_flat();
            ptree.add_subscription(&patterns, &s.callbacks, &s.as_str);
        }
        ptree.collapse();
        assert!(ptree.size == 4); // eth -> tls -> [MyGroup matched, matching]
        let node1 = ptree.get_subtree(2).unwrap();
        let node2 = ptree.get_subtree(3).unwrap();
        assert!(node1.pred.is_matching() || node2.pred.is_matching());
        assert!(!node1.pred.is_matching() || !node2.pred.is_matching());

        let mut ptree = PTree::new_empty(DataLevel::L7EndHdrs);
        for s in &decoder.subscriptions {
            let filter = Filter::new(&s.filter, &decoder.custom_preds).unwrap();
            let patterns = filter.get_patterns_flat();
            ptree.add_subscription(&patterns, &s.callbacks, &s.as_str);
        }
        ptree.collapse();
        assert!(!ptree.deliver.is_empty());

        let mut ptree = PTree::new_empty(DataLevel::L4InPayload(false));
        for s in &decoder.subscriptions {
            let filter = Filter::new(&s.filter, &decoder.custom_preds).unwrap();
            let patterns = filter.get_patterns_flat();
            ptree.add_subscription(&patterns, &s.callbacks, &s.as_str);
        }
        ptree.collapse();
        assert!(!ptree.deliver.is_empty());
    }
}
