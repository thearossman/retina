use super::parse::*;
use super::subscription::*;
use proc_macro2::Span;
use quote::quote;
use retina_core::conntrack::Actions;
use retina_core::conntrack::StateTransition;
use retina_core::conntrack::TrackedActions;
use retina_core::filter::subscription::DataActions;
use std::collections::HashSet;

pub(crate) fn cb_to_tokens(
    sub: &SubscriptionDecoder,
    datatypes: &Vec<String>,
    cb_name: &String,
    cb_group: Option<&String>,
) -> proc_macro2::TokenStream {
    let mut conditions = vec![];
    let mut cond_match = vec![];
    let mut params = vec![];
    params_to_tokens(
        sub,
        datatypes,
        &mut conditions,
        &mut cond_match,
        &mut params,
    );

    // Invoking this CB requires invoking a method on a struct
    // TODO also handle the static CBs that are tracked to avoid being
    // invoked 2x!!
    let cb_name = syn::Ident::new(&cb_name, Span::call_site());
    let (cb_id, cb_wrapper) = match &cb_group {
        Some(grp) => {
            let mut grp = grp.to_lowercase();
            let id = syn::Ident::new(&grp, Span::call_site());
            grp.push_str("_wrap");
            (id, syn::Ident::new(&grp.to_lowercase(), Span::call_site()))
        }
        None => (
            syn::Ident::new("", Span::call_site()),
            syn::Ident::new("", Span::call_site()),
        ),
    };

    let invoke = match cb_group.is_some() {
        true => {
            quote! {
                if !conn.tracked.#cb_id.#cb_name(#( #params ), *) {
                    conn.tracked.#cb_wrapper.set_inactive();
                }
            }
        }
        false => {
            quote! { #cb_name(#( #params ), *); }
        }
    };

    let invoke = match cond_match.is_empty() {
        true => {
            quote! { #invoke }
        }
        false => {
            quote! {
                match ( #( #conditions ), * ) {
                    (#( #cond_match ), *) => {
                        #invoke
                    }
                    _ => {},
                }
            }
        }
    };

    match cb_group.is_some() {
        true => {
            quote! {
                // Only invoke if active; unsubscribe if needed
                if tracked.#cb_wrapper.is_active() {
                    #invoke
                }
            }
        }
        false => {
            quote! { #invoke }
        }
    }
}

/// Invoking a custom streaming filter function
pub(crate) fn filter_func_to_tokens(
    sub: &SubscriptionDecoder,
    filter: &ParsedInput,
    streaming: bool,
) -> proc_macro2::TokenStream {
    let func = match filter {
        ParsedInput::FilterGroupFn(fil) => &fil.func,
        ParsedInput::Filter(fil) => &fil.func,
        _ => unreachable!(),
    };
    let mut conditions = vec![];
    let mut cond_match = vec![];
    let mut params = vec![];
    params_to_tokens(
        sub,
        &func.datatypes,
        &mut conditions,
        &mut cond_match,
        &mut params,
    );
    let func_ident = syn::Ident::new(&func.name, Span::call_site());
    let fil_ident = syn::Ident::new(&filter.name(), Span::call_site());
    let mut fil_wrapper = filter.name().to_lowercase();
    fil_wrapper.push_str("_wrap");
    let fil_wrapper = syn::Ident::new(&fil_wrapper, Span::call_site());

    // Either invoke via `tracked` parent struct or just invoke directly
    let invoke = match filter {
        ParsedInput::FilterGroupFn(_) => {
            quote! { conn.tracked.#fil_ident.#func_ident(#( #params ), *) }
        }
        ParsedInput::Filter(_) => {
            quote! { #func_ident(#( #params ), *) }
        }
        _ => unreachable!(),
    };
    // Record FilterResult
    let mut invoke = quote! {
        let res = #invoke;
        conn.tracked.#fil_wrapper.record_result(res);
    };
    // Get return value for `update` function
    if streaming {
        invoke = quote! {
            #invoke
            state_tx = state_tx || matches!(res, FilterResult::Accept | FilterResult::Drop);
        };
    }

    // Extract parameters for filter if needed
    if cond_match.is_empty() {
        invoke = quote! {
            match ( #( #conditions ), * ) {
                (#( #cond_match ), *) => {
                    #invoke
                }
                _ => {},
            }
        };
    }

    quote! {
        if conn.tracked.#fil_wrapper.is_active() {
            #invoke
        }
    }
}

pub(crate) fn datatype_func_to_tokens(dt: &DatatypeFnSpec) -> proc_macro2::TokenStream {
    assert!(
        dt.func.datatypes.first().unwrap().contains("self") && dt.func.datatypes.len() == 2,
        "Check function definition of {:?}",
        dt
    );
    let param = dt
        .func
        .datatypes
        .last()
        .expect(&format!("Check function definition of {:?}", dt));
    let dt_name = syn::Ident::new(&dt.group_name.to_lowercase(), Span::call_site());
    let fname = syn::Ident::new(&dt.func.name, Span::call_site());
    if param == "L4Pdu" {
        return quote! {
            tracked.#dt_name.#fname(pdu);
        };
    } else if param == "StateTxOrd" {
        return quote! {
            tracked.#dt_name.#fname(tx);
        };
    }
    panic!("Unknown param for {}: {}", dt.func.name, param);
}

/// Checking whether a custom filter matched
pub(crate) fn filter_check_to_tokens(
    sub: &SubscriptionDecoder,
    fil_id: &String,
) -> proc_macro2::TokenStream {
    let _fil = sub
        .filters_raw
        .get(fil_id)
        .expect(&format!("Cannot find {} in defined filters", fil_id));

    // TODO support custom filters that don't need to be tracked

    let ident = syn::Ident::new(&fil_id, Span::call_site());
    quote! { tracked.#ident.matched() }
}

/// Used for filters and CBs
/// @sub Subscription decoder must already be built up
/// @datatypes Input datatypes (name of the type, e.g., struct)
///
/// Some parameters require constructors and may return Option<Self>.
/// Must provide vectors to generate the code that accounts for this.
/// @condition: e.g.: `match (val1, val2)`
/// @cond_match: e.g.: `Some(val1), Some(val2) => ... `
/// @params: actual variable names
pub(crate) fn params_to_tokens(
    sub: &SubscriptionDecoder,
    datatypes: &Vec<String>,
    conditions: &mut Vec<proc_macro2::TokenStream>,
    cond_match: &mut Vec<proc_macro2::TokenStream>,
    params: &mut Vec<proc_macro2::TokenStream>,
) {
    for dt in datatypes {
        let dt_metadata = sub
            .datatypes_raw
            .get(dt)
            .expect(&format!("Cannot find {} in known datatypes", dt));
        let dt_name_ident = syn::Ident::new(&dt.to_lowercase(), Span::call_site());

        // Case 1: extract directly from tracked data
        if sub.tracked.contains(dt) {
            // TODO need to standardize how `tracked` is stored
            // (`self` vs. in `conn`).
            params.push(quote! { &conn.tracked.#dt_name_ident, });
            continue;
        }

        // Case 2: Built-in datatype
        if BUILTIN_TYPES.iter().any(|inp| inp.name() == dt) {
            let builtin = builtin_to_tokens(&dt);
            params.push(quote! { #builtin });
            continue;
        }

        // Case 3: datatype constructed in-place
        let constructor = dt_metadata.iter().find(|inp| match inp {
            ParsedInput::DatatypeFn(spec) => {
                matches!(spec.func.returns, FnReturn::Constructor(_))
            }
            _ => false,
        });
        if let Some(inp) = constructor {
            if let ParsedInput::DatatypeFn(spec) = inp {
                // TODO validate / what other restrictions needed here?
                constr_to_tokens(spec, conditions, cond_match, params, &dt_name_ident);
            }
        }
    }
}

pub(crate) fn constr_to_tokens(
    spec: &DatatypeFnSpec,
    conditions: &mut Vec<proc_macro2::TokenStream>,
    cond_match: &mut Vec<proc_macro2::TokenStream>,
    params: &mut Vec<proc_macro2::TokenStream>,
    name_ident: &syn::Ident,
) {
    let returns = match spec.func.returns {
        FnReturn::Constructor(Constructor::Opt) => Constructor::Opt,
        FnReturn::Constructor(Constructor::OptRef) => Constructor::OptRef,
        FnReturn::Constructor(Constructor::Sel) => Constructor::Sel,
        _ => unreachable!(),
    };

    let constructor = {
        assert!(spec.func.datatypes.len() == 1);
        let dt = spec.func.datatypes.first().unwrap();
        // TODO confirm syntax
        let param = if dt == "L4Pdu" {
            quote! { pdu }
        } else if dt == "Session" {
            quote! { conn.tracked.last_session }
        } else if dt == "Mbuf" {
            quote! { &pdu.mbuf }
        } else {
            panic!(
                "Invalid input for datatype constructor: {}",
                spec.func.datatypes.first().unwrap()
            );
        };
        let name = syn::Ident::new(&spec.func.name, Span::call_site());
        quote! { #name(#param) }
    };

    if matches!(returns, Constructor::Opt | Constructor::OptRef) {
        conditions.push(quote! { #constructor, });
        cond_match.push(quote! { Some(#name_ident), });
        if matches!(returns, Constructor::OptRef) {
            params.push(quote! { #name_ident, });
        } else {
            // TODO can relax the borrowing requirement here
            params.push(quote! { &#name_ident, });
        }
    } else {
        // TODO check is &Self also an option?
        params.push(quote! { &#constructor });
    }
}

pub(crate) fn builtin_to_tokens(name: &String) -> proc_macro2::TokenStream {
    if name == "L4Pdu" {
        return quote! { pdu };
    } else if name == "FilterStr" {
        unimplemented!(); // TODO
    }
    panic!("Unknown builtin datatype: {}", name);
}

pub(crate) fn data_actions_to_tokens(actions: &DataActions) -> proc_macro2::TokenStream {
    let mut ret = vec![quote! {}];
    if !actions.transport.drop() {
        let tracked = tracked_actions_to_tokens(&actions.transport);
        ret.push(quote! { conn.linfo.actions.extend(#tracked); });
    }
    if !actions.layers[0].drop() {
        let lyrs = tracked_actions_to_tokens(&actions.layers[0]);
        ret.push(quote! { conn.layers[0].push_action(#lyrs); });
    }
    quote! { #( #ret )* }
}

pub(crate) fn tracked_actions_to_tokens(actions: &TrackedActions) -> proc_macro2::TokenStream {
    let active = actions_to_tokens(&actions.active);
    let refr_at: Vec<proc_macro2::TokenStream> = actions
        .refresh_at
        .iter()
        .map(|a| actions_to_tokens(a))
        .collect();
    quote! {
        TrackedActions {
            active: #active,
            refresh_at: [#(#refr_at),*],
        }
    }
}

pub(crate) fn actions_to_tokens(actions: &Actions) -> proc_macro2::TokenStream {
    let bits = syn::LitInt::new(&actions.bits().to_string(), Span::call_site());
    quote! { Actions::from(#bits) }
}

pub(crate) fn update_to_tokens(
    sub: &SubscriptionDecoder,
    curr: &StateTransition,
) -> proc_macro2::TokenStream {
    let updates = match sub.updates.get(&curr) {
        Some(updates) => updates,
        None => return quote! {},
    };
    let mut ret = vec![];
    for upd in updates {
        match upd {
            ParsedInput::Callback(cb) => {
                ret.push(cb_to_tokens(sub, &cb.func.datatypes, &cb.func.name, None));
            }
            ParsedInput::CallbackGroupFn(cb) => {
                ret.push(cb_to_tokens(
                    sub,
                    &cb.func.datatypes,
                    &cb.func.name,
                    Some(&cb.group_name),
                ));
            }
            ParsedInput::Filter(_) | ParsedInput::FilterGroupFn(_) => {
                ret.push(filter_func_to_tokens(sub, upd, curr.is_streaming()));
            }
            ParsedInput::DatatypeFn(dt) => {
                ret.push(datatype_func_to_tokens(dt));
            }
            _ => panic!("Invalid input in update list"),
        }
    }
    quote! {
        #( #ret )*
    }
}

pub(crate) fn tracked_to_tokens(tracked_datatypes: &HashSet<String>) -> proc_macro2::TokenStream {
    let mut def = vec![];
    for name in tracked_datatypes {
        let field_name = syn::Ident::new(&name.to_lowercase(), Span::call_site());
        let type_name = syn::Ident::new(name, Span::call_site());
        def.push(quote! {
            #field_name: #type_name,
        });
    }
    quote! {
        pub struct TrackedWrapper {
            core_id: retina_core::CoreId,
            #( #def )*
        }
    }
}

pub(crate) fn tracked_new_to_tokens(
    tracked_datatypes: &HashSet<String>,
) -> proc_macro2::TokenStream {
    let mut new = vec![];
    for name in tracked_datatypes {
        let field_name = syn::Ident::new(&name.to_lowercase(), Span::call_site());
        let type_name = syn::Ident::new(name, Span::call_site());
        new.push(quote! {
            #field_name: #type_name::new(),
        });
    }
    quote! {
        pub(crate) fn new(pdu: &retina_core::L4Pdu,
               core_id: retina_core::CoreId) -> Self {
            Self {
                core_id,
                #( #new )*
            }
        }
    }
}

pub(crate) fn tracked_update_to_tokens(sub: &SubscriptionDecoder) -> proc_macro2::TokenStream {
    let mut all_updates = vec![];
    for (level, inps) in &sub.updates {
        if inps.is_empty() {
            continue;
        }
        let updates = update_to_tokens(sub, level);
        let level_ident = syn::Ident::new(&level.to_string(), Span::call_site());
        all_updates.push(quote! {
            #level_ident => {
                #updates
            }
        });
    }
    quote! {
        match tx {
            #( #all_updates )*
            _ => {},
        }
    }
}
