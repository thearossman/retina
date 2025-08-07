use super::subscription::*;
use super::parse::*;
use proc_macro2::Span;
use quote::quote;
use retina_core::conntrack::Actions;
use retina_core::conntrack::TrackedActions;
use retina_core::filter::subscription::{DataActions, CallbackSpec, DataLevelSpec};

fn cb_to_tokens(sub: &SubscriptionDecoder, cb: &CallbackSpec) -> proc_macro2::TokenStream {
    let mut conditions = vec![];
    let mut cond_match = vec![];
    let mut params = vec![];
    params_to_tokens(sub, &cb.datatypes,
        &mut conditions,
        &mut cond_match,
        &mut params);

    // Invoking this CB requires invoking a method on a struct
    // TODO also handle the static CBs that are tracked to avoid being
    // invoked 2x!!
    let is_stateful = cb.as_str != cb.subscription_id &&
        cb.subscription_id != "";
    let cb_name = syn::Ident::new(&cb.as_str, Span::call_site());
    let cb_id = syn::Ident::new(
        &cb.subscription_id.to_lowercase(),
        Span::call_site());
    let mut cb_wrapper = cb.subscription_id.to_lowercase();
    cb_wrapper.push_str("_wrap");
    let cb_wrapper = syn::Ident::new(
        &cb_wrapper,
        Span::call_site()
    );

    let invoke = match is_stateful {
        true => {
            quote! {
                if !tracked.#cb_id.#cb_name(#( #params ), *) {
                    tracked.#cb_wrapper.set_inactive();
                }
            }
        },
        false => {
            quote! { #cb_name(#( #params ), *); }
        }
    };

    let invoke = match cond_match.is_empty() {
        true => {
            quote! { #invoke }
        },
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

    match is_stateful {
        true => {
            quote! {
                // Only invoke if active; unsubscribe if needed
                if tracked.#cb_wrapper.is_active() {
                    #invoke
                }
            }
        },
        false => {
            quote! { #invoke }
        }
    }
}

/// Checking whether a custom filter matched
fn cust_filter_to_tokens(
    sub: &SubscriptionDecoder,
    fil_id: &String,
) -> proc_macro2::TokenStream {
    let _fil = sub.filters_raw
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
fn params_to_tokens(
    sub: &SubscriptionDecoder,
    datatypes: &Vec<DataLevelSpec>,
    conditions: &mut Vec<proc_macro2::TokenStream>,
    cond_match: &mut Vec<proc_macro2::TokenStream>,
    params: &mut Vec<proc_macro2::TokenStream>,
)
{
    for dt in datatypes {
        let dt_metadata = sub.datatypes_raw
            .get(&dt.name)
            .expect(&format!("Cannot find {} in known datatypes", dt.name));
        let dt_name_ident = syn::Ident::new(
            &dt.name.to_lowercase(),
            Span::call_site());

        // Case 1: extract directly from tracked data
        if sub.tracked.contains(&dt.name) {
            // TODO need to standardize how `tracked` is stored
            // (`self` vs. in `conn`).
            params.push(quote! { &conn.tracked.#dt_name_ident, });
            continue;
        }

        // Case 2: Built-in datatype
        if BUILTIN_TYPES.iter().any(|inp| inp.name() == &dt.name) {
            let builtin = builtin_to_tokens(&dt.name);
            params.push( quote!{ #builtin });
            continue;
        }

        // Case 3: datatype constructed in-place
        let constructor = dt_metadata.iter()
            .find(|inp| {
                match inp {
                    ParsedInput::DatatypeFn(spec) => {
                        matches!(spec.func.returns, FnReturn::Constructor(_))
                    },
                    _ => false,
                }
            });
        if let Some(inp) = constructor {
            if let ParsedInput::DatatypeFn(spec) = inp {
                // TODO validate / what other restrictions needed here?
                assert!(dt.updates.iter().any(|l| !l.is_streaming()));
                constr_to_tokens(spec, conditions,
                        cond_match, params, &dt_name_ident);
            }
        }
    }
}

fn constr_to_tokens(
    spec: &DatatypeFnSpec,
    conditions: &mut Vec<proc_macro2::TokenStream>,
    cond_match: &mut Vec<proc_macro2::TokenStream>,
    params:  &mut Vec<proc_macro2::TokenStream>,
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
            panic!("Invalid input for datatype constructor: {}",
                    spec.func.datatypes.first().unwrap());
        };
        let name = syn::Ident::new(&spec.func.name, Span::call_site());
        quote! { #name(#param) }
    };

    if matches!(returns, Constructor::Opt | Constructor::OptRef) {
        conditions.push(quote!{ #constructor, });
        cond_match.push(quote!{ Some(#name_ident), });
        if matches!(returns, Constructor::OptRef) {
            params.push(quote! { #name_ident, });
        } else {
            // TODO can relax the borrowing requirement here
            params.push(quote! { &#name_ident, });
        }
    } else {
        // TODO check is &Self also an option?
        params.push( quote! { &#constructor } );
    }
}

fn builtin_to_tokens(name: &String) -> proc_macro2::TokenStream {
    if name == "L4Pdu" {
        return quote! { pdu };
    } else if name == "FilterStr" {
        unimplemented!(); // TODO
    }
    panic!("Unknown builtin datatype: {}", name);
}

fn data_actions_to_tokens(actions: &DataActions) -> proc_macro2::TokenStream {
    let mut ret = vec![ quote! { } ];
    if !actions.transport.drop() {
        let tracked = tracked_actions_to_tokens(&actions.transport);
        ret.push(quote! { conn.linfo.actions.extend(#tracked); });
    }
    if !actions.layers[0].drop() {
        let lyrs = tracked_actions_to_tokens(&actions.layers[0]);
        ret.push(
            quote! { conn.layers[0].push_action(#lyrs); }
        );
    }
    quote! { #( #ret )* }
}

fn tracked_actions_to_tokens(actions: &TrackedActions) -> proc_macro2::TokenStream {
    let active = actions_to_tokens(&actions.active);
    let refr_at: Vec<proc_macro2::TokenStream> = actions
        .refresh_at
        .iter()
        .map(|a| {
           actions_to_tokens(a)
        })
        .collect();
    quote! {
        TrackedActions {
            active: #active,
            refresh_at: [#(#refr_at),*],
        }
    }
}

fn actions_to_tokens(actions: &Actions) -> proc_macro2::TokenStream {
    let bits = syn::LitInt::new(&actions.bits().to_string(), Span::call_site());
    quote! { Actions::from(#bits) }
}