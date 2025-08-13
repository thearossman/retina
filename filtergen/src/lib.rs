#![allow(clippy::needless_doctest_main)]

use proc_macro::TokenStream;
use quote::quote;
use std::collections::HashMap;
use syn::{parse_macro_input, Item};

mod parse;
use parse::*;
mod cache;
mod codegen;
mod subscription;

mod packet_filter;

use subscription::SubscriptionDecoder;

#[proc_macro_attribute]
pub fn datatype(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Datatype(DatatypeSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed datatype: {:?}", spec);
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn datatype_group(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::DatatypeFn(DatatypeFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed datatype function: {:?}", spec);
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn callback(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Callback(CallbackFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed callback: {:?}", spec);
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn callback_group(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::CallbackGroupFn(CallbackGroupFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed grouped callback function: {:?}", spec);
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn filter(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::Filter(FilterFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed filter definition: {:?}", spec);
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn filter_group(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as StringOpt).value;
    let input = parse_macro_input!(input as Item);
    let mut spec = ParsedInput::FilterGroupFn(FilterGroupFnSpec::default());
    spec.parse(&input, args).unwrap();
    println!("Parsed grouped filter function: {:?}", spec);
    cache::push_input(spec);
    quote::quote! {
        #input
    }
    .into()
}

#[proc_macro_attribute]
pub fn cache_file(args: TokenStream, input: TokenStream) -> TokenStream {
    let fp = parse_macro_input!(args as syn::LitStr);
    cache::set_crate_outfile(fp.value());
    input
}

#[proc_macro_attribute]
pub fn cache_file_env(args: TokenStream, input: TokenStream) -> TokenStream {
    let var = parse_macro_input!(args as syn::LitStr).value();
    let fp = std::env::var(var).unwrap();
    cache::set_crate_outfile(fp);
    input
}

#[proc_macro_attribute]
pub fn input_files(args: TokenStream, input: TokenStream) -> TokenStream {
    let fps = parse_macro_input!(args as syn::LitStr).value();
    let fps = fps.split(",").collect::<Vec<_>>();
    cache::set_input_files(fps);
    input
}

#[proc_macro_attribute]
pub fn retina_main(_args: TokenStream, input: TokenStream) -> TokenStream {
    // TODO - backup option that lets you specify num expected invocations?
    println!("Done with macros - beginning code generation");

    // TODO - allow this to be any input
    let input = parse_macro_input!(input as syn::ItemFn);

    let decoder = {
        let mut inputs = cache::CACHED_DATA.lock().unwrap();
        SubscriptionDecoder::new(inputs.as_mut())
    };
    let _tracked_def = codegen::tracked_to_tokens(&decoder.tracked);
    let _tracked_new = codegen::tracked_new_to_tokens(&decoder.tracked);
    let _tracked_update = codegen::tracked_update_to_tokens(&decoder);

    let packet_tree = decoder.get_packet_filter_tree();
    let packet_filter = packet_filter::gen_packet_filter(&packet_tree);
    let filter_str = packet_tree.to_filter_string();

    let statics: HashMap<String, proc_macro2::TokenStream> = HashMap::new();
    let lazy_statics = if statics.is_empty() {
        quote! {}
    } else {
        let statics = statics.values().collect::<Vec<_>>();
        quote! {
            lazy_static::lazy_static! {
                #( #statics )*
            }
        }
    };

    quote! {

        use retina_core::subscription::{Trackable, Subscribable};
        use retina_core::conntrack::{TrackedActions, ConnInfo};
        use retina_core::protocols::stream::ParserRegistry;

        #lazy_statics

        pub struct SubscribedWrapper;
        impl Subscribable for SubscribedWrapper {
            type Tracked = TrackedWrapper;
        }

        pub struct TrackedWrapper {
            packets: Vec<retina_core::Mbuf>,
            core_id: retina_core::CoreId,
            // TODO tracked
        }

        impl Trackable for TrackedWrapper {
            type Subscribed = SubscribedWrapper;
            fn new(first_pkt: &L4Pdu, core_id: retina_core::CoreId) -> Self {
                Self {
                    packets: Vec::new(),
                    core_id,
                    // TODO #new
                }
            }

            fn packets(&self) -> &Vec<retina_core::Mbuf> {
                &self.packets
            }

            fn core_id(&self) -> &retina_core::CoreId {
                &self.core_id
            }

            fn parsers() -> ParserRegistry {
                // TODO
                ParserRegistry::from_strings(vec![])
            }

            fn clear(&mut self) {
                self.packets.clear();
                // TODO: #clear
            }
        }

        pub fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {

            fn packet_filter(
                mbuf: &retina_core::Mbuf,
                core_id: &retina_core::CoreId
            ) -> bool
            {
                #packet_filter
            }

            fn state_tx(conn: &mut ConnInfo<TrackedWrapper>,
                    tx: &retina_core::StateTransition) {
                let tx_data = retina_core::StateTxData::from_tx(&tx, &conn.layers[0]);
                match tx {
                    _ => {},
                }
            }

            fn update(conn: &mut ConnInfo<TrackedWrapper>,
                pdu: &retina_core::L4Pdu,
                state: retina_core::StateTransition) -> bool
            {
                false
                // TODO: #update; let ret = false; ret
            }

            retina_core::filter::FilterFactory::new(
                #filter_str,
                packet_filter,
                state_tx,
                update
            )
        }

        #input
    }
    .into()
}
