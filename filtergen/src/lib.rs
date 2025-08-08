#![allow(clippy::needless_doctest_main)]

use proc_macro::TokenStream;
use syn::{parse_macro_input, Item};

mod parse;
use parse::*;
mod cache;
mod codegen;
mod subscription;

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
    let decoder = {
        let mut inputs = cache::CACHED_DATA.lock().unwrap();
        SubscriptionDecoder::new(inputs.as_mut())
    };
    let _tracked_def = codegen::tracked_to_tokens(&decoder.tracked);
    let _tracked_new = codegen::tracked_new_to_tokens(&decoder.tracked);
    let _tracked_update = codegen::tracked_update_to_tokens(&decoder);

    input
}
