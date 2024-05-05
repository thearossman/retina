use retina_core::filter::ast::{BinOp, FieldName, ProtocolName, Value};
use retina_core::filter::ptree::PNode;

use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;
use regex::Regex;
use syn::LitInt;

// TODO: give better compiler errors

pub(crate) fn binary_to_tokens(
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
    statics: &mut Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    if field.is_combined() {
        combined_field(protocol, field, op, value)
    } else {
        standard_field(protocol, field, op, value, statics)
    }
}

/// Generates filters for combined fields `addr` and `port`. Note that `!=` behavior
/// differs from Wireshark: https://wiki.wireshark.org/DisplayFilters, instead following
/// the intuitive meaning. For example, `tcp.port != 443` is equivalent to
/// `tcp.src_port != 443 and tcp.dst_port != 443`.
fn combined_field(
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
) -> proc_macro2::TokenStream {
    let proto = Ident::new(protocol.name(), Span::call_site());
    match field.name() {
        "addr" => match value {
            Value::Ipv4(ipv4net) => {
                let addr_u32 = u32::from(ipv4net.addr());
                let addr_lit = syn::LitInt::new(&addr_u32.to_string(), Span::call_site());

                let netmask_u32 = u32::from(ipv4net.netmask());
                let netmask_lit = syn::LitInt::new(&netmask_u32.to_string(), Span::call_site());

                let net_u32 = addr_u32 & netmask_u32;
                let net_lit = syn::LitInt::new(&net_u32.to_string(), Span::call_site());

                match *op {
                    BinOp::Eq => {
                        if ipv4net.prefix_len() == 32 {
                            quote! { u32::from(#proto.src_addr()) == #addr_lit || u32::from(#proto.dst_addr()) == #addr_lit }
                        } else {
                            quote! { u32::from(#proto.src_addr()) & #netmask_lit == #net_lit || u32::from(#proto.dst_addr()) & #netmask_lit == #net_lit }
                        }
                    }
                    BinOp::Ne => {
                        if ipv4net.prefix_len() == 32 {
                            quote! { u32::from(#proto.src_addr()) != #addr_lit && u32::from(#proto.dst_addr()) != #addr_lit }
                        } else {
                            quote! { u32::from(#proto.src_addr()) & #netmask_lit != #net_lit && u32::from(#proto.dst_addr()) & #netmask_lit != #net_lit }
                        }
                    }
                    BinOp::In => {
                        if ipv4net.prefix_len() == 32 {
                            quote! { u32::from(#proto.src_addr()) == #addr_lit || u32::from(#proto.dst_addr()) == #addr_lit }
                        } else {
                            quote! { u32::from(#proto.src_addr()) & #netmask_lit == #net_lit || u32::from(#proto.dst_addr()) & #netmask_lit == #net_lit }
                        }
                    }
                    _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
                }
            }
            Value::Ipv6(ipv6net) => {
                let addr_u128 = u128::from(ipv6net.addr());
                let addr_lit = syn::LitInt::new(&addr_u128.to_string(), Span::call_site());

                let netmask_u128 = u128::from(ipv6net.netmask());
                let netmask_lit = syn::LitInt::new(&netmask_u128.to_string(), Span::call_site());

                let net_u128 = addr_u128 & netmask_u128;
                let net_lit = syn::LitInt::new(&net_u128.to_string(), Span::call_site());

                match *op {
                    BinOp::Eq => {
                        if ipv6net.prefix_len() == 128 {
                            quote! { u128::from(#proto.src_addr()) == #addr_lit || u128::from(#proto.dst_addr()) == #addr_lit }
                        } else {
                            quote! { u128::from(#proto.src_addr()) & #netmask_lit == #net_lit || u128::from(#proto.dst_addr()) & #netmask_lit == #net_lit }
                        }
                    }
                    BinOp::Ne => {
                        if ipv6net.prefix_len() == 128 {
                            quote! { u128::from(#proto.src_addr()) != #addr_lit && u128::from(#proto.dst_addr()) != #addr_lit }
                        } else {
                            quote! { u128::from(#proto.src_addr()) & #netmask_lit != #net_lit && u128::from(#proto.dst_addr()) & #netmask_lit != #net_lit }
                        }
                    }
                    BinOp::In => {
                        if ipv6net.prefix_len() == 128 {
                            quote! { u128::from(#proto.src_addr()) == #addr_lit || u128::from(#proto.dst_addr()) == #addr_lit }
                        } else {
                            quote! { u128::from(#proto.src_addr()) & #netmask_lit == #net_lit || u128::from(#proto.dst_addr()) & #netmask_lit == #net_lit }
                        }
                    }
                    _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
                }
            }
            _ => panic!("Invalid value `{}` for combined field `addr`.", value),
        },
        "port" => match value {
            Value::Int(val) => {
                let val_lit = syn::LitInt::new(&val.to_string(), Span::call_site());
                match *op {
                    BinOp::Eq => {
                        quote! { #proto.src_port() == #val_lit || #proto.dst_port() == #val_lit }
                    }
                    BinOp::Ne => {
                        quote! { #proto.src_port() != #val_lit && #proto.dst_port() != #val_lit }
                    }
                    BinOp::Ge => {
                        quote! { #proto.src_port() >= #val_lit || #proto.dst_port() >= #val_lit }
                    }
                    BinOp::Le => {
                        quote! { #proto.src_port() <= #val_lit || #proto.dst_port() <= #val_lit }
                    }
                    BinOp::Gt => {
                        quote! { #proto.src_port() > #val_lit || #proto.dst_port() > #val_lit }
                    }
                    BinOp::Lt => {
                        quote! { #proto.src_port() < #val_lit || #proto.dst_port() < #val_lit }
                    }
                    _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
                }
            }
            _ => panic!("Invalid value `{}` for combined field `port`.", value),
        },
        _ => panic!("Unknown combined field: `{}`.", field.name()),
    }
}

fn standard_field(
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
    statics: &mut Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    let proto = Ident::new(protocol.name(), Span::call_site());
    let field = Ident::new(field.name(), Span::call_site());

    match value {
        Value::Int(val) => {
            let val_lit = syn::LitInt::new(&val.to_string(), Span::call_site());
            match *op {
                BinOp::Eq => quote! { #proto.#field() == #val_lit },
                BinOp::Ne => quote! { #proto.#field() != #val_lit },
                BinOp::Ge => quote! { #proto.#field() >= #val_lit },
                BinOp::Le => quote! { #proto.#field() <= #val_lit },
                BinOp::Gt => quote! { #proto.#field() > #val_lit },
                BinOp::Lt => quote! { #proto.#field() < #val_lit },
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::IntRange { from, to } => {
            let from_lit = syn::LitInt::new(&from.to_string(), Span::call_site());
            let to_lit = syn::LitInt::new(&to.to_string(), Span::call_site());
            match *op {
                BinOp::In => quote! {
                    #proto.#field() >= #from_lit && #proto.#field() <= #to_lit
                },
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Ipv4(ipv4net) => {
            let addr_u32 = u32::from(ipv4net.addr());
            let addr_lit = syn::LitInt::new(&addr_u32.to_string(), Span::call_site());

            let netmask_u32 = u32::from(ipv4net.netmask());
            let netmask_lit = syn::LitInt::new(&netmask_u32.to_string(), Span::call_site());

            let net_u32 = addr_u32 & netmask_u32;
            let net_lit = syn::LitInt::new(&net_u32.to_string(), Span::call_site());

            match *op {
                BinOp::Eq => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                BinOp::Ne => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) != #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit != #net_lit }
                    }
                }
                BinOp::In => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Ipv6(ipv6net) => {
            let addr_u128 = u128::from(ipv6net.addr());
            let addr_lit = syn::LitInt::new(&addr_u128.to_string(), Span::call_site());

            let netmask_u128 = u128::from(ipv6net.netmask());
            let netmask_lit = syn::LitInt::new(&netmask_u128.to_string(), Span::call_site());

            let net_u128 = addr_u128 & netmask_u128;
            let net_lit = syn::LitInt::new(&net_u128.to_string(), Span::call_site());

            match *op {
                BinOp::Eq => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                BinOp::Ne => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) != #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit != #net_lit }
                    }
                }
                BinOp::In => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Text(text) => {
            match *op {
                BinOp::Eq => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());
                    quote! { #proto.#field() == #val_lit }
                }
                BinOp::En => {
                    let field_ident =
                        Ident::new(&field.to_string().to_camel_case(), Span::call_site());
                    let variant_ident =
                        Ident::new(&text.as_str().to_camel_case(), Span::call_site());
                    quote! { #proto.#field() == retina_core::protocols::stream::#proto::#field_ident::#variant_ident }
                }
                BinOp::Re => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());
                    if Regex::new(text).is_err() {
                        panic!("Invalid Regex string")
                    }

                    let re_name = format!("RE{}", statics.len());
                    let re_ident = Ident::new(&re_name, Span::call_site());
                    let lazy_re = quote! {
                        static ref #re_ident: regex::Regex = regex::Regex::new(#val_lit).unwrap();
                    };
                    // avoids compiling the Regex every time
                    statics.push(lazy_re);
                    quote! {
                        #re_ident.is_match(&#proto.#field()[..])
                    }
                    // quote! {
                    //     Regex::new(#val_lit).unwrap().is_match(#proto.#field())
                    // }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
    }
}


// Codegen utils shared between packet, connection, and session filters. //

pub(crate) fn terminal_match(node: &PNode) -> (proc_macro2::TokenStream, Vec<usize>) {
    if node.is_terminal.is_empty() {
        return (quote! {}, vec![]);
    }
    let mut terminal_body = vec![];
    let mut terminal_matches = vec![];
    for idx in &node.is_terminal {
        let idx_lit = syn::LitInt::new(&idx.to_string(), Span::call_site());
        terminal_body.push(
            quote! { result.terminal_matches.push( #idx_lit ); }
        );
        terminal_matches.push(*idx);
    }
    (quote! { #( #terminal_body )* }, terminal_matches)
}

pub(crate) fn nonterminal_match(node: &PNode, terminal_matches: &Vec<usize>) -> (proc_macro2::TokenStream, bool) {
    if node.filter_ids.is_empty() {
        return (quote! {}, false);
    }
    let node_idx_lit = syn::LitInt::new(&node.id.to_string(), Span::call_site());
    let mut nonterminal_nodes = vec![];
    let mut nonterminal_body = vec![];
    for idx in &node.filter_ids {
        if !terminal_matches.contains(idx) {
            let idx_lit = syn::LitInt::new(&idx.to_string(), Span::call_site());
            nonterminal_body.push(
                quote! { result.nonterminal_matches.push( #idx_lit ); }
            );
        }
    }
    nonterminal_nodes.push(quote! {
        result.nonterminal_nodes.push(#node_idx_lit);
    });

    (quote! { 
        #( #nonterminal_body )*
        #( #nonterminal_nodes )*
    }, true)
}
