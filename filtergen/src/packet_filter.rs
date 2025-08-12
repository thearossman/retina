use quote::quote;
use proc_macro2::{Ident, Span};
use heck::CamelCase;
use retina_core::filter::ast::*;
use retina_core::filter::pkt_ptree::{PacketPNode, PacketPTree};
use crate::codegen::binary_to_tokens;

pub(crate) fn gen_packet_filter(
    ptree: &PacketPTree,
) -> proc_macro2::TokenStream {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    // Store result in variable (vs. early return)
    if !ptree.deliver.is_empty() {
        body.push(quote! { let mut matched = false; });
    }

    // Ensure root delivery/matches are covered
    if !ptree.root.deliver.is_empty() || ptree.root.is_terminal {
        update_body(&mut body, &ptree.root, ptree);
    }

    gen_packet_filter_util(&mut body, &ptree.root, &ptree);

    // Return value
    body.push(
        match ptree.deliver.is_empty() {
            true => quote! { false },
            false => quote! { matched },
        }
    );

    // Extract outer protocol (ethernet)
    let outer = Ident::new("ethernet", Span::call_site());
    let outer_type = Ident::new(&outer.to_string().to_camel_case(), Span::call_site());

    quote! {
        if let Ok(#outer) = &retina_core::protocols::packet::Packet::parse_to::<retina_core::protocols::packet::#outer::#outer_type>(mbuf) {
            #( #body )*
        }
    }
}


fn gen_packet_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PacketPNode,
    tree: &PacketPTree,
) {
    let mut first_unary = true;
    for child in node.children.iter().filter(|n| n.pred.on_packet()) {
        match &child.pred {
            Predicate::Unary { protocol } => {
                add_unary_pred(
                    code,
                    child,
                    node.pred.get_protocol(),
                    protocol,
                    first_unary,
                    tree
                );
                first_unary = false;
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                add_binary_pred(
                    code,
                    child,
                    protocol,
                    field,
                    op,
                    value,
                    tree
                );
            }
            _ => panic!("Unexpected predicate in packet filter: {:?}", child.pred),
        }
    }
}

fn update_body(
    body: &mut Vec<proc_macro2::TokenStream>,
    node: &PacketPNode,
    tree: &PacketPTree
) {
    if node.is_terminal {
        // If there won't be anything that needs to be delivered,
        // return `true` immediately
        if tree.deliver.is_empty() {
            body.push(quote! { return true; } );
        } else {
            body.push(quote! { ret = true; });
        }
    }
    if !node.deliver.is_empty() {
        unimplemented!(); // TODO
    }
}

fn add_unary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PacketPNode,
    outer_protocol: &ProtocolName,
    protocol: &ProtocolName,
    first_unary: bool,
    tree: &PacketPTree,
) {
    let outer = Ident::new(outer_protocol.name(), Span::call_site());
    let ident = Ident::new(protocol.name(), Span::call_site());
    let ident_type = Ident::new(&ident.to_string().to_camel_case(), Span::call_site());

    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_packet_filter_util(&mut body, node, tree);
    update_body(&mut body, node, tree);

    if first_unary {
        code.push(quote! {
            if let Ok(#ident) = &retina_core::protocols::packet::Packet::parse_to::<retina_core::protocols::packet::#ident::#ident_type>(#outer) {
                #( #body )*
            }
        });
    } else {
        code.push(quote! {
            else if let Ok(#ident) = &retina_core::protocols::packet::Packet::parse_to::<retina_core::protocols::packet::#ident::#ident_type>(#outer) {
                #( #body )*
            }
        });
    }
}

fn add_binary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    node: &PacketPNode,
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
    tree: &PacketPTree,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_packet_filter_util(&mut body, node, tree);
    update_body(&mut body, node, tree);
    let mut statics = vec![];
    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, &mut statics);
    assert!(statics.is_empty());
    code.push(quote! {
        if #pred_tokenstream {
            #( #body )*
        }
    });
}
