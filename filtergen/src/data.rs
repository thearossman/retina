use retina_datatypes::*;
use std::collections::HashSet;
use proc_macro2::{Ident, Span};

use quote::quote;

pub(crate) struct TrackedDataBuilder {
    update: Vec<proc_macro2::TokenStream>,
    struct_def: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    subscribable_enum: Vec<proc_macro2::TokenStream>,
    app_parsers: HashSet<String>,
    subscribed_data: HashSet<String>
}

impl TrackedDataBuilder {
    pub(crate) fn new(subscribed_data: HashSet<String>) -> Self {
        Self {
            update: vec![],
            struct_def: vec![],
            new: vec![],
            subscribable_enum: vec![],
            app_parsers: HashSet::new(),
            subscribed_data
        }
    }

    pub(crate) fn build(&mut self) {
        for name in &self.subscribed_data {
            let type_name_str = name.as_str();
            if !DATATYPES.contains_key(type_name_str) {
                let valid_types: Vec<&str> = DATATYPES.keys()
                                                    .map(|s| *s )
                                                    .collect();

                panic!("Invalid datatype: {};\nDid you mean:\n {}", 
                        name, valid_types.join(",\n"));
            }
            let datatype = DATATYPES.get(type_name_str).unwrap();

            let type_name = Ident::new(&type_name_str, Span::call_site());
            let field_name_str = name.to_lowercase();
            let field_name = Ident::new(&field_name_str, Span::call_site());
            let needs_update = datatype.needs_update; 
            let needs_parse = datatype.needs_parse;
            
            self.struct_def.push(
                quote! { 
                    #field_name : #type_name,
                }
            );
            self.new.push( 
                quote! { #field_name: #type_name::new(&five_tuple), }
            );
            self.subscribable_enum.push(
                quote! { #type_name (#type_name), }
            );
            if needs_update {
                // TODO will a subscription ever want to be able to know if *it* is matching 
                //              before the deliver phase? 
                self.update.push(
                    quote! { self.#field_name.update(&pdu, session_id); }
                );
            }
            if needs_parse {
                self.app_parsers.insert(name.clone());
            }
        }
    }

    pub(crate) fn subscribable_wrapper(&mut self) -> proc_macro2::TokenStream {
        
        // TODO only include if actually needed
        let packet_deliver = quote! {
            if actions.data.contains(ActionData::PacketDeliver) {
                subscription.deliver_packet(&mbuf);
            }
        }; 

        // TODO only include if actually needed
        let packet_track = quote! {
            if actions.data.intersects(ActionData::PacketContinue) {
                if let Ok(ctxt) = L4Context::new(&mbuf) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
        };

        let mut conn_parsers = vec![];
        for datatype in &self.app_parsers {
            let type_ident = Ident::new(datatype, Span::call_site());
            // TODO: need to make sure that the parsers unique
            // best to do later in the code, since it also needs to be done for 
            // filter-req. parsers
            conn_parsers.push(
                quote! {
                    ret.extend(#type_ident::conn_parsers());
                }
            );
        }

        quote! {
            pub struct SubscribedWrapper;

            impl Subscribable for SubscribedWrapper {
                type Tracked = TrackedWrapper;
                type SubscribedData = Subscribed;
                fn parsers() -> Vec<ConnParser> {
                    let mut ret = vec![];
                    #( #conn_parsers )*
                    ret
                }
            
                fn process_packet(
                    mbuf: Mbuf,
                    subscription: &Subscription<Self>,
                    conn_tracker: &mut ConnTracker<Self::Tracked>,
                    actions: Actions
                ) {
                    #packet_deliver
                    #packet_track
                }
            } 
        }       
    }

    pub(crate) fn subscribed_enum(&mut self) -> proc_macro2::TokenStream {
        let field_names = std::mem::take(&mut self.subscribable_enum);
        quote! { 
            #[derive(Debug)]
            pub enum Subscribed {
                #( #field_names )*
            }
        }
    }

    pub(crate) fn tracked(&mut self) -> proc_macro2::TokenStream {
        let def = std::mem::take(&mut self.struct_def);
        let update = std::mem::take(&mut self.update);
        let new = std::mem::take(&mut self.new);
        quote! {
            pub struct TrackedWrapper {
                five_tuple: FiveTuple,
                #( #def )*
            }

            impl Trackable for TrackedWrapper {
                type Subscribed = SubscribedWrapper;
    
                fn new(five_tuple: FiveTuple) -> Self {

                    Self {
                        five_tuple,
                        #( #new )*
                    }
                }

                fn update(&mut self, 
                        pdu: L4Pdu, 
                        session_id: Option<usize>, 
                        actions: &ActionData)
                {
                    #( #update )*
                }
            
                fn deliver_session(&mut self, session: Session, 
                                subscription: &Subscription<Self::Subscribed>,
                                actions: &ActionData, conn_data: &ConnData)
                { 
                    // TODO only if actually needed
                    if actions.intersects(ActionData::SessionDeliver) {
                        subscription.deliver_session(&session, &conn_data, &self);
                    }
                }

                fn deliver_conn(&mut self, 
                                subscription: &Subscription<Self::Subscribed>,
                                actions: &ActionData, conn_data: &ConnData)
                {
                    subscription.deliver_conn(conn_data, self);
                }
                
                fn five_tuple(&self) -> FiveTuple {
                    self.five_tuple
                }
            }
        }
    }

}