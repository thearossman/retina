//! New datatypes are defined in this module.
//! Newly-defined datatypes must be added to the DATATYPES map in this module.

use proc_macro2::Span;
use quote::quote;
use retina_core::filter::SubscriptionSpec;

use crate::*;

/// A list of all sessions (zero-copy) parsed in the connection.
pub type SessionList = Vec<Session>;

/// The string literal representing a matched filter.
pub type FilterStr<'a> = &'a str;

impl<'a> FromSubscription for FilterStr<'a> {
    fn from_subscription(spec: &SubscriptionSpec) -> proc_macro2::TokenStream {
        let str = syn::LitStr::new(&spec.filter, Span::call_site());
        quote! { &#str }
    }
}
