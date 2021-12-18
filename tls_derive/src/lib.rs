use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod tls_struct;
use tls_struct::{tls_from_network_bytes, tls_length, tls_to_network_bytes};

mod tls_enum;
use tls_enum::tls_enum;

#[proc_macro_derive(TlsLength)]
pub fn tls_macro_length(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    tls_length(&ast)
}

#[proc_macro_derive(TlsToNetworkBytes)]
pub fn tls_macro_to_network_bytes(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    tls_to_network_bytes(&ast)
}

#[proc_macro_derive(TlsFromNetworkBytes)]
pub fn from_network_bytes(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    tls_from_network_bytes(&ast)
}

#[proc_macro_derive(TlsEnum)]
pub fn tls_macro_enum(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // inject code
    tls_enum(&ast)
}
