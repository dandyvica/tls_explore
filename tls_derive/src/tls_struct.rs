// all helper functions for derive macrosused in TLS structures
use proc_macro::TokenStream;
use quote::quote;
use syn::visit::{self, Visit};
use syn::{Data, DataStruct, DeriveInput, Ident, TraitBound, TypeParam};

// structure used with the visit methods: stores generic parameter existence and list of bounds
#[derive(Default)]
struct ExprVisitor<'ast> {
    is_generic: bool,
    bounds: Vec<&'ast Ident>,
}

impl<'ast> Visit<'ast> for ExprVisitor<'ast> {
    fn visit_type_param(&mut self, node: &'ast TypeParam) {
        self.is_generic = true;
        visit::visit_type_param(self, node);
    }

    fn visit_trait_bound(&mut self, node: &'ast TraitBound) {
        //println!("TraitBound={:?}", node.path.segments[0].ident.to_string());
        if node.path.segments.len() > 0 {
            self.bounds.push(&node.path.segments[0].ident);
        }
        visit::visit_trait_bound(self, node);
    }
}

// helper function to check whether the structure being derived is a generic one
// and stores bounds if any
fn get_generic_data(derive_input: &DeriveInput) -> Option<proc_macro2::TokenStream> {
    // check whether we have generic type and bounds
    let mut visitor = ExprVisitor::default();
    visitor.visit_derive_input(&derive_input);

    // we have a generic type and maybe bounds
    if visitor.is_generic {
        // if no bound, empty token is used, otherwise the "where" keyword
        let where_bound = if visitor.bounds.len() == 0 {
            quote!()
        } else {
            quote!(where)
        };

        // now build the list of bounds as tokenstreams
        let trait_bound = visitor.bounds.iter().map(|bound| {
            // get name of the field as TokenStream
            let trait_bound = bound;

            quote! {
                T: #trait_bound,
            }
        });

        Some(quote!(#where_bound #(#trait_bound)*))
    } else {
        None
    }
}

// verify if the derive macro is applied to a structure
fn get_struct(ast: &DeriveInput) -> &DataStruct {
    if let Data::Struct(struct_token) = &ast.data {
        struct_token
    } else {
        panic!("<{}> is not a struct!", ast.ident.to_string());
    }
}

// create the impl methods for trait TlsDerive
pub fn tls_derive(ast: &DeriveInput) -> TokenStream {
    // get generic parameter if any
    let param = get_generic_data(&ast);

    // get struct data or panic
    let struct_token = get_struct(&ast);

    // save structure name because we're gonna use it soon
    let structure_name = &ast.ident;

    // calculate the summation of all lengths
    let method_calls_1 = struct_token.fields.iter().map(|f| {
        // get name of the field as TokenStream
        let field_name = f.ident.as_ref().unwrap();

        quote! {
            TlsDerive::tls_len(&self.#field_name)
        }
    });

    // call to_network_bytes() call for each field
    let method_calls_2 = struct_token.fields.iter().map(|f| {
        // get name of the field as TokenStream
        let field_name = f.ident.as_ref().unwrap();

        quote! {
            length += TlsDerive::to_network_bytes(&self.#field_name, v)?;
        }
    });

    // call from_network_bytes() call for each field
    let method_calls_3 = struct_token.fields.iter().map(|f| {
        // get name of the field as TokenStream
        let field_name = f.ident.as_ref().unwrap();

        quote! {
            TlsDerive::from_network_bytes(&mut self.#field_name, v)?;
        }
    });

    // implement the Structurizer trait for function length()
    let new_code = if param.is_some() {
        let bounds: proc_macro2::TokenStream = param.unwrap();

        quote! {
            // the generated impl.
            impl<T> TlsDerive for #structure_name<T> #bounds {
                fn tls_len(&self) -> usize {
                    0 #(+ #method_calls_1)*
                }

                fn to_network_bytes(&self, v: &mut Vec<u8>) -> std::io::Result<usize> {
                    let mut length = 0usize;
                    #( #method_calls_2)*
                    Ok(length)
                }

                fn from_network_bytes(&mut self, v: &mut std::io::Cursor<Vec<u8>>) -> std::io::Result<()> {
                    #( #method_calls_3)*
                    Ok(())
                }
            }
        }
    } else {
        quote! {
            // the generated impl.
            impl TlsDerive for #structure_name  {
                fn tls_len(&self) -> usize {
                    0 #(+ #method_calls_1)*
                }

                fn to_network_bytes(&self, v: &mut Vec<u8>)-> std::io::Result<usize> {
                    let mut length = 0usize;
                    #( #method_calls_2)*
                    Ok(length)
                }

                fn from_network_bytes(&mut self, v: &mut std::io::Cursor<Vec<u8>>) -> std::io::Result<()> {
                    #( #method_calls_3)*
                    Ok(())
                }
            }
        }
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(new_code)
}

// // create the to_network_bytes() method
// pub fn tls_to_network_bytes(ast: &DeriveInput) -> TokenStream {
//     // get generic parameter if any
//     let param = get_generic_data(&ast);

//     // get struct data or panic
//     let struct_token = get_struct(&ast);

//     // test if input is a struct: don't want anything other than that
//     // save structure name because we're gonna use it soon
//     let structure_name = &ast.ident;

//     // calculate the summation of all lengths
//     let method_calls = struct_token.fields.iter().map(|f| {
//         // get name of the field as TokenStream
//         let field_name = f.ident.as_ref().unwrap();

//         quote! {
//             length += TlsToNetworkBytes::to_network_bytes(&self.#field_name, v)?;
//         }
//     });

//     // implement the Structurizer trait for function TlsLength()
//     let new_code = if param.is_some() {
//         let bounds: proc_macro2::TokenStream = param.unwrap();

//         quote! {
//             // the generated impl.
//             impl<T> TlsToNetworkBytes for #structure_name<T> #bounds  {
//                 fn to_network_bytes(&self, v: &mut Vec<u8>) -> std::io::Result<usize> {
//                     let mut length = 0usize;
//                     #( #method_calls)*
//                     Ok(length)
//                 }
//             }
//         }
//     } else {
//         quote! {
//             // the generated impl.
//             impl TlsToNetworkBytes for #structure_name  {
//                 fn to_network_bytes(&self, v: &mut Vec<u8>)-> std::io::Result<usize> {
//                     let mut length = 0usize;
//                     #( #method_calls)*
//                     Ok(length)
//                 }
//             }
//         }
//     };

//     // Hand the output tokens back to the compiler
//     TokenStream::from(new_code)
// }

// // create the from_network_bytes() method
// pub fn tls_from_network_bytes(ast: &DeriveInput) -> TokenStream {
//     // get generic parameter if any
//     let param = get_generic_data(&ast);

//     // get struct data or panic
//     let struct_token = get_struct(&ast);

//     // save structure name because we're gonna use it soon
//     let structure_name = &ast.ident;

//     // calculate the summation of all lengths
//     let method_calls = struct_token.fields.iter().map(|f| {
//         // get name of the field as TokenStream
//         let field_name = f.ident.as_ref().unwrap();

//         quote! {
//             TlsFromNetworkBytes::from_network_bytes(&mut self.#field_name, v)?;
//         }
//     });

//     // implement the Structurizer trait for function length()
//     let new_code = if param.is_some() {
//         let bounds: proc_macro2::TokenStream = param.unwrap();

//         quote! {
//             // the generated impl.
//             impl<T> TlsFromNetworkBytes for #structure_name<T> #bounds {
//                 fn from_network_bytes(&mut self, v: &mut std::io::Cursor<Vec<u8>>) -> std::io::Result<()> {
//                     #( #method_calls)*
//                     Ok(())
//                 }
//             }
//         }
//     } else {
//         quote! {
//             // the generated impl.
//             impl TlsFromNetworkBytes for #structure_name  {
//                 fn from_network_bytes(&mut self, v: &mut std::io::Cursor<Vec<u8>>) -> std::io::Result<()> {
//                     #( #method_calls)*
//                     Ok(())
//                 }
//             }
//         }
//     };

//     // Hand the output tokens back to the compiler
//     TokenStream::from(new_code)
// }
