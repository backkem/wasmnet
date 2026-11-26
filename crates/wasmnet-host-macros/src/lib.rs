//! `portable_adapter!`: the wasmtime half of a portable extension, generated from the WIT of
//! the interfaces it serves (use it through `wasmnet_host::portable_adapter!`).
//!
//! A portable extension serves its interfaces through the core's generic `ImportServer`, which
//! reads and answers `Value`s, so that one implementation serves every backend. The browser
//! backend links such an interface from its names alone. wasmtime could too (with dynamic
//! `Val`s), but a dynamic `Val` costs a host allocation per list element, and a large
//! `list<u8>` would cost a hundred times what the typed bindings cost. So this macro runs
//! wasmtime's own `bindgen!` on the WIT and implements the generated host traits: each call's
//! typed arguments become `Value`s for the server, its answer becomes the typed result. Bytes
//! move once, as they would through hand-written bindings.
//!
//! ```ignore
//! wasmnet_host::portable_adapter!({
//!     name: PadAdapter,
//!     path: ["wit/pad"],
//!     world: "example:pad/user",
//! });
//! // Host::builder().extension(PadAdapter)
//! ```
//!
//! Supported WIT: `bool`, unsigned integers, `string`, records, variants, enums, options,
//! results, tuples, lists (`list<u8>` as bytes) and resources (own and borrow; constructors,
//! methods and static functions), and type aliases of any of these (`type id = u32` crosses as
//! a `u32`, a list of an alias of `u8` as bytes). Signed integers, floats, `char`, flags,
//! streams, futures and async functions are refused with a compile error: the browser boundary
//! does not carry them yet.

use std::collections::BTreeMap;
use std::path::PathBuf;

use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{Ident, LitStr, Token, braced, bracketed};
use wit_parser::{
    Function, FunctionKind, Handle, InterfaceId, Resolve, Type, TypeDefKind, TypeId, TypeOwner,
    WorldItem,
};

/// `{ name: Ident, path: "dir" | ["dir", ...], world: "ns:pkg/world" }`.
struct Input {
    name: Ident,
    paths: Vec<LitStr>,
    world: LitStr,
}

impl Parse for Input {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let content;
        braced!(content in input);
        let (mut name, mut paths, mut world) = (None, Vec::new(), None);
        while !content.is_empty() {
            let key: Ident = content.parse()?;
            content.parse::<Token![:]>()?;
            match key.to_string().as_str() {
                "name" => name = Some(content.parse::<Ident>()?),
                "world" => world = Some(content.parse::<LitStr>()?),
                "path" => {
                    if content.peek(syn::token::Bracket) {
                        let list;
                        bracketed!(list in content);
                        let items = list.parse_terminated(|p| p.parse::<LitStr>(), Token![,])?;
                        paths.extend(items);
                    } else {
                        paths.push(content.parse::<LitStr>()?);
                    }
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown key `{other}`"),
                    ));
                }
            }
            if !content.is_empty() {
                content.parse::<Token![,]>()?;
            }
        }
        let missing = |what| syn::Error::new(Span::call_site(), format!("missing `{what}`"));
        Ok(Self {
            name: name.ok_or_else(|| missing("name"))?,
            paths: if paths.is_empty() {
                return Err(missing("path"));
            } else {
                paths
            },
            world: world.ok_or_else(|| missing("world"))?,
        })
    }
}

/// Generates a `HostExtension` that links the world's imported interfaces into every store and
/// serves them from the device's portable servers.
#[proc_macro]
pub fn portable_adapter(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as Input);
    match expand(&input) {
        Ok(ts) => ts.into(),
        Err(e) => syn::Error::new(Span::call_site(), e)
            .to_compile_error()
            .into(),
    }
}

type R<T> = Result<T, String>;

/// `to_rust_ident` of wasmtime's bindgen: snake case, keywords escaped.
fn rust_ident(name: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
        "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final",
        "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
    ];
    if KEYWORDS.contains(&name) {
        format!("{name}_")
    } else {
        name.to_snake_case()
    }
}

/// `to_rust_upper_camel_case` of wasmtime's bindgen.
fn rust_camel(name: &str) -> String {
    if name == "host" {
        "Host_".to_owned()
    } else {
        name.to_upper_camel_case()
    }
}

fn ident(s: &str) -> Ident {
    Ident::new(s, Span::call_site())
}

struct Gen<'a> {
    resolve: &'a Resolve,
    /// Resource definitions to their marker types.
    markers: BTreeMap<TypeId, Ident>,
    /// The world's exported interfaces (their bindings live under `exports::`).
    exported: Vec<InterfaceId>,
}

fn expand(input: &Input) -> R<TokenStream> {
    let root = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").map_err(|_| "CARGO_MANIFEST_DIR is not set")?,
    );
    let mut resolve = Resolve::new();
    let mut packages = Vec::new();
    for p in &input.paths {
        let (id, _) = resolve
            .push_path(root.join(p.value()))
            .map_err(|e| format!("{e:#}"))?;
        packages.push(id);
    }
    let world = resolve
        .select_world(&packages, Some(&input.world.value()))
        .map_err(|e| format!("{e:#}"))?;
    let interfaces: Vec<InterfaceId> = resolve.worlds[world]
        .imports
        .values()
        .filter_map(|item| match item {
            WorldItem::Interface { id, .. } => Some(*id),
            _ => None,
        })
        .filter(|id| {
            let i = &resolve.interfaces[*id];
            !i.functions.is_empty()
                || i.types
                    .values()
                    .any(|t| matches!(resolve.types[*t].kind, TypeDefKind::Resource))
        })
        .collect();
    let exported: Vec<InterfaceId> = resolve.worlds[world]
        .exports
        .values()
        .filter_map(|item| match item {
            WorldItem::Interface { id, .. } => Some(*id),
            _ => None,
        })
        .filter(|id| !resolve.interfaces[*id].functions.is_empty())
        .collect();
    if interfaces.is_empty() && exported.is_empty() {
        return Err(format!(
            "world `{}` imports no interface with functions or resources and exports none with functions",
            input.world.value()
        ));
    }
    if let Some(both) = exported.iter().find(|e| interfaces.contains(e)) {
        return Err(format!(
            "`{}` is both imported and exported",
            resolve.id_of(*both).unwrap_or_default()
        ));
    }
    let mut g = Gen {
        resolve: &resolve,
        markers: BTreeMap::new(),
        exported: exported.clone(),
    };
    let mut marker_items = Vec::new();
    let mut with = Vec::new();
    for &iid in &interfaces {
        let i = &resolve.interfaces[iid];
        let iname = i.name.clone().unwrap_or_default();
        let pkg = &resolve.packages[i.package.ok_or("an interface without a package")?].name;
        for (rname, &tid) in &i.types {
            if matches!(resolve.types[tid].kind, TypeDefKind::Resource) {
                let m = format_ident!("{}{}", rust_camel(&iname), rust_camel(rname));
                marker_items.push(quote! {
                    #[doc = "The marker of a portable resource; its handle is the server's."]
                    pub struct #m;
                });
                let key = format!("{}:{}/{}.{}", pkg.namespace, pkg.name, iname, rname);
                with.push(quote! { #key: super::markers::#m });
                g.markers.insert(tid, m);
            }
        }
    }
    let mut impls = Vec::new();
    let mut links = Vec::new();
    let mut decls = Vec::new();
    for &iid in &interfaces {
        let (imp, link, decl) = g.interface(iid)?;
        impls.push(imp);
        links.push(link);
        decls.push(decl);
    }
    let (export_fields, export_finds, (export_selects, export_arms), export_names) = g.exports()?;
    let name = &input.name;
    let module = format_ident!("__{}", name.to_string().to_snake_case());
    let paths: Vec<String> = input.paths.iter().map(LitStr::value).collect();
    let world_name = input.world.value();
    let ext_name = format!("portable {world_name}");
    Ok(quote! {
        #[doc = concat!("A portable extension's typed adapter for wasmtime, generated from the WIT of `", #world_name, "`: give it to `Host::builder().extension`.")]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct #name;

        #[doc(hidden)]
        #[allow(clippy::all, unused_qualifications, unused_mut, unused_variables, non_camel_case_types)]
        mod #module {
            pub mod markers {
                #(#marker_items)*
            }
            mod bindings {
                ::wasmnet_host::wasmtime::component::bindgen!({
                    path: [#(#paths),*],
                    world: #world_name,
                    imports: { default: trappable | store },
                    exports: { default: async | store },
                    with: { #(#with),* },
                    wasmtime_crate: ::wasmnet_host::wasmtime,
                });
            }
            use ::wasmnet_host::sim::value::Value;
            use ::wasmnet_host::wasmtime::component::Resource;
            use ::wasmnet_host::wasmtime::AsContextMut as _;
            type Access<'a> = ::wasmnet_host::wasmtime::component::Access<'a, ::wasmnet_host::HostState, Data>;
            type Trap<T> = ::wasmnet_host::wasmtime::Result<T>;

            pub struct View<'a>(pub &'a mut ::wasmnet_host::HostState);
            pub struct Data;
            impl ::wasmnet_host::wasmtime::component::HasData for Data {
                type Data<'a> = View<'a>;
            }
            #(#impls)*

            pub fn add_to_linker(
                l: &mut ::wasmnet_host::wasmtime::component::Linker<::wasmnet_host::HostState>,
            ) -> Trap<()> {
                #(#links)*
                Ok(())
            }

            pub fn interfaces() -> ::std::vec::Vec<::wasmnet_host::sim::Interface> {
                ::std::vec![#(#decls),*]
            }

            /// The world's exported interfaces a device has: calls of them by name.
            pub struct Exports {
                #(#export_fields,)*
            }

            impl Exports {
                pub fn find(
                    pre: &::wasmnet_host::wasmtime::component::InstancePre<::wasmnet_host::HostState>,
                    store: &mut ::wasmnet_host::wasmtime::Store<::wasmnet_host::HostState>,
                    instance: &::wasmnet_host::wasmtime::component::Instance,
                ) -> Trap<::std::option::Option<(::std::string::String, ::std::boxed::Box<dyn ::wasmnet_host::ControlHandler>)>> {
                    let found = Exports { #(#export_finds,)* };
                    let names: &[(&str, bool)] = &[#(#export_names),*];
                    let _ = (&pre, &store, &instance);
                    Ok(names.iter().find(|(_, has)| *has).map(|(n, _)| {
                        ((*n).to_owned(), ::std::boxed::Box::new(found) as ::std::boxed::Box<dyn ::wasmnet_host::ControlHandler>)
                    }))
                }
            }

            impl ::wasmnet_host::ControlHandler for Exports {
                fn serve<'a>(
                    &'a self,
                    acc: &'a ::wasmnet_host::wasmtime::component::Accessor<::wasmnet_host::HostState>,
                    call: ::std::boxed::Box<dyn ::wasmnet_host::sim::ext::ControlCall>,
                ) -> ::std::result::Result<::wasmnet_host::ControlFuture<'a>, ::std::boxed::Box<dyn ::wasmnet_host::sim::ext::ControlCall>> {
                    // Which function, by name, before the call is taken: one that is not this
                    // adapter's goes back untouched to the next handler.
                    let which: ::std::option::Option<usize> = match call.target() {
                        #(#export_selects)*
                        _ => ::std::option::Option::None,
                    };
                    let ::std::option::Option::Some(which) = which else {
                        return Err(call);
                    };
                    let mut call = call;
                    // The arguments move out of the call into the device's (no copy here).
                    let ::std::option::Option::Some(inv) = call.invocation(::wasmnet_host::portable::now(acc)) else {
                        return Err(call);
                    };
                    let mut args = inv.args.into_iter();
                    match which {
                        #(#export_arms)*
                        _ => Err(call),
                    }
                }
            }
        }

        impl #name {
            /// The interfaces this adapter links, as its WIT declares them: what the extension's
            /// `NetworkExtension::interfaces` must declare too.
            pub fn interfaces() -> ::std::vec::Vec<::wasmnet_host::sim::Interface> {
                #module::interfaces()
            }
        }

        impl ::wasmnet_host::HostExtension for #name {
            fn name(&self) -> &str {
                #ext_name
            }
            fn add_to_linker(
                &self,
                linker: &mut ::wasmnet_host::wasmtime::component::Linker<::wasmnet_host::HostState>,
            ) -> ::wasmnet_host::wasmtime::Result<()> {
                #module::add_to_linker(linker)
            }
            fn init_device(
                &self,
                state: &mut ::wasmnet_host::HostState,
                device: &::wasmnet_host::sim::DeviceContext,
            ) -> ::wasmnet_host::wasmtime::Result<()> {
                ::wasmnet_host::portable::attach(state, device);
                Ok(())
            }
            fn instance_ready(
                &self,
                pre: &::wasmnet_host::wasmtime::component::InstancePre<::wasmnet_host::HostState>,
                store: &mut ::wasmnet_host::wasmtime::Store<::wasmnet_host::HostState>,
                instance: &::wasmnet_host::wasmtime::component::Instance,
            ) -> ::wasmnet_host::wasmtime::Result<::std::option::Option<(::std::string::String, ::std::boxed::Box<dyn ::wasmnet_host::ControlHandler>)>> {
                #module::Exports::find(pre, store, instance)
            }
        }
    })
}

impl Gen<'_> {
    /// The module path of an interface's bindings: `bindings::ns::pkg::iface`.
    fn module(&self, iid: InterfaceId) -> R<TokenStream> {
        let i = &self.resolve.interfaces[iid];
        let pkg = &self.resolve.packages[i.package.ok_or("an interface without a package")?].name;
        let (ns, p, n) = (
            ident(&rust_ident(&pkg.namespace)),
            ident(&rust_ident(&pkg.name)),
            ident(&rust_ident(
                i.name.as_deref().ok_or("an unnamed interface")?,
            )),
        );
        if self.exported.contains(&iid) {
            return Ok(quote!(bindings::exports::#ns::#p::#n));
        }
        Ok(quote!(bindings::#ns::#p::#n))
    }

    /// Follows type aliases to the definition.
    fn def(&self, mut id: TypeId) -> TypeId {
        while let TypeDefKind::Type(Type::Id(next)) = self.resolve.types[id].kind {
            id = next;
        }
        id
    }

    /// Follows type aliases to what they name, a primitive included (`type id = u32` is `u32`):
    /// bindgen gives an alias the Rust type of what it names, and the browser boundary carries
    /// it as that.
    fn peel(&self, ty: &Type) -> Type {
        let mut ty = *ty;
        while let Type::Id(id) = ty {
            match self.resolve.types[id].kind {
                TypeDefKind::Type(next) => ty = next,
                _ => break,
            }
        }
        ty
    }

    /// Whether `ty` is `u8`, through aliases: a list of it crosses as bytes.
    fn is_byte(&self, ty: &Type) -> bool {
        self.peel(ty) == Type::U8
    }

    fn named_path(&self, id: TypeId) -> R<TokenStream> {
        let t = &self.resolve.types[id];
        let TypeOwner::Interface(iid) = t.owner else {
            return Err("a named type outside an interface".into());
        };
        let m = self.module(iid)?;
        let n = ident(&rust_camel(
            t.name.as_deref().ok_or("an anonymous named type")?,
        ));
        Ok(quote!(#m::#n))
    }

    fn marker(&self, resource: TypeId) -> R<(&Ident, String)> {
        let def = self.def(resource);
        let m = self
            .markers
            .get(&def)
            .ok_or("a resource of an interface this adapter does not serve")?;
        Ok((m, self.resolve.types[def].name.clone().unwrap_or_default()))
    }

    fn unsupported(&self, what: &str) -> String {
        format!(
            "{what} cannot cross a portable interface yet (the browser boundary does not carry it)"
        )
    }

    /// The Rust type bindgen gives `ty`.
    fn rust_type(&self, ty: &Type) -> R<TokenStream> {
        Ok(match &self.peel(ty) {
            Type::Bool => quote!(bool),
            Type::U8 => quote!(u8),
            Type::U16 => quote!(u16),
            Type::U32 => quote!(u32),
            Type::U64 => quote!(u64),
            Type::String => quote!(::std::string::String),
            Type::S8 | Type::S16 | Type::S32 | Type::S64 => {
                return Err(self.unsupported("a signed integer"));
            }
            Type::F32 | Type::F64 => return Err(self.unsupported("a float")),
            Type::Char => return Err(self.unsupported("a char")),
            Type::ErrorContext => return Err(self.unsupported("an error context")),
            Type::Id(id) => {
                let id = self.def(*id);
                match &self.resolve.types[id].kind {
                    TypeDefKind::Record(_) | TypeDefKind::Variant(_) | TypeDefKind::Enum(_) => {
                        self.named_path(id)?
                    }
                    TypeDefKind::Option(t) => {
                        let t = self.rust_type(t)?;
                        quote!(::std::option::Option<#t>)
                    }
                    TypeDefKind::Result(r) => {
                        let ok = self.opt_type(r.ok.as_ref())?;
                        let err = self.opt_type(r.err.as_ref())?;
                        quote!(::std::result::Result<#ok, #err>)
                    }
                    TypeDefKind::Tuple(t) => {
                        let ts = t
                            .types
                            .iter()
                            .map(|t| self.rust_type(t))
                            .collect::<R<Vec<_>>>()?;
                        quote!((#(#ts,)*))
                    }
                    TypeDefKind::List(t) => {
                        let t = self.rust_type(t)?;
                        quote!(::std::vec::Vec<#t>)
                    }
                    TypeDefKind::Handle(Handle::Own(r) | Handle::Borrow(r)) => {
                        let (m, _) = self.marker(*r)?;
                        quote!(Resource<markers::#m>)
                    }
                    other => return Err(self.unsupported(&format!("{other:?}"))),
                }
            }
        })
    }

    fn opt_type(&self, ty: Option<&Type>) -> R<TokenStream> {
        match ty {
            Some(t) => self.rust_type(t),
            None => Ok(quote!(())),
        }
    }

    /// An expression turning `e` (of `ty`'s Rust type) into a `Value`.
    fn to_value(&self, e: TokenStream, ty: &Type) -> R<TokenStream> {
        Ok(match &self.peel(ty) {
            Type::Bool => quote!(Value::Bool(#e)),
            Type::U8 | Type::U16 => quote!(Value::U32(u32::from(#e))),
            Type::U32 => quote!(Value::U32(#e)),
            Type::U64 => quote!(Value::U64(#e)),
            Type::String => quote!(Value::Str(#e)),
            Type::Id(id) => {
                let id = self.def(*id);
                match &self.resolve.types[id].kind {
                    TypeDefKind::Record(r) => {
                        let path = self.named_path(id)?;
                        let mut fields = Vec::new();
                        let mut names = Vec::new();
                        for f in &r.fields {
                            let fi = ident(&rust_ident(&f.name));
                            let v = self.to_value(quote!(#fi), &f.ty)?;
                            let wit = &f.name;
                            names.push(fi);
                            fields.push(quote!((::std::string::String::from(#wit), #v)));
                        }
                        quote!({ let #path { #(#names),* } = #e; Value::Record(::std::vec![#(#fields),*]) })
                    }
                    TypeDefKind::Variant(v) => {
                        let path = self.named_path(id)?;
                        let mut arms = Vec::new();
                        for c in &v.cases {
                            let ci = ident(&rust_camel(&c.name));
                            let wit = &c.name;
                            arms.push(match &c.ty {
                                Some(t) => {
                                    let inner = self.to_value(quote!(x), t)?;
                                    quote!(#path::#ci(x) => Value::Variant(::std::string::String::from(#wit), Some(::std::boxed::Box::new(#inner))))
                                }
                                None => quote!(#path::#ci => Value::Variant(::std::string::String::from(#wit), None)),
                            });
                        }
                        quote!(match #e { #(#arms),* })
                    }
                    TypeDefKind::Enum(en) => {
                        let path = self.named_path(id)?;
                        let arms = en.cases.iter().map(|c| {
                            let ci = ident(&rust_camel(&c.name));
                            let wit = &c.name;
                            quote!(#path::#ci => Value::Enum(::std::string::String::from(#wit)))
                        });
                        quote!(match #e { #(#arms),* })
                    }
                    TypeDefKind::Option(t) => {
                        let inner = self.to_value(quote!(x), t)?;
                        quote!(match #e { Some(x) => Value::Some(::std::boxed::Box::new(#inner)), None => Value::None })
                    }
                    TypeDefKind::Result(r) => {
                        let arm = |tag: &str, t: Option<&Type>| -> R<TokenStream> {
                            Ok(match t {
                                Some(t) => {
                                    let inner = self.to_value(quote!(x), t)?;
                                    quote!(Value::Variant(::std::string::String::from(#tag), Some(::std::boxed::Box::new(#inner))))
                                }
                                None => {
                                    quote!({ let _ = x; Value::Variant(::std::string::String::from(#tag), None) })
                                }
                            })
                        };
                        let ok = arm("ok", r.ok.as_ref())?;
                        let err = arm("err", r.err.as_ref())?;
                        quote!(match #e { Ok(x) => #ok, Err(x) => #err })
                    }
                    TypeDefKind::Tuple(t) => {
                        let names: Vec<Ident> = (0..t.types.len())
                            .map(|i| format_ident!("t{}", i))
                            .collect();
                        let vals = names
                            .iter()
                            .zip(&t.types)
                            .map(|(n, t)| self.to_value(quote!(#n), t))
                            .collect::<R<Vec<_>>>()?;
                        quote!({ let (#(#names,)*) = #e; Value::Tuple(::std::vec![#(#vals),*]) })
                    }
                    TypeDefKind::List(t) if self.is_byte(t) => quote!(Value::Bytes(#e)),
                    TypeDefKind::List(t) => {
                        let inner = self.to_value(quote!(x), t)?;
                        quote!(Value::List((#e).into_iter().map(|x| #inner).collect()))
                    }
                    TypeDefKind::Handle(Handle::Own(r) | Handle::Borrow(r)) => {
                        let (_, name) = self.marker(*r)?;
                        quote!(Value::Resource(::std::string::String::from(#name), (#e).rep()))
                    }
                    other => return Err(self.unsupported(&format!("{other:?}"))),
                }
            }
            other => return Err(self.unsupported(&format!("{other:?}"))),
        })
    }

    /// An expression turning `v` (a `Value`) into `Result<T, String>`, `T` being `ty`'s Rust type.
    fn value_to(&self, v: TokenStream, ty: &Type) -> R<TokenStream> {
        let want = |what: &str| {
            let what = what.to_owned();
            quote!(other => Err(::std::format!("want {}, got {:?}", #what, other)))
        };
        let ty = &self.peel(ty);
        Ok(match ty {
            Type::Bool => {
                let w = want("a bool");
                quote!(match #v { Value::Bool(b) => Ok(b), #w })
            }
            Type::U8 | Type::U16 => {
                let t = self.rust_type(ty)?;
                let w = want("a small unsigned integer");
                quote!(match #v { Value::U32(n) => <#t>::try_from(n).map_err(|e| e.to_string()), #w })
            }
            Type::U32 => {
                let w = want("a u32");
                quote!(match #v { Value::U32(n) => Ok(n), #w })
            }
            Type::U64 => {
                let w = want("a u64");
                quote!(match #v { Value::U64(n) => Ok(n), Value::U32(n) => Ok(u64::from(n)), #w })
            }
            Type::String => {
                let w = want("a string");
                quote!(match #v { Value::Str(s) => Ok(s), #w })
            }
            Type::Id(id) => {
                let id = self.def(*id);
                match &self.resolve.types[id].kind {
                    TypeDefKind::Record(r) => {
                        let path = self.named_path(id)?;
                        let mut fields = Vec::new();
                        for f in &r.fields {
                            let fi = ident(&rust_ident(&f.name));
                            let wit = &f.name;
                            let inner = self
                                .value_to(quote!(m.remove(#wit).unwrap_or(Value::None)), &f.ty)?;
                            fields.push(quote!(#fi: (#inner).map_err(|e| ::std::format!("{}: {}", #wit, e))?));
                        }
                        let w = want("a record");
                        quote!(match #v {
                            Value::Record(fields) => (|| -> ::std::result::Result<_, ::std::string::String> {
                                let mut m: ::std::collections::BTreeMap<::std::string::String, Value> = fields.into_iter().collect();
                                Ok(#path { #(#fields),* })
                            })(),
                            #w
                        })
                    }
                    TypeDefKind::Variant(var) => {
                        let path = self.named_path(id)?;
                        let mut arms = Vec::new();
                        for c in &var.cases {
                            let ci = ident(&rust_camel(&c.name));
                            let wit = &c.name;
                            arms.push(match &c.ty {
                                Some(t) => {
                                    let inner = self.value_to(
                                        quote!(*p.ok_or_else(
                                            || ::std::format!("{} without its payload", #wit)
                                        )?),
                                        t,
                                    )?;
                                    quote!(#wit => Ok(#path::#ci((#inner)?)))
                                }
                                None => quote!(#wit => Ok(#path::#ci)),
                            });
                        }
                        let w = want("a variant");
                        quote!(match #v {
                            Value::Variant(tag, p) => (|| -> ::std::result::Result<_, ::std::string::String> {
                                match tag.as_str() { #(#arms,)* other => Err(::std::format!("no case `{}`", other)) }
                            })(),
                            #w
                        })
                    }
                    TypeDefKind::Enum(en) => {
                        let path = self.named_path(id)?;
                        let arms = en.cases.iter().map(|c| {
                            let ci = ident(&rust_camel(&c.name));
                            let wit = &c.name;
                            quote!(#wit => Ok(#path::#ci))
                        });
                        let w = want("an enum case");
                        quote!(match #v {
                            Value::Enum(s) => match s.as_str() { #(#arms,)* other => Err(::std::format!("no case `{}`", other)) },
                            #w
                        })
                    }
                    TypeDefKind::Option(t) => {
                        let inner = self.value_to(quote!(x), t)?;
                        quote!(match (#v).into_option() { None => Ok(None), Some(x) => (#inner).map(Some) })
                    }
                    TypeDefKind::Result(r) => {
                        let arm = |t: Option<&Type>| -> R<TokenStream> {
                            Ok(match t {
                                Some(t) => {
                                    let inner = self.value_to(
                                        quote!(*p.ok_or("a result without its payload")?),
                                        t,
                                    )?;
                                    quote!((#inner)?)
                                }
                                None => quote!(()),
                            })
                        };
                        let ok = arm(r.ok.as_ref())?;
                        let err = arm(r.err.as_ref())?;
                        let w = want("a result");
                        quote!(match #v {
                            Value::Variant(tag, p) => (|| -> ::std::result::Result<_, ::std::string::String> {
                                match tag.as_str() {
                                    "ok" => Ok(Ok(#ok)),
                                    "err" => Ok(Err(#err)),
                                    other => Err(::std::format!("no result case `{}`", other)),
                                }
                            })(),
                            #w
                        })
                    }
                    TypeDefKind::Tuple(t) => {
                        let n = t.types.len();
                        let vals = t
                            .types
                            .iter()
                            .map(|t| {
                                let inner =
                                    self.value_to(quote!(it.next().ok_or("a short tuple")?), t)?;
                                Ok(quote!((#inner)?))
                            })
                            .collect::<R<Vec<_>>>()?;
                        let w = want("a tuple");
                        quote!(match #v {
                            Value::Tuple(items) | Value::List(items) if items.len() == #n => (|| -> ::std::result::Result<_, ::std::string::String> {
                                let mut it = items.into_iter();
                                Ok((#(#vals,)*))
                            })(),
                            #w
                        })
                    }
                    TypeDefKind::List(t) if self.is_byte(t) => {
                        let w = want("bytes");
                        quote!(match #v { Value::Bytes(b) => Ok(b), #w })
                    }
                    TypeDefKind::List(t) => {
                        let inner = self.value_to(quote!(x), t)?;
                        let w = want("a list");
                        quote!(match #v {
                            Value::List(items) => items.into_iter().map(|x| #inner).collect::<::std::result::Result<::std::vec::Vec<_>, ::std::string::String>>(),
                            #w
                        })
                    }
                    TypeDefKind::Handle(Handle::Own(r)) => {
                        let (m, _) = self.marker(*r)?;
                        let w = want("a resource");
                        quote!(match #v { Value::Resource(_, h) => Ok(Resource::<markers::#m>::new_own(h)), #w })
                    }
                    other => return Err(self.unsupported(&format!("{other:?} in a result"))),
                }
            }
            other => return Err(self.unsupported(&format!("{other:?}"))),
        })
    }

    /// The exported interfaces' handler parts: its fields, how each is found in an instance,
    /// the match arms that pick a function by a call's target (to its number) and those that
    /// call it (by its number), and the interfaces' names (without a version) with whether the
    /// instance has them.
    #[allow(clippy::type_complexity)]
    fn exports(
        &self,
    ) -> R<(
        Vec<TokenStream>,
        Vec<TokenStream>,
        (Vec<TokenStream>, Vec<TokenStream>),
        Vec<TokenStream>,
    )> {
        let (mut fields, mut finds, mut selects, mut arms, mut names) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for &iid in &self.exported {
            let i = &self.resolve.interfaces[iid];
            let full = self.resolve.id_of(iid).ok_or("an unnamed interface")?;
            let iname = full
                .split_once('@')
                .map_or(full.as_str(), |(n, _)| n)
                .to_owned();
            let m = self.module(iid)?;
            let f = format_ident!("e_{}", rust_ident(i.name.as_deref().unwrap_or_default()));
            fields.push(quote!(#f: ::std::option::Option<#m::Guest>));
            finds.push(quote! {
                #f: match #m::GuestIndices::new(pre) {
                    Ok(ix) => Some(ix.load(&mut *store, instance)?),
                    Err(_) => None,
                }
            });
            names.push(quote!((#iname, found.#f.is_some())));
            for func in i.functions.values() {
                if !matches!(func.kind, FunctionKind::Freestanding) {
                    return Err(format!(
                        "`{}` in exported `{iname}`: only freestanding functions of an exported interface are portable yet",
                        func.name
                    ));
                }
                let wit = &func.name;
                let call = format_ident!("call_{}", rust_ident(&func.name));
                let mut convs = Vec::new();
                let mut checks = Vec::new();
                let mut names_a = Vec::new();
                for (n, p) in func.params.iter().enumerate() {
                    let a = format_ident!("a{}", n);
                    let conv = self.value_to(quote!(v), &p.ty)?;
                    convs.push(quote! {
                        let #a = match args.next() {
                            Some(v) => #conv,
                            None => Err(::std::string::String::from("a missing argument")),
                        };
                    });
                    checks.push(quote! {
                        let #a = #a.map_err(|e| ::wasmnet_host::wasmtime::format_err!("{}#{}: {}", #iname, #wit, e))?;
                    });
                    names_a.push(a);
                }
                let decode = match &func.result {
                    None => quote!({
                        let () = r;
                        Ok(Value::None)
                    }),
                    Some(Type::Id(id))
                        if matches!(
                            self.resolve.types[self.def(*id)].kind,
                            TypeDefKind::Result(_)
                        ) =>
                    {
                        let TypeDefKind::Result(res) = &self.resolve.types[self.def(*id)].kind
                        else {
                            unreachable!()
                        };
                        let side = |t: Option<&Type>| -> R<TokenStream> {
                            Ok(match t {
                                Some(t) => self.to_value(quote!(x), t)?,
                                None => quote!({
                                    let _ = x;
                                    Value::None
                                }),
                            })
                        };
                        let ok = side(res.ok.as_ref())?;
                        let err = side(res.err.as_ref())?;
                        quote!(match r { Ok(x) => Ok(#ok), Err(x) => Err(#err) })
                    }
                    Some(t) => {
                        let v = self.to_value(quote!(r), t)?;
                        quote!(Ok(#v))
                    }
                };
                let k = arms.len();
                selects.push(quote! {
                    ::std::option::Option::Some((#iname, #wit)) if self.#f.is_some() => ::std::option::Option::Some(#k),
                });
                arms.push(quote! {
                    #k => {
                        let g = self.#f.as_ref().expect("checked by its target");
                        #(#convs)*
                        Ok(::std::boxed::Box::pin(async move {
                            #(#checks)*
                            let r = g.#call(acc, #(#names_a),*).await?;
                            let answer: ::std::result::Result<Value, Value> = #decode;
                            ::wasmnet_host::portable::invoked(acc, call, answer);
                            Ok(())
                        }))
                    }
                });
            }
        }
        Ok((fields, finds, (selects, arms), names))
    }
    /// One function's trait method.
    fn method(&self, iface: &str, f: &Function) -> R<TokenStream> {
        let name = match f.kind {
            FunctionKind::Constructor(_) => ident("new"),
            FunctionKind::Freestanding | FunctionKind::Method(_) | FunctionKind::Static(_) => {
                ident(&rust_ident(f.item_name()))
            }
            _ => {
                return Err(format!(
                    "`{}`: async functions, getters and setters are not portable yet",
                    f.name
                ));
            }
        };
        let mut params = Vec::new();
        let mut args = Vec::new();
        for (n, p) in f.params.iter().enumerate() {
            let pi = format_ident!("a{}", n);
            let t = self.rust_type(&p.ty)?;
            params.push(quote!(#pi: #t));
            args.push(self.to_value(quote!(#pi), &p.ty)?);
        }
        let ret = self.opt_type(f.result.as_ref())?;
        let wit = &f.name;
        let bad = quote!(|e: ::std::string::String| ::wasmnet_host::portable::bad_answer(#iface, #wit, &e));
        let decode = match &f.result {
            None => quote!(match served {
                ::wasmnet_host::sim::Served::Ok(_) => Ok(()),
                other => Err(::wasmnet_host::portable::bad_answer(#iface, #wit, &::std::format!("{:?}", other))),
            }),
            Some(Type::Id(id))
                if matches!(
                    self.resolve.types[self.def(*id)].kind,
                    TypeDefKind::Result(_)
                ) =>
            {
                let TypeDefKind::Result(r) = &self.resolve.types[self.def(*id)].kind else {
                    unreachable!()
                };
                let side = |t: Option<&Type>| -> R<TokenStream> {
                    Ok(match t {
                        Some(t) => {
                            let inner = self.value_to(quote!(v), t)?;
                            quote!((#inner).map_err(#bad)?)
                        }
                        None => quote!({
                            let _ = v;
                        }),
                    })
                };
                let ok = side(r.ok.as_ref())?;
                let err = side(r.err.as_ref())?;
                quote!(match served {
                    ::wasmnet_host::sim::Served::Ok(v) => Ok(Ok(#ok)),
                    ::wasmnet_host::sim::Served::Err(v) => Ok(Err(#err)),
                    other => Err(::wasmnet_host::portable::bad_answer(#iface, #wit, &::std::format!("{:?}", other))),
                })
            }
            Some(t) => {
                let inner = self.value_to(quote!(v), t)?;
                quote!(match served {
                    ::wasmnet_host::sim::Served::Ok(v) => Ok((#inner).map_err(#bad)?),
                    other => Err(::wasmnet_host::portable::bad_answer(#iface, #wit, &::std::format!("{:?}", other))),
                })
            }
        };
        Ok(quote! {
            fn #name(mut host: Access<'_>, #(#params),*) -> Trap<#ret> {
                let args = ::std::vec![#(#args),*];
                // With the store: a fuel span the server begins or ends applies in the call.
                let served = ::wasmnet_host::portable::call(host.as_context_mut(), #iface, #wit, args)?;
                #decode
            }
        })
    }

    /// One interface: its trait impls, its linking, its declaration.
    fn interface(&self, iid: InterfaceId) -> R<(TokenStream, TokenStream, TokenStream)> {
        let i = &self.resolve.interfaces[iid];
        let iface = self.resolve.id_of(iid).ok_or("an unnamed interface")?;
        let module = self.module(iid)?;
        let mut free = Vec::new();
        let mut by_resource: BTreeMap<TypeId, Vec<TokenStream>> = BTreeMap::new();
        let mut functions = Vec::new();
        for f in i.functions.values() {
            functions.push(f.name.clone());
            let m = self.method(&iface, f)?;
            match f.kind {
                FunctionKind::Method(r)
                | FunctionKind::Static(r)
                | FunctionKind::Constructor(r) => {
                    by_resource.entry(self.def(r)).or_default().push(m);
                }
                _ => free.push(m),
            }
        }
        let mut resources = Vec::new();
        let mut resource_impls = Vec::new();
        for (rname, &tid) in &i.types {
            if !matches!(self.resolve.types[tid].kind, TypeDefKind::Resource) {
                continue;
            }
            resources.push(rname.clone());
            let (m, _) = self.marker(tid)?;
            let host = format_ident!("Host{}", rust_camel(rname));
            let with_store = format_ident!("Host{}WithStore", rust_camel(rname));
            let methods = by_resource.remove(&tid).unwrap_or_default();
            resource_impls.push(quote! {
                impl #module::#host for View<'_> {}
                impl #module::#with_store<::wasmnet_host::HostState> for Data {
                    #(#methods)*
                    fn drop(mut host: Access<'_>, r: Resource<markers::#m>) -> Trap<()> {
                        ::wasmnet_host::portable::drop_resource(host.data_mut(), #iface, #rname, r.rep());
                        Ok(())
                    }
                }
            });
        }
        // Every function takes the store (`Access`), so it lives in the `*WithStore` traits,
        // implemented for `Data`; bindgen gives an empty one a blanket impl of its own.
        let free_impl = if free.is_empty() {
            quote!()
        } else {
            quote! {
                impl #module::HostWithStore<::wasmnet_host::HostState> for Data {
                    #(#free)*
                }
            }
        };
        let imp = quote! {
            impl #module::Host for View<'_> {}
            #free_impl
            #(#resource_impls)*
        };
        let link = quote! {
            #module::add_to_linker::<::wasmnet_host::HostState, Data>(l, |s| View(s))?;
        };
        let decl = quote! {
            ::wasmnet_host::sim::Interface::new(#iface)
                #(.function(#functions))*
                #(.resource(#resources))*
        };
        Ok((imp, link, decl))
    }
}
