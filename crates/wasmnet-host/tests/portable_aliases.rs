//! `portable_adapter!` on type aliases (`tests/fixtures/aliases`): an alias crosses a portable
//! interface as what it names, in both directions, whether it names a primitive, another alias,
//! a string, bytes, an option, a tuple, a record or a result, and wherever it is used (an
//! argument, a result, a record field, a list element, a variant's payload). That the adapter
//! compiles is most of the test: bindgen's traits pin every generated type. The pad's own WIT
//! (`wit/test-pad`) carries aliases of primitives through the tests that run it.

wasmnet_host::portable_adapter!({
    name: Aliases,
    path: "tests/fixtures/aliases",
    world: "wasmnet-test:aliases/aliases",
});

#[test]
fn an_adapter_over_aliases_declares_its_imports() {
    let declared = Aliases::interfaces();
    assert_eq!(declared.len(), 1, "{declared:?}");
    assert_eq!(declared[0].name, "wasmnet-test:aliases/calls@0.1.0");
    assert_eq!(
        declared[0].functions,
        [
            "put", "get", "pairs", "echo", "next", "name", "bytes", "settle"
        ]
    );
    assert!(declared[0].resources.is_empty());
}
