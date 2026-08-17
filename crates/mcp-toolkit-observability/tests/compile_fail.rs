#[test]
fn terminal_diagnostic_record_cannot_be_emitted_twice() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/terminal_diagnostic_emit_twice.rs");
}
