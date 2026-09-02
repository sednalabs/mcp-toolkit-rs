fn with_operator_profile_gate() {
    with_feature_flag("operator_tools");
}

fn with_feature_flag(_: &str) {}
