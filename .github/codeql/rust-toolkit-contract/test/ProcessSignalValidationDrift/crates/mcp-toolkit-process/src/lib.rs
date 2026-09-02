fn signal_process() {
    signal_raw();
}

fn signal_process_group() {
    validate_mutating_pid();
    signal_raw();
}

fn process_exists() {
    validate_probe_pid();
}

fn signal_raw() {}
fn validate_mutating_pid() {}
fn validate_probe_pid() {}
