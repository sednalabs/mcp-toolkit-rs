/**
 * @name Process signalling or probing bypasses PID validation
 * @description Public process signal and liveness primitives must retain their fail-closed PID validation before reaching Unix syscalls.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id rust/mcp-toolkit-process-pid-validation-drift
 * @tags correctness
 *       security
 *       product-invariants
 *       external/cwe/cwe-20
 */

import rust
import ToolkitContract

predicate guardedProcessFunction(Function function, string validator) {
  toolkitProcessFile(function.getFile()) and
  (
    (function.getName().getText() = "signal_process" or
      function.getName().getText() = "signal_process_group") and
    validator = "validate_mutating_pid"
    or
    function.getName().getText() = "process_exists" and
    validator = "validate_probe_pid"
  )
}

from Function function, string validator
where
  guardedProcessFunction(function, validator) and
  not functionCallsNamed(function, validator)
select function,
  "This process primitive bypasses " + validator +
    ". Keep special and unrepresentable PID rejection ahead of process syscalls."
