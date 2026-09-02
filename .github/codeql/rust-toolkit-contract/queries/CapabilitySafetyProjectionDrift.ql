/**
 * @name MCP capability safety projection drops a safety dimension
 * @description CapabilitySafety::to_mcp_annotations must project read-only, destructive, idempotent, and open-world hints so MCP metadata remains aligned with the canonical capability contract.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id rust/mcp-toolkit-capability-safety-projection-drift
 * @tags correctness
 *       maintainability
 *       product-invariants
 */

import rust
import ToolkitContract

predicate requiredSafetyProjectionCall(string targetName) {
  targetName = "read_only" or
  targetName = "destructive" or
  targetName = "idempotent" or
  targetName = "open_world"
}

from Function function, string missingProjection
where
  toolkitCapabilityFile(function.getFile()) and
  function.getName().getText() = "to_mcp_annotations" and
  requiredSafetyProjectionCall(missingProjection) and
  not functionCallsNamed(function, missingProjection)
select function,
  "CapabilitySafety::to_mcp_annotations does not project the '" + missingProjection +
    "' safety dimension. Keep MCP annotations aligned with the canonical capability safety contract."
