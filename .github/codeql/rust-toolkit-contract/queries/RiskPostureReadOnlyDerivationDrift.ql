/**
 * @name Tool risk posture no longer derives read-only state
 * @description ToolCapability::with_risk_posture must derive read-only state from the guarded-action posture so inventory metadata cannot drift from execution risk.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id rust/mcp-toolkit-risk-posture-read-only-drift
 * @tags correctness
 *       maintainability
 *       product-invariants
 */

import rust
import ToolkitContract

from Function function
where
  toolkitToolInventoryFile(function.getFile()) and
  function.getName().getText() = "with_risk_posture" and
  not functionCallsNamed(function, "is_read_only")
select function,
  "ToolCapability::with_risk_posture no longer derives read_only from GuardedActionPosture::is_read_only. Keep inventory safety metadata bound to the guarded-action posture."
