/**
 * @name Operator profile gate bypasses the shared feature-flag constant
 * @description ToolCapability::with_operator_profile_gate must route through with_feature_flag and the shared OPERATOR_TOOLS_FEATURE_FLAG constant.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id rust/mcp-toolkit-operator-profile-gate-drift
 * @tags correctness
 *       maintainability
 *       product-invariants
 */

import rust
import ToolkitContract

from Function function
where
  toolkitToolInventoryFile(function.getFile()) and
  function.getName().getText() = "with_operator_profile_gate" and
  (
    not functionCallsNamed(function, "with_feature_flag") or
    not functionReferencesPath(function, "OPERATOR_TOOLS_FEATURE_FLAG")
  )
select function,
  "ToolCapability::with_operator_profile_gate must use with_feature_flag(OPERATOR_TOOLS_FEATURE_FLAG). Keep operator exposure policy on the shared source of truth."
