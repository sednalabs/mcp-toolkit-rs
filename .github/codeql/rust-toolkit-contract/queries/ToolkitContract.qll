import rust

/**
 * Shared helpers for high-confidence mcp-toolkit Rust contract queries.
 */

predicate nodeInsideFunction(AstNode node, Function function) {
  node.getFile() = function.getFile() and
  function.getLocation().getStartLine() <= node.getLocation().getStartLine() and
  node.getLocation().getEndLine() <= function.getLocation().getEndLine()
}

predicate functionCallsNamed(Function function, string targetName) {
  exists(Call call |
    call.getEnclosingCallable() = function and
    call.getTargetName() = targetName
  )
}

predicate functionReferencesPath(Function function, string pathText) {
  exists(PathExpr path |
    nodeInsideFunction(path, function) and
    path.getPath().getText() = pathText
  )
}

predicate toolkitToolInventoryFile(File file) {
  file.getRelativePath() = "crates/mcp-toolkit-core/src/tool_inventory.rs"
}

predicate toolkitCapabilityFile(File file) {
  file.getRelativePath() = "crates/mcp-toolkit-core/src/capability.rs"
}

predicate toolkitProcessFile(File file) {
  file.getRelativePath() = "crates/mcp-toolkit-process/src/lib.rs"
}
