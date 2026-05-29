//! # MCP Toolkit Docs
//!
//! Domain logic for documentation-oriented MCP servers (Corpus management, Chunking).
//!
//! ## Ownership
//! This module owns the standard algorithms for text chunking and corpus metadata
//! management.
//!
//! ## Non-ownership
//! This module does not manage I/O or persistent storage; it performs pure
//! text-transformation tasks.
//!
//! ## Policy & Guarantees
//! * **Deterministic Chunking**: Provides stable splitting algorithms to ensure
//!   consistent RAG performance.
//!
//! ## Caller Responsibility
//! Callers are responsible for:
//! * Enforcing resource constraints (e.g., input size limits).
//! * Sanitizing input text if it contains sensitive data before chunking.
//!
//! ## References
//! * `docs/design/rag-chunking-strategy.md`

use serde::{Deserialize, Serialize};

/// Metadata for a corpus document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMeta {
    /// Stable identifier for the document (e.g., relative path).
    pub id: String,
    /// Relative or absolute path to the source file.
    pub path: String,
    /// Optional title derived from the source.
    pub title: Option<String>,
    /// Optional source label (e.g., top-level corpus directory).
    pub source: Option<String>,
}

/// Chunking configuration for documents.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChunkConfig {
    /// Maximum number of characters per chunk.
    pub max_chars: usize,
    /// Number of overlapping characters between chunks.
    pub overlap: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            max_chars: 2000,
            overlap: 200,
        }
    }
}

/// A chunk of text derived from a larger document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Zero-based chunk index within the source document.
    pub index: usize,
    /// Character offset where the chunk starts.
    pub start: usize,
    /// Character offset where the chunk ends.
    pub end: usize,
    /// The chunk text.
    pub text: String,
}

/// Splits text into overlapping chunks based on the provided configuration.
///
/// Preserves character offsets relative to the input string.
pub fn chunk_text(text: &str, config: ChunkConfig) -> Vec<Chunk> {
    let max_chars = config.max_chars.max(1);
    let overlap = config.overlap.min(max_chars - 1);
    let mut chunks = Vec::new();

    let mut start = 0usize;
    let mut index = 0usize;
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    while start < len {
        let end = (start + max_chars).min(len);
        let slice: String = chars[start..end].iter().collect();
        if !slice.trim().is_empty() {
            chunks.push(Chunk {
                index,
                start,
                end,
                text: slice,
            });
            index += 1;
        }
        if end == len {
            break;
        }
        start = end.saturating_sub(overlap);
    }

    chunks
}
