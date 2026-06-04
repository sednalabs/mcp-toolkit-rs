//! Stdio MCP smoke-test helpers.
//!
//! These helpers exercise the real JSON-RPC process boundary. They are meant
//! for integration tests that need to prove a binary initializes and exposes
//! the intended `tools/list` surface.

use serde_json::{json, Value};
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Running stdio MCP process with a JSON-RPC line protocol harness.
pub struct StdioMcpProcess {
    child: Child,
    stdin: ChildStdin,
    responses: mpsc::Receiver<Value>,
}

impl StdioMcpProcess {
    /// Spawn a binary, perform an MCP initialize handshake, and send
    /// `notifications/initialized`.
    ///
    /// # Panics
    /// Panics if the process cannot spawn, the initialize response times out,
    /// or the server returns a different protocol version.
    pub fn start(exe: impl AsRef<OsStr>) -> Self {
        Self::start_with_client(exe, "mcp-toolkit-stdio-contract", DEFAULT_PROTOCOL_VERSION)
    }

    /// Spawn a binary with explicit client metadata.
    ///
    /// # Panics
    /// Panics if the process cannot spawn, the initialize response times out,
    /// or the server returns a different protocol version.
    pub fn start_with_client(
        exe: impl AsRef<OsStr>,
        client_name: &str,
        protocol_version: &str,
    ) -> Self {
        let mut command = Command::new(exe);
        command
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn MCP stdio server");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let stderr = child.stderr.take().expect("child stderr");
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    let _ = tx.send(value);
                }
            }
        });
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("MCP stdio server stderr: {line}");
            }
        });

        let mut process = Self {
            child,
            stdin,
            responses: rx,
        };
        process.send(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "0.0.0"}
            }
        }));
        let init = process.response(1);
        assert_eq!(init["result"]["protocolVersion"], json!(protocol_version));
        process.send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
        process
    }

    /// Send one JSON-RPC message as a single stdout-delimited JSON line.
    ///
    /// # Panics
    /// Panics if serialization or process stdin writes fail.
    pub fn send(&mut self, value: Value) {
        let line = serde_json::to_string(&value).expect("serialize JSON-RPC request");
        writeln!(self.stdin, "{line}").expect("write JSON-RPC request");
        self.stdin.flush().expect("flush JSON-RPC request");
    }

    /// Wait for a response with the matching JSON-RPC id.
    ///
    /// # Panics
    /// Panics if the response does not arrive before the default timeout.
    pub fn response(&self, id: u64) -> Value {
        self.response_with_timeout(id, DEFAULT_TIMEOUT)
    }

    /// Wait for a response with the matching JSON-RPC id and explicit timeout.
    ///
    /// The timeout is an absolute deadline, not a per-message timeout. Noisy
    /// servers can emit notifications or unrelated responses without extending
    /// the wait forever.
    ///
    /// # Panics
    /// Panics if the response does not arrive before `timeout`.
    pub fn response_with_timeout(&self, id: u64, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| {
                    panic!("timed out waiting for JSON-RPC response id {id}");
                });
            let value = self
                .responses
                .recv_timeout(remaining)
                .unwrap_or_else(|_| panic!("timed out waiting for JSON-RPC response id {id}"));
            if value.get("id") == Some(&json!(id)) {
                return value;
            }
        }
    }

    /// Call `tools/list` and return exported tool names in server order.
    ///
    /// # Panics
    /// Panics if the server does not return a JSON array at `result.tools`.
    pub fn list_tool_names(&mut self) -> Vec<String> {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }));
        let response = self.response(2);
        response["result"]["tools"]
            .as_array()
            .expect("tools/list array")
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(ToString::to_string))
            .collect()
    }
}

impl Drop for StdioMcpProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Assert that a stdio MCP binary initializes and returns the expected
/// `tools/list` names.
///
/// # Panics
/// Panics if the process cannot initialize, `tools/list` fails, or the exported
/// names differ from `expected_names`.
pub fn assert_stdio_tools_list(exe: impl AsRef<OsStr>, expected_names: &[&str]) {
    let mut process = StdioMcpProcess::start(exe);
    let names = process.list_tool_names();
    let expected = expected_names
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    assert_eq!(names, expected);
}

#[cfg(test)]
mod tests {
    use super::StdioMcpProcess;
    use serde_json::json;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn response_ignores_unrelated_ids_until_match() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(json!({"jsonrpc":"2.0","id":99,"result":{}}))
            .expect("send unrelated");
        tx.send(json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}}))
            .expect("send target");

        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sleeper");
        let stdin = child.stdin.take().expect("stdin");
        let process = StdioMcpProcess {
            child,
            stdin,
            responses: rx,
        };

        let response = process.response(7);
        assert_eq!(response["result"], json!({"ok": true}));
    }

    #[test]
    fn response_timeout_is_absolute_across_unrelated_messages() {
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || loop {
            if tx
                .send(json!({"jsonrpc":"2.0","id":99,"result":{}}))
                .is_err()
            {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        });

        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sleeper");
        let stdin = child.stdin.take().expect("stdin");
        let process = StdioMcpProcess {
            child,
            stdin,
            responses: rx,
        };

        let start = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process.response_with_timeout(7, Duration::from_millis(50));
        }));
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
