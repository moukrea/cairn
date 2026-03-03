//! cairn conformance test runner (Rust).
//!
//! Reads scenario names from stdin (one per line), executes them against
//! cairn-p2p, and outputs JSON-lines results to stdout.
//!
//! Output format per line:
//! ```json
//! {"scenario":"<name>","status":"pass|fail|skip","duration_ms":<int>,"diagnostics":{}}
//! ```

mod executor;
mod scenario;

use std::io::BufRead;
use std::time::Instant;

fn main() {
    // Determine the conformance base directory.
    // In Docker: /conformance
    // Locally: the conformance/ directory relative to the workspace root.
    let base_dir = if std::path::Path::new("/conformance/tests").exists() {
        "/conformance".to_string()
    } else {
        // Try relative to the binary or the env var.
        std::env::var("CONFORMANCE_DIR").unwrap_or_else(|_| {
            // Walk up from the binary to find the conformance directory.
            let exe = std::env::current_exe().unwrap_or_default();
            let mut dir = exe
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            for _ in 0..6 {
                let candidate = dir.join("conformance/tests");
                if candidate.exists() {
                    return dir.join("conformance").to_string_lossy().to_string();
                }
                if !dir.pop() {
                    break;
                }
            }
            // Last resort: current directory
            "conformance".to_string()
        })
    };

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l.trim().to_string(),
            Err(_) => break,
        };

        if line.is_empty() {
            continue;
        }

        let start = Instant::now();

        // Find and parse the scenario.
        let result = match scenario::find_scenario(&line, &base_dir) {
            Some(scenario) => executor::execute_scenario(&scenario, &base_dir),
            None => executor::ScenarioResult {
                status: executor::Status::Fail,
                diagnostics: {
                    let mut d = std::collections::HashMap::new();
                    d.insert(
                        "error".to_string(),
                        serde_json::json!(format!("scenario '{}' not found", line)),
                    );
                    d
                },
            },
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        let output = serde_json::json!({
            "scenario": line,
            "status": result.status.to_string(),
            "duration_ms": duration_ms,
            "diagnostics": result.diagnostics,
        });

        println!("{}", output);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn status_display() {
        assert_eq!(super::executor::Status::Pass.to_string(), "pass");
        assert_eq!(super::executor::Status::Fail.to_string(), "fail");
        assert_eq!(super::executor::Status::Skip.to_string(), "skip");
    }
}
